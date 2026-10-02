package tui

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// taskFunc does one console job, reporting output lines and progress.
type taskFunc func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error)

type (
	taskLineMsg     string
	taskProgressMsg struct {
		pct    float64
		detail string
	}
	taskDoneMsg struct {
		summary string
		err     error
	}
)

// task runs a taskFunc in the background and shows its output.
type task struct {
	title   string
	back    *console
	lines   []string
	running bool
	pct     float64
	detail  string
	summary string
	err     error
	events  chan tea.Msg
	cancel  context.CancelFunc
	started time.Time
}

func newTask(a *App, back *console, title string, fn taskFunc) (screen, tea.Cmd) {
	t := &task{title: title, back: back, running: true, events: make(chan tea.Msg, 256), started: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	events := t.events
	h := a.opt.Host
	if l := localOf(h); l != nil {
		l.Observe = func(e host.Event) {
			if !e.Dry {
				return
			}
			select {
			case events <- taskLineMsg("would run: " + compactCommand(e.Text)):
			default:
			}
		}
	}
	go func() {
		out := func(s string) {
			select {
			case events <- taskLineMsg(s):
			default:
			}
		}
		progress := func(p float64, d string) {
			select {
			case events <- taskProgressMsg{p, d}:
			default:
			}
		}
		summary, err := fn(ctx, h, out, progress)
		events <- taskDoneMsg{summary: summary, err: err}
	}()
	return t, t.listen()
}

func (t *task) listen() tea.Cmd {
	ch := t.events
	return func() tea.Msg { return <-ch }
}

func (t *task) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case taskLineMsg:
		t.lines = append(t.lines, string(msg))
		if len(t.lines) > 500 {
			t.lines = t.lines[len(t.lines)-500:]
		}
		return t, t.listen()
	case taskProgressMsg:
		t.pct, t.detail = msg.pct, msg.detail
		return t, t.listen()
	case taskDoneMsg:
		t.running, t.summary, t.err = false, msg.summary, msg.err
		t.cancel()
		return t, nil
	case tea.KeyPressMsg:
		if !t.running {
			switch msg.String() {
			case "enter", "esc", "q", "backspace":
				return t.back, t.back.refresh(a)
			}
		}
	}
	return t, nil
}

func (t *task) view(a *App) string {
	th := a.theme
	w := a.contentWidth()
	var head string
	switch {
	case t.running:
		head = a.spin.View() + " " + th.Bold.Render(t.title)
		if t.detail != "" {
			head += th.Subtle.Render("  " + truncate(t.detail, w/2))
		}
		if t.pct > 0 {
			head += th.Subtle.Render(fmt.Sprintf("  %3.0f%%", t.pct))
		}
		head += th.Faintly.Render("  " + formatDuration(time.Since(t.started).Truncate(time.Second)))
	case t.err != nil:
		head = th.BadText.Bold(true).Render(iconFail+" "+t.title+" failed") + "\n\n" + th.BadText.Render(t.err.Error())
	default:
		head = th.GoodText.Bold(true).Render(iconDone + " " + t.title)
		if t.summary != "" {
			head += "\n\n" + t.summary
		}
	}
	n := clamp(a.height-12, 4, 40)
	lines := t.lines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = truncate(l, w-4)
	}
	body := head
	if len(out) > 0 {
		body += "\n\n" + panel(th, "Output", th.Subtle.Render(strings.Join(out, "\n")), w, false)
	}
	return body
}

func (t *task) keys(a *App) []string {
	if t.running {
		return []string{"ctrl+c", "abort"}
	}
	return []string{"enter", "back to console"}
}

// writeTorrc verifies new torrc content for inst with tor, installs it with
// a backup, and reloads or restarts that instance.
func writeTorrc(ctx context.Context, h host.Host, inst relay.Instance, data []byte, restart bool, out func(string)) error {
	inst = inst.OrDefault()
	candidate, err := os.CreateTemp("", "torrc-candidate-")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	if _, err := candidate.Write(data); err != nil {
		_ = candidate.Close()
		return err
	}
	if err := candidate.Close(); err != nil {
		return err
	}
	out("tor --verify-config")
	if err := relay.VerifyInstance(ctx, h, inst, candidate.Name()); err != nil {
		if !errors.Is(err, relay.ErrTorMissing) || !h.DryRun() {
			return fmt.Errorf("tor rejected the change (nothing was written): %w", err)
		}
	}
	ch, err := h.WriteFile(inst.TorrcPath, data, host.FileOptions{Mode: 0o644, Backup: true})
	if err != nil {
		return err
	}
	if ch.Unchanged {
		out("torrc unchanged")
		return nil
	}
	if ch.BackupOf != "" {
		out("previous torrc saved as " + ch.BackupOf)
	}
	tor := service.Tor{Host: h, Unit: inst.Unit}
	if restart {
		out("systemctl restart " + inst.Unit)
		return tor.Restart(ctx)
	}
	out("systemctl reload " + inst.Unit)
	if err := tor.Reload(ctx); err != nil {
		out("reload failed, restarting")
		return tor.Restart(ctx)
	}
	return nil
}

func restartTask(inst relay.Instance) taskFunc {
	unit := inst.OrDefault().Unit
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		tor := service.Tor{Host: h, Unit: unit}
		since := time.Now()
		progress(10, "restarting")
		if err := tor.Restart(ctx); err != nil {
			return "", err
		}
		if h.DryRun() {
			return "Dry run: Tor was not restarted.", nil
		}
		progress(50, "waiting for the service")
		deadline := time.Now().Add(15 * time.Second)
		for !tor.Active(ctx) {
			if time.Now().After(deadline) {
				return "", errors.New(unit + " did not come back; check the log")
			}
			time.Sleep(500 * time.Millisecond)
		}
		if w, _ := tor.FamilyWarnings(ctx, since); len(w) > 0 {
			for _, line := range w {
				out(line)
			}
		}
		return "Tor restarted. Reachability is re-tested in the background; refresh the console in a minute.", nil
	}
}

func stopTask(inst relay.Instance) taskFunc {
	unit := inst.OrDefault().Unit
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		if err := (service.Tor{Host: h, Unit: unit}).Stop(ctx); err != nil {
			return "", err
		}
		return "Tor is stopped; the relay is offline. To keep it off after reboots too: systemctl disable " + unit, nil
	}
}

func startTask(inst relay.Instance) taskFunc {
	unit := inst.OrDefault().Unit
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		tor := service.Tor{Host: h, Unit: unit}
		if err := tor.Enable(ctx); err != nil {
			return "", err
		}
		if err := tor.Start(ctx); err != nil {
			return "", err
		}
		return "Tor is starting. Refresh the console in a minute for the reachability result.", nil
	}
}

func reloadTask(inst relay.Instance) taskFunc {
	inst = inst.OrDefault()
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		progress(20, "tor --verify-config")
		if err := relay.VerifyInstance(ctx, h, inst, inst.TorrcPath); err != nil && !errors.Is(err, relay.ErrTorMissing) {
			return "", fmt.Errorf("torrc is invalid, not reloading: %w", err)
		}
		progress(60, "reloading")
		if err := (service.Tor{Host: h, Unit: inst.Unit}).Reload(ctx); err != nil {
			return "", err
		}
		return "Tor re-read its configuration.", nil
	}
}

func updateTask() taskFunc {
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		c := apt.Client{Host: h}
		if err := c.Update(ctx, func(p apt.Progress) { progress(p.Percent*0.3, p.Detail) }, out); err != nil {
			return "", err
		}
		policy, err := c.Policy(ctx, "tor")
		if err != nil {
			return "", err
		}
		if !h.DryRun() && !torproject.CandidateFromTorProject(policy) {
			return "", errors.New("the tor candidate does not come from deb.torproject.org; use Reconfigure to repair the repository")
		}
		if err := c.Install(ctx, []string{"tor", "deb.torproject.org-keyring"}, func(p apt.Progress) {
			progress(30+p.Percent*0.7, p.Detail)
		}, out); err != nil {
			return "", err
		}
		res, err := h.Run(ctx, host.Command{Name: "tor", Args: []string{"--version"}})
		if err != nil {
			return "Updated.", nil
		}
		v, _ := torproject.ParseTorVersion(res.Output)
		return "tor " + v + " is installed.", nil
	}
}

func backupTask(inst relay.Instance, keyDir string) taskFunc {
	inst = inst.OrDefault()
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		if keyDir == "" {
			keyDir = inst.KeyDir
		}
		prefix := "/root/tor-relay-keys-"
		if !inst.IsDefault() {
			prefix += inst.Name + "-"
		}
		name := prefix + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz"
		if h.DryRun() {
			return "Dry run: would archive " + keyDir + " to " + name + " (mode 600).", nil
		}
		if err := archiveDir(keyDir, name, out); err != nil {
			return "", err
		}
		return "Wrote " + name + " (mode 600). It contains the relay identity and family keys: copy it somewhere private and off this server.", nil
	}
}

func archiveDir(dir, target string, out func(string)) error {
	// os.Root confines every open to dir, so a symlink swapped in while
	// walking cannot make the archive include files from elsewhere.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	prefix := filepath.Base(dir)
	walkErr := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.Join(prefix, path)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		src, err := root.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		if _, err := io.Copy(tw, src); err != nil {
			return err
		}
		out("added " + hdr.Name)
		return nil
	})
	for _, c := range []io.Closer{tw, gz, f} {
		if cerr := c.Close(); walkErr == nil {
			walkErr = cerr
		}
	}
	if walkErr != nil {
		_ = os.Remove(target)
	}
	return walkErr
}
