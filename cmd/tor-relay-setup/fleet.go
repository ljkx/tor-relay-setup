package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/remote"
	"github.com/ljkx/tor-relay-setup/internal/torctl"
	"github.com/ljkx/tor-relay-setup/internal/tui"
)

// probeParallel bounds concurrent fleet-probe calls.
const probeParallel = 16

// Seams for tests.
var (
	runFleetUI = tui.RunFleet
	cacheDir   = os.UserCacheDir
	scrape     = func(ctx context.Context, addr string) (metrics.Sample, error) { return metrics.Scrape(ctx, nil, addr) }
)

// fleetProbe prints the probe document of this host on one line. It only
// reads, so it needs no root (but sees more with it).
func fleetProbe(h host.Host, stdout io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p := fleet.ProbeLocal(ctx, h, buildVersion(), scrape)
	if err := json.NewEncoder(stdout).Encode(p); err != nil {
		return 1
	}
	return 0
}

type torOptions struct {
	Yes      bool
	Terminal bool
	In       io.Reader
	Out      io.Writer
	// Instance selects the tor instance (--instance); zero means the
	// default one.
	Instance relay.Instance
}

// torCmd is `tor restart|reload|update`: the console's service actions
// without the console, for scripts and rolling fleet actions.
func torCmd(h host.Host, verb string, opt torOptions) error {
	unit := opt.Instance.OrDefault().Unit
	question := map[string]string{
		"restart": "Restart " + unit + "? The relay is offline for a few seconds.",
		"reload":  "Reload " + unit + " (re-read torrc)?",
		"update":  "Upgrade tor from deb.torproject.org now? apt restarts the service.",
	}[verb]
	if !h.DryRun() && !opt.Yes {
		if !opt.Terminal {
			return fmt.Errorf("tor %s needs --yes when not run from a terminal", verb)
		}
		fmt.Fprintf(opt.Out, "%s [y/N] ", question)
		answer, _ := bufio.NewReader(opt.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return tui.ErrAborted
		}
	}
	if d, ok := h.(*host.DryRun); ok {
		d.Observe = func(e host.Event) {
			if e.Dry && e.Kind == host.EventCommand {
				fmt.Fprintln(opt.Out, "  would run: "+e.Text)
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	out := func(line string) { fmt.Fprintln(opt.Out, "  "+line) }
	last := -1
	progress := func(pct float64, detail string) {
		if step := int(pct) / 25; step > last && detail != "" {
			last = step
			fmt.Fprintf(opt.Out, "%3.0f%% %s\n", pct, detail)
		}
	}
	ops := torctl.Ops{Host: h, Instance: opt.Instance}
	var summary string
	var err error
	switch verb {
	case "restart":
		summary, err = ops.Restart(ctx, out, progress)
	case "reload":
		summary, err = ops.Reload(ctx, out, progress)
	case "update":
		summary, err = ops.Update(ctx, out, progress)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(opt.Out, summary)
	return nil
}

type fleetOptions struct {
	Sub, Inventory, Only string
	Format               string
	FormatSet            bool // --format or --json was given
	Yes, DryRun          bool
	KeepGoing            bool
	Interactive          bool
	Terminal             bool
	In                   io.Reader
	Out, Err             io.Writer
	Onionoo              onionoo.Client
	Local                host.Host // reads and writes the dashboard's flag cache
	Version              string
}

// fleetCmd is `fleet`: the dashboard, `fleet status`, and the rolling
// restart, reload and Tor update.
func fleetCmd(o fleetOptions) int {
	path := o.Inventory
	if path == "" {
		path = fleet.DefaultInventory
	}
	inv, err := loadInventory(path, o.Only)
	if err != nil {
		if o.Inventory == "" && errors.Is(err, fs.ErrNotExist) {
			err = errors.New("no fleet.toml in this directory; pass --inventory FILE (an example is docs/examples/fleet.toml)")
		}
		fmt.Fprintln(o.Err, "error:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cachePath := ""
	if dir, err := cacheDir(); err == nil {
		cachePath = fleet.CachePath(dir, inv)
	}

	if action, ok := remote.ParseAction(o.Sub); ok {
		return fleetRollout(ctx, o, inv, action)
	}
	f := newFleet(io.Discard)
	defer f.Close()
	if o.Sub == "" && o.Interactive && !o.FormatSet {
		err := runFleetUI(tui.FleetOptions{
			Version: o.Version, DryRun: o.DryRun, Inventory: inv, Onionoo: o.Onionoo,
			Probe: f.Probe, Cache: o.Local, CachePath: cachePath,
			Rollout: func(ctx context.Context, action string, entries []fleet.Entry, out func(string)) error {
				a, _ := remote.ParseAction(action)
				w := &lineWriter{out: out}
				rf := newFleet(w)
				defer rf.Close()
				_, err := rf.Rollout(ctx, remote.RolloutOptions{Action: a, Entries: entries, DryRun: o.DryRun, KeepGoing: o.KeepGoing})
				w.Flush()
				return err
			},
		})
		switch {
		case err == nil:
			return 0
		case errors.Is(err, tui.ErrAborted):
			return 130
		}
		fmt.Fprintln(o.Err, "error:", err)
		return 1
	}
	return fleetStatus(ctx, f, inv, o, cachePath)
}

// fleetStatus probes the fleet once and prints it.
func fleetStatus(ctx context.Context, f *remote.Fleet, inv fleet.Inventory, o fleetOptions, cachePath string) int {
	m := fleet.NewModel(inv)
	if cachePath != "" {
		m.PrevFlags = fleet.LoadFlagCache(o.Local, cachePath)
	}
	start := time.Now()
	for _, hp := range f.ProbeAll(ctx, inv.Addresses(), probeParallel) {
		m.Apply(hp)
	}
	m.EndRound(start, time.Now())
	if fps, bridges := m.Fingerprints(), m.BridgeFingerprints(); len(fps)+len(bridges) > 0 {
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		m.SetDirectoryResult(fleet.FetchDirectory(dctx, o.Onionoo, fps, bridges, o.Format != "prometheus"))
		cancel()
	}
	var err error
	switch o.Format {
	case "prometheus":
		if err := m.WritePrometheus(o.Out, fleet.PrometheusOptions{}); err != nil {
			return 1
		}
		return 0
	case "json":
		err = m.WriteJSON(o.Out, time.Now())
	default:
		err = m.WriteText(o.Out)
	}
	if err != nil || !m.Healthy() {
		return 1
	}
	return 0
}

// fleetRollout confirms and runs a rolling action.
func fleetRollout(ctx context.Context, o fleetOptions, inv fleet.Inventory, action remote.Action) int {
	if !o.Yes && !o.DryRun {
		if !o.Terminal {
			fmt.Fprintf(o.Err, "fleet %s changes %d relays; add --yes to run it without a terminal\n", action, len(inv.Entries))
			return 2
		}
		fmt.Fprintf(o.Out, "fleet %s, one relay at a time, waiting until each is running and listening:\n", action)
		for i, e := range inv.Entries {
			fmt.Fprintf(o.Out, "  %d. %s (%s)\n", i+1, e.Nickname(), e.Address)
		}
		fmt.Fprint(o.Out, "Continue? [y/N] ")
		answer, _ := bufio.NewReader(o.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(o.Err, "Stopped. Nothing was changed.")
			return 130
		}
	}
	f := newFleet(o.Out)
	defer f.Close()
	if _, err := f.Rollout(ctx, remote.RolloutOptions{Action: action, Entries: inv.Entries, DryRun: o.DryRun, KeepGoing: o.KeepGoing}); err != nil {
		fmt.Fprintln(o.Err, "error:", err)
		return 1
	}
	return 0
}

// lineWriter turns writes into complete lines for a callback.
type lineWriter struct {
	mu  sync.Mutex
	out func(string)
	buf bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.WriteString(line)
			return len(p), nil
		}
		if line = strings.TrimRight(line, "\n"); line != "" {
			w.out(line)
		}
	}
}

// Flush passes on a last line without a newline.
func (w *lineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.out(w.buf.String())
		w.buf.Reset()
	}
}
