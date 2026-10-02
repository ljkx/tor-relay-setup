package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

type stepStatus int

const (
	stepPending stepStatus = iota
	stepRunning
	stepDone
	stepFailed
)

type stepNote struct {
	level plan.Level
	text  string
}

type stepState struct {
	title   string
	status  stepStatus
	started time.Time
	elapsed time.Duration
	percent float64
	detail  string
	notes   []stepNote
}

type (
	applyEventMsg plan.Event
	applyHostMsg  host.Event
	applyDoneMsg  struct{ err error }
	reachMsg      struct {
		st  service.SelfTest
		err error
	}
	secondMsg time.Time
)

// apply runs the plan and shows it as a live checklist.
type apply struct {
	setup  config.Setup
	steps  []plan.Step
	states []stepState
	env    *plan.Env
	events chan tea.Msg
	cancel context.CancelFunc

	log     []string
	showLog bool
	bar     progress.Model
	started time.Time
	ended   time.Time
	done    bool
	err     error
	logPath string
	logFile *os.File

	reaching   bool
	reachStart time.Time
	reach      service.SelfTest
	reachDone  bool
	reachErr   error
	finger     string
}

func newApply(a *App, s config.Setup) *apply {
	steps := plan.Build(s, a.checks.Facts)
	ap := &apply{
		setup:  s,
		steps:  steps,
		states: make([]stepState, len(steps)),
		events: make(chan tea.Msg, 256),
		bar: progress.New(progress.WithColors(a.theme.Accent, a.theme.Good), progress.WithoutPercentage(),
			progress.WithFillCharacters('━', '─')),
	}
	for i, st := range steps {
		ap.states[i].title = st.Title
	}
	return ap
}

func (ap *apply) init(a *App) tea.Cmd { return ap.start(a) }

func (ap *apply) start(a *App) tea.Cmd {
	ap.started = time.Now()
	ap.env = plan.NewEnv(a.opt.Host, a.checks.Facts, ap.setup, program(a.opt.Version))
	ap.openLog(a)
	ap.observeHost(a.opt.Host)

	ctx, cancel := context.WithCancel(context.Background())
	ap.cancel = cancel
	events := ap.events
	go func() {
		facts := ap.env.Facts
		if !a.checks.FactsReady {
			dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
			if f, err := system.Detect(dctx, a.opt.Host, os.Getenv); err == nil {
				facts = f
			}
			dcancel()
		}
		ap.env.Facts = facts
		err := plan.Run(ctx, ap.steps, ap.env, func(e plan.Event) { events <- applyEventMsg(e) })
		events <- applyDoneMsg{err: err}
	}()
	return tea.Batch(ap.listen(), everySecond())
}

func (ap *apply) listen() tea.Cmd {
	ch := ap.events
	return func() tea.Msg { return <-ch }
}

func everySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return secondMsg(t) })
}

// observeHost forwards command and file events into the log pane.
func (ap *apply) observeHost(h host.Host) {
	var l *host.Local
	switch v := h.(type) {
	case *host.Local:
		l = v
	case *host.DryRun:
		l = v.Local
	}
	if l == nil {
		return
	}
	events := ap.events
	l.Observe = func(e host.Event) {
		select {
		case events <- applyHostMsg(e):
		default: // never block a running command on the UI
		}
	}
}

func (ap *apply) openLog(a *App) {
	if a.opt.DryRun {
		return
	}
	dir := "/var/log/tor-relay-setup"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	ap.logFile, ap.logPath = f, path
}

func (ap *apply) appendLog(line string) {
	ap.log = append(ap.log, line)
	if len(ap.log) > 2000 {
		ap.log = ap.log[len(ap.log)-2000:]
	}
	if ap.logFile != nil {
		fmt.Fprintln(ap.logFile, line)
	}
}

func (ap *apply) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case applyEventMsg:
		ap.handle(plan.Event(msg))
		return ap, ap.listen()
	case applyHostMsg:
		prefix := "  "
		switch {
		case msg.Kind == host.EventCommand && msg.Dry:
			prefix = "would run $ "
		case msg.Kind == host.EventCommand:
			prefix = "$ "
		}
		text := msg.Text
		if msg.Kind == host.EventCommand {
			if ap.logFile != nil {
				fmt.Fprintln(ap.logFile, prefix+text)
			}
			text = compactCommand(text)
			ap.log = append(ap.log, prefix+text)
			return ap, ap.listen()
		}
		ap.appendLog(prefix + text)
		return ap, ap.listen()
	case applyDoneMsg:
		ap.done, ap.err, ap.ended = true, msg.err, time.Now()
		if ap.logFile != nil {
			if msg.err != nil {
				fmt.Fprintln(ap.logFile, "FAILED:", msg.err)
			}
			_ = ap.logFile.Close()
			ap.logFile = nil
		}
		if msg.err == nil && !a.opt.DryRun {
			ap.finger = readFingerprint(a.opt.Host, ap.setup.Instance())
			return ap, ap.waitReachable(a)
		}
		return ap, nil
	case reachMsg:
		ap.reach, ap.reachErr, ap.reachDone = msg.st, msg.err, true
		return ap, nil
	case secondMsg:
		if !ap.done || (ap.reaching && !ap.reachDone) {
			return ap, everySecond()
		}
	case progress.FrameMsg:
		var cmd tea.Cmd
		ap.bar, cmd = ap.bar.Update(msg)
		return ap, cmd
	case tea.KeyPressMsg:
		switch msg.String() {
		case "l":
			ap.showLog = !ap.showLog
		case "enter", "q", "esc":
			if ap.done {
				if ap.cancel != nil {
					ap.cancel()
				}
				return ap, quit(ap.err)
			}
		case "r":
			if ap.done && ap.err != nil {
				fresh := newApply(a, ap.setup)
				return fresh, fresh.start(a)
			}
		}
	}
	return ap, nil
}

func (ap *apply) handle(e plan.Event) {
	st := &ap.states[e.Step]
	switch e.Kind {
	case plan.StepStarted:
		st.status, st.started = stepRunning, time.Now()
		ap.appendLog("── " + st.title)
	case plan.StepProgress:
		st.percent, st.detail = e.Percent, e.Text
	case plan.StepLog:
		ap.appendLog("  " + e.Text)
	case plan.StepNote:
		st.notes = append(st.notes, stepNote{level: e.Level, text: e.Text})
		ap.appendLog("  • " + e.Text)
	case plan.StepFinished:
		st.status, st.elapsed, st.percent, st.detail = stepDone, e.Elapsed, 100, ""
	case plan.StepFailed:
		st.status, st.elapsed = stepFailed, e.Elapsed
		ap.appendLog("  ✗ " + e.Text)
	}
}

func (ap *apply) waitReachable(a *App) tea.Cmd {
	ap.reaching, ap.reachStart = true, time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	prev := ap.cancel
	ap.cancel = func() {
		cancel()
		if prev != nil {
			prev()
		}
	}
	tor := service.Tor{Host: a.opt.Host, Unit: ap.setup.Instance().Unit}
	since, wantV6 := ap.env.RestartedAt, ap.setup.Relay.IPv6 != ""
	return tea.Batch(func() tea.Msg {
		st, err := tor.WaitReachable(ctx, since, 5*time.Second, wantV6)
		return reachMsg{st: st, err: err}
	}, everySecond())
}

func (ap *apply) overall() float64 {
	var total, done float64
	for i, s := range ap.steps {
		total += s.Weight
		switch ap.states[i].status {
		case stepDone:
			done += s.Weight
		case stepRunning:
			done += s.Weight * ap.states[i].percent / 100
		}
	}
	if total == 0 {
		return 0
	}
	return done / total
}

func (ap *apply) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	var b strings.Builder

	end := time.Now()
	if ap.done {
		end = ap.ended
	}
	elapsed := end.Sub(ap.started).Round(100 * time.Millisecond)
	doneCount := 0
	for _, s := range ap.states {
		if s.status == stepDone {
			doneCount++
		}
	}
	title := t.Title.Render(" Applying")
	switch {
	case ap.done && ap.err == nil && a.opt.DryRun:
		title = t.GoodText.Bold(true).Render(" Dry run complete") + t.Subtle.Render(" · nothing was changed")
	case ap.done && ap.err == nil:
		title = t.GoodText.Bold(true).Render(" Relay configured")
	case ap.done:
		title = t.BadText.Bold(true).Render(" Setup stopped")
	}
	status := t.Subtle.Render(fmt.Sprintf(" %d/%d · %s", doneCount, len(ap.steps), formatDuration(elapsed)))
	ap.bar.SetWidth(clamp(w-lipgloss.Width(title)-lipgloss.Width(status)-4, 10, 60))
	b.WriteString(title + status + "  " + ap.bar.ViewAs(ap.overall()) + "\n\n")

	for _, s := range ap.states {
		b.WriteString(ap.stepLine(a, s, w) + "\n")
		if s.status != stepPending {
			for _, n := range s.notes {
				style := t.Subtle
				icon := iconInfo
				switch n.level {
				case plan.Success:
					style, icon = t.GoodText, iconDone
				case plan.Warn:
					style, icon = t.WarnText, iconWarn
				}
				b.WriteString("     " + style.Render(icon+" "+truncate(n.text, w-8)) + "\n")
			}
		}
	}

	if ap.done {
		b.WriteString("\n" + ap.resultCard(a, w))
	}
	if ap.showLog || (ap.done && ap.err != nil) {
		b.WriteString("\n" + ap.logPanel(a, w))
	}
	return b.String()
}

func (ap *apply) stepLine(a *App, s stepState, w int) string {
	t := a.theme
	var icon, text string
	switch s.status {
	case stepPending:
		icon, text = t.Faintly.Render(iconPending), t.Faintly.Render(s.title)
	case stepRunning:
		icon, text = a.spin.View(), t.Bold.Render(s.title)
		if s.detail != "" {
			text += t.Subtle.Render("  " + truncate(s.detail, w/2))
		}
		if s.percent > 0 && s.percent < 100 {
			text += t.Subtle.Render(fmt.Sprintf("  %3.0f%%", s.percent))
		}
	case stepDone:
		icon, text = t.GoodText.Render(iconDone), s.title
	case stepFailed:
		icon, text = t.BadText.Render(iconFail), t.BadText.Render(s.title)
	}
	line := "  " + icon + " " + text
	if s.status == stepDone || s.status == stepFailed {
		d := t.Faintly.Render(formatDuration(s.elapsed))
		if gap := w - lipgloss.Width(line) - lipgloss.Width(d); gap > 1 {
			line += strings.Repeat(" ", gap) + d
		}
	}
	return line
}

func (ap *apply) resultCard(a *App, w int) string {
	t := a.theme
	if ap.err != nil {
		body := t.BadText.Render(ap.err.Error())
		if ap.logPath != "" {
			body += "\n\n" + t.Subtle.Render("Full log: "+ap.logPath)
		}
		body += "\n" + t.Subtle.Render("Fix the cause and press r to retry; every step is safe to run again.")
		return panel(t, "What went wrong", body, w, true)
	}
	if a.opt.DryRun {
		return panel(t, "Next", "Run again without --dry-run to apply these changes:\n  "+t.Bold.Render("sudo tor-relay-setup"), w, false)
	}
	rows := [][2]string{{"Nickname", ap.setup.Relay.Nickname}}
	if ap.finger != "" {
		rows = append(rows, [2]string{"Fingerprint", ap.finger})
	}
	if ap.env.FamilyID != "" {
		rows = append(rows, [2]string{"FamilyId", ap.env.FamilyID})
	}
	rows = append(rows, [2]string{"Reachability", ap.reachText(a)})
	body := kv(t, rows) + "\n\n" +
		t.Subtle.Render("Relay Search lists new relays after about 3 hours; traffic ramps up over days.") + "\n" +
		t.Subtle.Render("Open the operator console any time with: ") + t.Bold.Render("sudo tor-relay-setup")
	if ap.setup.Family.Mode == "generate" {
		body += "\n" + t.Subtle.Render("Copy the family key to your other relays: console → Relay family → Share.")
	}
	return panel(t, "Your relay", body, w, true)
}

func (ap *apply) reachText(a *App) string {
	t := a.theme
	switch {
	case ap.reachDone && ap.reach.IPv4:
		s := t.GoodText.Render(iconDone + " ORPort reachable from outside")
		if ap.reach.IPv6 {
			s += t.GoodText.Render(" (IPv4 + IPv6)")
		}
		return s
	case ap.reachDone && ap.reach.Failed:
		return t.WarnText.Render(iconWarn + " not confirmed — check the provider firewall for TCP " + itoa(ap.setup.Relay.ORPort))
	case ap.reachDone:
		return t.WarnText.Render(iconWarn + " no result yet; the console shows it later")
	default:
		return a.spin.View() + " " + t.Subtle.Render("waiting for Tor's self-test · "+formatDuration(time.Since(ap.reachStart).Truncate(time.Second))+" · enter finishes now")
	}
}

func (ap *apply) logPanel(a *App, w int) string {
	t := a.theme
	n := clamp(a.height/3, 6, 30)
	tail := ap.log
	if len(tail) > n {
		tail = tail[len(tail)-n:]
	}
	// Copy before truncating: tail shares ap.log's backing array.
	lines := make([]string, len(tail))
	for i, l := range tail {
		lines[i] = truncate(l, w-4)
	}
	return panel(t, "Output", t.Subtle.Render(strings.Join(lines, "\n")), w, false)
}

func (ap *apply) keys(a *App) []string {
	if !ap.done {
		return []string{"l", "toggle output", "ctrl+c", "abort"}
	}
	if ap.err != nil {
		return []string{"r", "retry", "l", "output", "q", "quit"}
	}
	return []string{"enter", "finish", "l", "output"}
}

// readFingerprint reads the relay fingerprint from inst's DataDirectory.
func readFingerprint(h host.Host, inst relay.Instance) string {
	inst = inst.OrDefault()
	dataDir := inst.DataDir
	if torrc, err := h.ReadFile(inst.TorrcPath); err == nil {
		dataDir = relay.ParseDocument(torrc).DataDirectoryOr(dataDir)
	}
	data, err := h.ReadFile(strings.TrimRight(dataDir, "/") + "/fingerprint")
	if err != nil {
		return ""
	}
	if f := strings.Fields(string(data)); len(f) > 0 {
		return strings.ToUpper(f[len(f)-1])
	}
	return ""
}
