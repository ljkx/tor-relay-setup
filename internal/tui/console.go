package tui

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// How often the console refreshes on its own.
const (
	liveEvery      = 2 * time.Second  // MetricsPort scrape
	refreshEvery   = 30 * time.Second // service, listener, log, warnings
	directoryEvery = 30 * time.Minute // Onionoo publishes hourly
	liveWindow     = 60               // samples kept for the live sparkline
)

type (
	reportMsg status.Report
	// instancesMsg carries every relay instance on the host with its
	// report, when there is more than one.
	instancesMsg struct {
		instances []relay.Instance
		reports   []status.Report
	}
	// The fingerprint (fp) or MetricsPort address (addr) a result belongs
	// to; a result for an instance that is no longer selected is dropped.
	directoryMsg struct {
		relay *onionoo.Relay
		err   error
		fp    string
	}
	historyMsg struct {
		bw  *onionoo.Bandwidth
		err error
		fp  string
	}
	bridgeDirMsg struct {
		bridge *onionoo.Bridge
		err    error
		fp     string
	}
	sampleMsg struct {
		sample metrics.Sample
		err    error
		addr   string
	}
	liveTickMsg    time.Time
	refreshTickMsg time.Time
)

type action struct {
	key, label, desc string
	run              func(a *App, c *console) (screen, tea.Cmd)
	// show limits the action to relays it applies to; nil shows it always.
	show func(r status.Report) bool
}

// Which relays an action applies to.
func isBridge(r status.Report) bool  { return r.Relay.Bridge }
func notBridge(r status.Report) bool { return !r.Relay.Bridge }
func isExit(r status.Report) bool    { return r.Relay.Exit && !r.Relay.Bridge }

// console is the operator dashboard for an existing relay.
type console struct {
	report     status.Report
	loaded     bool
	updated    time.Time
	dir        *onionoo.Relay
	dirErr     error
	dirLoading bool
	dirAt      time.Time
	history    *onionoo.Bandwidth
	// bridgeDir is the Tor Metrics entry of a bridge (by hashed fingerprint).
	bridgeDir *onionoo.Bridge
	cursor    int
	// actions are the ones that apply to the selected relay, out of all.
	actions []action
	all     []action
	ticking bool

	// Live traffic from the MetricsPort.
	last    metrics.Sample
	rate    metrics.Rate
	rates   []float64 // total bytes/s, oldest first
	liveErr error
	// Overload signals since the console started watching this relay: the
	// first sample is the baseline for tor's load counters.
	base     metrics.Sample
	overload metrics.Overload

	// Several relays on this server: inst is the selected one (the zero
	// value means the default instance); instances and overview list every
	// relay instance and its report, and stay empty for a single relay.
	inst      relay.Instance
	instances []relay.Instance
	overview  []status.Report
}

// selected is the instance every card and action works on.
func (c *console) selected() relay.Instance { return c.inst.OrDefault() }

// multi reports whether the server runs more than one relay instance.
func (c *console) multi() bool { return len(c.instances) > 1 }

func newConsole() *console {
	c := &console{}
	c.all = []action{
		{key: "r", label: "Refresh", desc: "Re-check everything now", run: func(a *App, c *console) (screen, tea.Cmd) {
			c.dirAt = time.Time{} // ask Tor Metrics again too
			return c, c.refresh(a)
		}},
		{key: "l", label: "Live logs", desc: "Follow the Tor log in place", run: func(a *App, c *console) (screen, tea.Cmd) {
			v := newLogView(c)
			return v, v.start(a)
		}},
		{key: "i", label: "Bridge line", desc: "Share the bridge, check reachability", show: isBridge, run: func(a *App, c *console) (screen, tea.Cmd) {
			return newBridgeView(c), nil
		}},
		{key: "f", label: "Relay family", desc: "Keys, FamilyIds, share, import", show: notBridge, run: func(a *App, c *console) (screen, tea.Cmd) {
			return newFamilyView(a, c), nil
		}},
		{key: "x", label: "Exit policy", desc: "Ports, custom rules, IPv6, exit notice", show: isExit, run: newExitPolicyView},
		{key: "e", label: "Edit settings", desc: "Nickname, contact, bandwidth, metrics", run: newEditView},
		{key: "k", label: "Identity keys", desc: "Offline master key, signing key expiry", run: func(a *App, c *console) (screen, tea.Cmd) {
			return newKeysView(c), nil
		}},
		{key: "c", label: "ContactInfo proof", desc: "Files to publish on your website", show: notBridge, run: func(a *App, c *console) (screen, tea.Cmd) {
			return newProofView(a, c), nil
		}},
		{key: "s", label: "Restart Tor", desc: "Restart and verify the service", run: func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Restart Tor"+instanceTitle(c.selected()), restartTask(c.selected()))
		}},
		{key: "o", label: "Reload Tor", desc: "Re-read torrc without a restart", run: func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Reload Tor"+instanceTitle(c.selected()), reloadTask(c.selected()))
		}},
		{key: "p", label: "Stop / start Tor", desc: "Take the relay offline, or bring it back", run: func(a *App, c *console) (screen, tea.Cmd) {
			inst := c.selected()
			if c.report.Service.Active {
				return newConfirmView(c, "Stop Tor"+instanceTitle(inst)+"? The relay goes offline until you start it again.", func() (screen, tea.Cmd) {
					return newTask(a, c, "Stop Tor"+instanceTitle(inst), stopTask(inst))
				}), nil
			}
			return newTask(a, c, "Start Tor"+instanceTitle(inst), startTask(inst))
		}},
		{key: "u", label: "Update Tor", desc: "Refresh apt and upgrade tor", run: func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Update Tor", updateTask())
		}},
		{key: "b", label: "Back up keys", desc: "Archive identity + family keys to /root", run: func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Back up keys"+instanceTitle(c.selected()), backupTask(c.selected(), c.report.Family.KeyDirectory))
		}},
		{key: "w", label: "Reconfigure", desc: "Run the full setup wizard again", run: func(a *App, c *console) (screen, tea.Cmd) {
			prefill, ok := instanceSetup(a.opt.Host, c.selected())
			if !ok {
				prefill = config.Default()
				if !c.selected().IsDefault() {
					prefill.Relay.Instance = c.selected().Name
				}
			}
			w := newWizard(a, prefill)
			return w, w.init(a)
		}},
		{key: "n", label: "Add a relay", desc: "Another tor instance on this server", run: func(a *App, c *console) (screen, tea.Cmd) {
			if found, _ := relay.Discover(a.opt.Host); len(found) >= relay.MaxRelaysPerIPv4 {
				return c, toast(fmt.Sprintf("This server already runs %d relays, the most the directory authorities list per IPv4 address.", len(found)))
			}
			w := newInstanceWizard(a, NewInstanceSetup(a.opt.Host, c.selected()))
			return w, w.init(a)
		}},
		{key: "q", label: "Quit", run: func(a *App, c *console) (screen, tea.Cmd) { return c, quit(nil) }},
	}
	c.filterActions()
	return c
}

// filterActions shows the actions that apply to the selected relay (bridge
// line for bridges, exit policy for exits, ...), keeping the cursor on the
// same action when it is still there.
func (c *console) filterActions() {
	current := ""
	if c.cursor < len(c.actions) {
		current = c.actions[c.cursor].key
	}
	c.actions = c.actions[:0:0]
	for _, act := range c.all {
		if act.show == nil || act.show(c.report) {
			c.actions = append(c.actions, act)
		}
	}
	c.cursor = max(slices.IndexFunc(c.actions, func(a action) bool { return a.key == current }), 0)
}

// init registers the console with the app, so its background updates keep
// arriving while another view is open, and starts the refresh timers.
func (c *console) init(a *App) tea.Cmd {
	a.console = c
	cmds := []tea.Cmd{c.refresh(a)}
	if !c.ticking {
		c.ticking = true
		cmds = append(cmds, c.scrape(), liveTick(), refreshTick())
	}
	return tea.Batch(cmds...)
}

func liveTick() tea.Cmd {
	return tea.Tick(liveEvery, func(t time.Time) tea.Msg { return liveTickMsg(t) })
}

func refreshTick() tea.Cmd {
	return tea.Tick(refreshEvery, func(t time.Time) tea.Msg { return refreshTickMsg(t) })
}

// scrape reads the MetricsPort once, when one is configured and Tor runs.
func (c *console) scrape() tea.Cmd {
	addr := c.report.Relay.MetricsPort
	if addr == "" || (c.loaded && !c.report.Service.Active) {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), liveEvery)
		defer cancel()
		s, err := metrics.Scrape(ctx, nil, addr)
		return sampleMsg{sample: s, err: err, addr: addr}
	}
}

// background handles the console's own data messages and timers. It runs
// whether or not the console is on screen; ok is false for other messages.
func (c *console) background(a *App, msg tea.Msg) (cmd tea.Cmd, ok bool) {
	switch msg := msg.(type) {
	case reportMsg:
		// A single relay: no switcher.
		c.instances, c.overview = nil, nil
		if msg.Instance != "" {
			c.inst, _ = relay.Named(msg.Instance)
		}
		return c.loadReport(a, status.Report(msg)), true
	case instancesMsg:
		c.instances, c.overview = msg.instances, msg.reports
		sel := slices.IndexFunc(c.instances, func(i relay.Instance) bool { return i.Name == c.selected().Name })
		if sel < 0 {
			sel = 0
		}
		c.inst = c.instances[sel]
		return c.loadReport(a, c.overview[sel]), true
	case directoryMsg:
		if msg.fp != "" && msg.fp != c.report.Relay.Fingerprint {
			return nil, true // for an instance no longer on screen
		}
		c.dir, c.dirErr, c.dirLoading, c.dirAt = msg.relay, msg.err, false, time.Now()
		return nil, true
	case bridgeDirMsg:
		if msg.fp != "" && msg.fp != c.report.Relay.Fingerprint {
			return nil, true
		}
		c.bridgeDir, c.dirErr, c.dirLoading, c.dirAt = msg.bridge, msg.err, false, time.Now()
		return nil, true
	case historyMsg:
		if msg.err == nil && (msg.fp == "" || msg.fp == c.report.Relay.Fingerprint) {
			c.history = msg.bw
		}
		return nil, true
	case sampleMsg:
		if msg.addr != "" && msg.addr != c.report.Relay.MetricsPort {
			return nil, true
		}
		c.record(msg.sample, msg.err)
		return nil, true
	case liveTickMsg:
		return tea.Batch(c.scrape(), liveTick()), true
	case refreshTickMsg:
		// Only re-check the system while the dashboard is visible.
		if a.screen == screen(c) {
			return tea.Batch(c.refresh(a), refreshTick()), true
		}
		return refreshTick(), true
	}
	return nil, false
}

// record adds a MetricsPort sample to the live traffic view.
func (c *console) record(s metrics.Sample, err error) {
	c.liveErr = err
	if err != nil {
		return
	}
	if r, ok := metrics.Between(c.last, s); ok && !c.last.At.IsZero() {
		c.rate = r
		c.rates = append(c.rates, r.Total())
		if len(c.rates) > liveWindow {
			c.rates = c.rates[len(c.rates)-liveWindow:]
		}
	}
	if c.base.At.IsZero() || s.Read < c.base.Read {
		c.base = s // first sample, or tor restarted
	}
	c.overload = metrics.AssessOverload(c.base, s)
	c.last = s
}

// overloadRows report tor's overload signals: those seen while the console
// watched (from the MetricsPort) and Relay Search's mark (from Tor Metrics,
// kept for 72 hours after tor last published overload-general).
func (c *console) overloadRows(a *App, width int) [][2]string {
	t := a.theme
	var rows [][2]string
	for _, f := range c.overload.Findings {
		rows = append(rows, [2]string{"Overload", statusIcon(t, false, !f.Published) + " " + truncate(f.Summary, width)})
	}
	if c.dir != nil && c.dir.Overloaded(time.Now()) {
		rows = append(rows, [2]string{"Relay Search", statusIcon(t, false, true) + " marked overloaded since " + c.dir.OverloadGeneral.Local().Format("Jan 2 15:04")})
	}
	if len(rows) == 0 && c.overload.Supported {
		rows = append(rows, [2]string{"Overload", statusIcon(t, true, false) + " " + t.Subtle.Render("no signals")})
	}
	return rows
}

// overloadWarnings explain each overload signal with Tor's remedy, for the
// "Needs attention" panel.
func (c *console) overloadWarnings() []string {
	var out []string
	for _, f := range c.overload.Findings {
		out = append(out, f.Summary+". "+f.Remedy)
	}
	if c.dir != nil && c.dir.Overloaded(time.Now()) && len(c.overload.Findings) == 0 {
		out = append(out, "Relay Search marks this relay overloaded: tor published overload-general in the last 72 hours. Run tor-relay-setup alert run --dry-run to see which signal.")
	}
	return out
}

// loadReport shows a fresh report of the selected instance.
func (c *console) loadReport(a *App, r status.Report) tea.Cmd {
	first := !c.loaded
	c.report, c.loaded, c.updated = r, true, time.Now()
	c.filterActions()
	if first {
		return tea.Batch(c.lookup(a), c.scrape())
	}
	if !c.dirLoading && (c.dirAt.IsZero() || time.Since(c.dirAt) > directoryEvery) {
		return c.lookup(a)
	}
	return nil
}

// refresh re-checks the relays. It looks for instances every time, so a
// relay added meanwhile shows up: one relay yields a reportMsg, several an
// instancesMsg with every instance's report.
func (c *console) refresh(a *App) tea.Cmd {
	h := a.opt.Host
	want := c.selected()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		found, _ := relay.Discover(h)
		switch len(found) {
		case 0:
			return reportMsg(status.Collect(ctx, h, status.Options{Instance: want}))
		case 1:
			return reportMsg(status.Collect(ctx, h, status.Options{Instance: found[0]}))
		}
		reports := make([]status.Report, len(found))
		var wg sync.WaitGroup
		for i, inst := range found {
			wg.Go(func() { reports[i] = status.Collect(ctx, h, status.Options{Instance: inst}) })
		}
		wg.Wait()
		return instancesMsg{instances: found, reports: reports}
	}
}

// switchTo selects instance i: its last report shows at once, and live
// traffic, Tor Metrics and a fresh report are fetched for it.
func (c *console) switchTo(a *App, i int) tea.Cmd {
	if !c.multi() || i < 0 || i >= len(c.instances) || c.instances[i].Name == c.selected().Name {
		return nil
	}
	c.inst = c.instances[i]
	if i < len(c.overview) {
		c.report = c.overview[i]
	}
	c.dir, c.dirErr, c.dirLoading, c.dirAt, c.history, c.bridgeDir = nil, nil, false, time.Time{}, nil, nil
	c.last, c.rate, c.rates, c.liveErr = metrics.Sample{}, metrics.Rate{}, nil, nil
	c.base, c.overload = metrics.Sample{}, metrics.Overload{}
	return tea.Batch(c.lookup(a), c.scrape(), c.refresh(a))
}

// selectedIndex is the selected instance's position among instances.
func (c *console) selectedIndex() int {
	return max(slices.IndexFunc(c.instances, func(i relay.Instance) bool { return i.Name == c.selected().Name }), 0)
}

// lookup asks Onionoo for the relay's published details and traffic
// history, concurrently.
func (c *console) lookup(a *App) tea.Cmd {
	fp := c.report.Relay.Fingerprint
	if fp == "" {
		return nil
	}
	c.dirLoading = true
	client := a.opt.Onionoo
	if c.report.Relay.Bridge {
		// Bridges are looked up by hashed fingerprint only, so the real one
		// never travels in a URL; Onionoo has no traffic graph for them here.
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			b, err := status.BridgeDirectory(ctx, client, fp)
			return bridgeDirMsg{bridge: b, err: err, fp: fp}
		}
	}
	return tea.Batch(
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			r, err := status.Directory(ctx, client, fp)
			return directoryMsg{relay: r, err: err, fp: fp}
		},
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			bw, err := client.Bandwidth(ctx, fp)
			return historyMsg{bw: bw, err: err, fp: fp}
		},
	)
}

func (c *console) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if cmd, ok := c.background(a, msg); ok {
		return c, cmd
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return c, nil
	}
	c.filterActions()
	switch k := key.String(); k {
	case "up", "k":
		c.cursor = (c.cursor - 1 + len(c.actions)) % len(c.actions)
	case "down", "j", "tab":
		c.cursor = (c.cursor + 1) % len(c.actions)
	case "enter":
		return c.actions[c.cursor].run(a, c)
	case "[", "]":
		// Switch relay instance (several relays on this server).
		if n := len(c.instances); n > 1 {
			step := 1
			if k == "[" {
				step = n - 1
			}
			return c, c.switchTo(a, (c.selectedIndex()+step)%n)
		}
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		return c, c.switchTo(a, int(k[0]-'1'))
	default:
		for i, act := range c.actions {
			if key.String() == act.key {
				c.cursor = i
				return act.run(a, c)
			}
		}
	}
	return c, nil
}

func (c *console) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	menuW := 34
	cardsW := w - menuW - 1
	stacked := cardsW < 60
	if stacked {
		cardsW, menuW = w, w
	}
	c.filterActions()

	var menu strings.Builder
	for i, act := range c.actions {
		line := t.Key.Render(act.key) + "  " + act.label
		if i == c.cursor {
			line = t.Selected.Render(" " + act.key + "  " + act.label + strings.Repeat(" ", clamp(menuW-8-lipgloss.Width(act.label), 0, 80)))
			if act.desc != "" {
				line += "\n" + t.Subtle.Render("    "+truncate(act.desc, menuW-8))
			}
		} else {
			line = " " + line
		}
		menu.WriteString(line + "\n")
	}
	menuPanel := panel(t, "Actions", strings.TrimRight(menu.String(), "\n"), menuW, true)

	if !c.loaded {
		body := a.spin.View() + " " + t.Subtle.Render("Checking the relay…")
		return lipgloss.JoinHorizontal(lipgloss.Top, menuPanel, " ", panel(t, "Relay", body, cardsW, false))
	}
	cards := c.cards(a, cardsW)
	top := c.switcher(a, w)
	if stacked {
		return top + cards + "\n" + menuPanel
	}
	return top + lipgloss.JoinHorizontal(lipgloss.Top, menuPanel, " ", cards)
}

// switcher renders the instance tabs and the all-relays health line above
// the dashboard; it is empty for a single relay.
func (c *console) switcher(a *App, width int) string {
	if !c.multi() {
		return ""
	}
	t := a.theme
	sel := c.selectedIndex()
	tabs := []string{t.Bold.Render(" Relays")}
	for i, inst := range c.instances {
		healthy := i < len(c.overview) && c.overview[i].Healthy()
		icon := iconDone
		if !healthy {
			icon = iconWarn
		}
		label := fmt.Sprintf(" %d %s ", i+1, inst.Name)
		if i == sel {
			tabs = append(tabs, t.Selected.Render(label+icon+" "))
		} else {
			tabs = append(tabs, label+statusIcon(t, healthy, !healthy)+" ")
		}
	}
	fit := lipgloss.NewStyle().MaxWidth(width)
	return fit.Render(strings.Join(tabs, " ")+t.Faintly.Render("   [ ] switch")) + "\n" +
		fit.Render(" "+overviewLine(t, c.overview)) + "\n"
}

func (c *console) cards(a *App, width int) string {
	t := a.theme
	r := c.report
	cols := 1
	if width >= 84 {
		cols = 2
	}
	cw := (width - (cols - 1)) / cols
	// The right column takes the remainder so both rows end flush with the
	// full-width panels below them.
	cwRight := width - (cols-1)*(cw+1)

	fp := r.Relay.Fingerprint
	if fp == "" {
		fp = t.Subtle.Render("not generated yet")
	} else if cw < 60 && len(fp) > 20 {
		fp = fp[:8] + "…" + fp[len(fp)-8:]
	}
	mode := "guard / middle"
	if r.Relay.Exit {
		mode = "exit"
	}
	ports := itoa(r.Relay.ORPort)
	if r.Relay.IPv6 {
		ports += " (IPv4 + IPv6)"
	}
	relayRows := [][2]string{
		{"Nickname", r.Relay.Nickname},
		{"Fingerprint", fp},
		{"Mode", mode},
		{"ORPort", ports},
	}
	if b := r.Bridge; b != nil {
		relayRows[2][1] = "bridge (" + b.Transport + ")"
		transport := "TCP " + itoa(b.Port)
		if b.Transport == string(relay.TransportWebTunnel) {
			relayRows[3][1] = "127.0.0.1 (auto)"
			transport = "127.0.0.1:" + itoa(b.Port) + " behind the website"
		}
		relayRows = append(relayRows, [2]string{"Transport", transport}, [2]string{"Distribution", b.Distribution})
	}
	relayCard := panel(t, "Relay", kv(t, relayRows), cw, false)

	// tor self-tests only at startup; a relay running in the consensus is
	// reachable even without a recent notice (status.ReachabilityVerdict).
	withDir := r
	if withDir.Directory == nil {
		withDir.Directory = c.dir
	}
	reach := t.Subtle.Render("not tested since startup")
	switch verdict, _ := withDir.ReachabilityVerdict(); {
	case r.Reachability.IPv4 && r.Reachability.IPv6:
		reach = statusIcon(t, true, false) + " reachable (IPv4 + IPv6)"
	case r.Reachability.IPv4:
		reach = statusIcon(t, true, false) + " reachable"
	case verdict == status.ReachNo:
		reach = statusIcon(t, false, false) + " not reachable from outside"
	case verdict == status.ReachYes:
		reach = statusIcon(t, true, false) + " reachable (in consensus)"
	}
	version := r.Tor.Version
	if version == "" {
		version = "not installed"
	}
	healthRows := [][2]string{
		{"Service", statusIcon(t, r.Service.Active, false) + " " + map[bool]string{true: "running", false: "stopped"}[r.Service.Active]},
		{"tor", statusIcon(t, r.Tor.Supported, r.Tor.Installed) + " " + version},
		{"Listener", statusIcon(t, r.Listener.IPv4 || r.Listener.IPv6, false) + " TCP " + itoa(r.Relay.ORPort)},
		{"Reachability", reach},
	}
	if b := r.Bridge; b != nil {
		healthRows = append(healthRows, [2]string{"Transport", statusIcon(t, b.Listening, false) + " " + b.Transport + map[bool]string{true: " listening", false: " not listening"}[b.Listening]})
		if b.Transport == string(relay.TransportWebTunnel) {
			// The ORPort is 127.0.0.1:auto and AssumeReachable 1: no self-test.
			healthRows = slices.Delete(healthRows, 2, 4)
			if b.WebServer != "" {
				healthRows = append(healthRows, [2]string{"nginx", statusIcon(t, b.WebServer == "active", false) + " " + b.WebServer})
			}
		}
	}
	if k := r.Keys; k != nil && k.Managed() {
		healthRows = append(healthRows, [2]string{"Signing key", signingKeyLine(t, *k, time.Now())})
	}
	health := panel(t, "Health", kv(t, healthRows), cwRight, false)

	famBody := t.Subtle.Render("single relay (no FamilyId)")
	if r.Relay.Bridge {
		famBody = t.Subtle.Render("none: bridges never join a family")
	}
	if len(r.Family.IDs) > 0 {
		var rows [][2]string
		for _, id := range r.Family.IDs {
			ok := true
			for _, m := range r.Family.MissingKeys {
				if m == id {
					ok = false
				}
			}
			rows = append(rows, [2]string{statusIcon(t, ok, false), truncate(id, cw-8)})
		}
		famBody = kv(t, rows)
	}
	if r.Family.LegacyCount > 0 {
		famBody += "\n" + t.Subtle.Render(fmt.Sprintf("legacy MyFamily: %d fingerprints", r.Family.LegacyCount))
	}
	fam := panel(t, "Family", famBody, cw, false)

	bw := r.Relay.Bandwidth
	if bw == "" {
		bw = "no limit"
	}
	acct := r.Relay.Accounting
	if acct == "" {
		acct = "off"
	}
	metrics := r.Relay.MetricsPort
	if metrics == "" {
		metrics = "off"
	}
	trafficRows := [][2]string{
		{"Limit", bw},
		{"Accounting", acct},
		{"MetricsPort", metrics},
	}
	trafficRows = append(trafficRows, c.liveRows(a, cwRight-18)...)
	trafficRows = append(trafficRows, c.overloadRows(a, cwRight-22)...)
	trafficRows = append(trafficRows, [2]string{"Sandbox", yesNo(r.Relay.Sandbox)})
	traffic := panel(t, "Traffic", kv(t, trafficRows), cwRight, false)

	var dirBody string
	switch {
	case c.dirLoading:
		dirBody = a.spin.View() + " " + t.Subtle.Render("asking Tor Metrics…")
	case c.dirErr != nil:
		dirBody = statusIcon(t, false, true) + " " + t.Subtle.Render(truncate(c.dirErr.Error(), cw-6))
	case r.Relay.Bridge && c.bridgeDir != nil:
		dirW := cw
		if cols == 2 {
			dirW = width
		}
		dirBody = kv(t, bridgeDirRows(t, c.bridgeDir, dirW-16))
	case r.Relay.Bridge && r.Relay.Fingerprint != "":
		dirBody = t.Subtle.Render("Not published yet — bridges appear after about 3 hours, by hashed fingerprint.")
	case c.dir == nil && r.Relay.Fingerprint != "":
		dirBody = t.Subtle.Render("Not published yet — new relays appear after about 3 hours.")
	case c.dir == nil:
		dirBody = t.Subtle.Render("Start Tor once to get a fingerprint.")
	default:
		d := c.dir
		dirW := cw
		if cols == 2 {
			dirW = width
		}
		dirRows := [][2]string{
			{"Status", statusIcon(t, d.Running, false) + " " + map[bool]string{true: "running", false: "not running"}[d.Running]},
			{"Flags", truncate(strings.Join(d.Flags, " "), dirW-16)},
			{"Advertised", humanBandwidth(d.AdvertisedBandwidth)},
			{"Weight", fmt.Sprintf("%d", d.ConsensusWeight)},
			{"First seen", d.FirstSeen},
		}
		dirBody = kv(t, append(dirRows, c.historyRows(a, dirW-18)...))
	}
	dir := panel(t, "Tor Metrics", dirBody, cw, false)

	var rows []string
	if cols == 2 {
		rows = []string{
			sideBySide(relayCard, health),
			sideBySide(fam, traffic),
			panel(t, "Tor Metrics", dirBody, width, false),
		}
	} else {
		rows = []string{relayCard, health, fam, traffic, dir}
	}
	if len(r.RecentLog) > 0 {
		var lb strings.Builder
		for i, line := range r.RecentLog {
			if i > 0 {
				lb.WriteString("\n")
			}
			style := t.Subtle
			if strings.Contains(line, "Self-testing indicates") {
				style = t.GoodText
			} else if strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
				style = t.WarnText
			}
			lb.WriteString(style.Render(truncate(line, width-4)))
		}
		rows = append(rows, panel(t, "Recent log  (l opens the live view)", lb.String(), width, false))
	}
	if warnings := slices.Concat(r.Warnings, c.overloadWarnings()); len(warnings) > 0 {
		var wb strings.Builder
		for i, w := range warnings {
			if i > 0 {
				wb.WriteString("\n")
			}
			wb.WriteString(t.WarnText.Render(iconWarn + " " + w))
		}
		rows = append([]string{panel(t, "Needs attention", wb.String(), width, true)}, rows...)
	}
	return strings.Join(rows, "\n")
}

func (c *console) keys(a *App) []string {
	refresh := "refresh"
	if !c.updated.IsZero() {
		refresh = "refresh · updated " + ago(time.Since(c.updated)) + " ago"
	}
	if c.multi() {
		return []string{"↑/↓", "select", "enter", "run", "[/]", "relay " + c.selected().Name, "r", refresh, "q", "quit"}
	}
	return []string{"↑/↓", "select", "enter", "run", "r", refresh, "q", "quit"}
}

// liveRows are the Traffic card's MetricsPort rows; barW is the room left
// for the sparkline.
func (c *console) liveRows(a *App, barW int) [][2]string {
	t := a.theme
	switch {
	case c.report.Relay.MetricsPort == "":
		return [][2]string{{"Live", t.Subtle.Render("enable MetricsPort (e) to see it")}}
	case c.loaded && !c.report.Service.Active:
		return [][2]string{{"Live", t.Subtle.Render("Tor is stopped")}}
	case c.liveErr != nil:
		return [][2]string{{"Live", statusIcon(t, false, true) + " " + t.Subtle.Render("MetricsPort not answering")}}
	case len(c.rates) == 0:
		return [][2]string{{"Live", a.spin.View() + " " + t.Subtle.Render("measuring…")}}
	}
	return [][2]string{
		{"Live", t.InfoText.Render("↓ "+humanRate(c.rate.Read)) + "  " + t.Directive.Render("↑ "+humanRate(c.rate.Written))},
		{"", t.Directive.Render(trendSparkline(c.rates, clamp(barW, 8, liveWindow))) + " " + t.Faintly.Render(fmt.Sprintf("%ds", len(c.rates)*int(liveEvery.Seconds())))},
		{"Connections", fmt.Sprintf("%d OR", c.last.Connections)},
	}
}

// historyRows are the Tor Metrics card's traffic-history rows.
func (c *console) historyRows(a *App, barW int) [][2]string {
	t := a.theme
	if c.history == nil {
		return nil
	}
	rd, wr := c.history.Read, c.history.Written
	if len(wr.Values) == 0 {
		return nil
	}
	total := make([]float64, len(wr.Values))
	var in, out float64
	for i, v := range wr.Values {
		total[i] = v
		if i < len(rd.Values) && !math.IsNaN(rd.Values[i]) {
			total[i] += rd.Values[i]
			in += rd.Values[i] * rd.Interval.Seconds()
		}
		if !math.IsNaN(v) {
			out += v * wr.Interval.Seconds()
		}
	}
	span := wr.Last.Sub(wr.First) + wr.Interval
	label := fmt.Sprintf("%d days", int(span.Hours()/24+0.5))
	return [][2]string{
		{label, t.Directive.Render(sparkline(total, clamp(barW, 8, 90)))},
		{"", t.Subtle.Render("in " + humanBytes(in) + " · out " + humanBytes(out))},
	}
}

// ago formats an elapsed time coarsely: 4s, 2m, 1h.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

// sideBySide joins two rendered panels, stretching the shorter one so the
// row has a clean bottom edge.
func sideBySide(left, right string) string {
	h := max(lipgloss.Height(left), lipgloss.Height(right))
	return lipgloss.JoinHorizontal(lipgloss.Top, stretch(left, h), " ", stretch(right, h))
}

// stretch pads a bordered panel to h lines by repeating its side borders.
func stretch(p string, h int) string {
	lines := strings.Split(p, "\n")
	if len(lines) >= h || len(lines) < 2 {
		return p
	}
	bottom := lines[len(lines)-1]
	blank := borderLine(bottom, lipgloss.Width(bottom))
	out := append([]string{}, lines[:len(lines)-1]...)
	for len(out) < h-1 {
		out = append(out, blank)
	}
	return strings.Join(append(out, bottom), "\n")
}

// borderLine turns a styled bottom border ("╰────╯") into a styled side
// border line ("│    │") of the same width and colour.
func borderLine(bottom string, width int) string {
	r := strings.NewReplacer("╰", "│", "╯", "│", "─", " ")
	line := r.Replace(bottom)
	if lipgloss.Width(line) != width {
		return strings.Repeat(" ", width)
	}
	return line
}

func humanBandwidth(bytesPerSecond int64) string {
	mbit := float64(bytesPerSecond) * 8 / 1e6
	return fmt.Sprintf("%.1f Mbit/s", mbit)
}
