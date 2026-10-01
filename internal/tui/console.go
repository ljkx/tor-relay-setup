package tui

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

const torrcPath = "/etc/tor/torrc"

// How often the console refreshes on its own.
const (
	liveEvery      = 2 * time.Second  // MetricsPort scrape
	refreshEvery   = 30 * time.Second // service, listener, log, warnings
	directoryEvery = 30 * time.Minute // Onionoo publishes hourly
	liveWindow     = 60               // samples kept for the live sparkline
)

type (
	reportMsg    status.Report
	directoryMsg struct {
		relay *onionoo.Relay
		err   error
	}
	historyMsg struct {
		bw  *onionoo.Bandwidth
		err error
	}
	sampleMsg struct {
		sample metrics.Sample
		err    error
	}
	liveTickMsg    time.Time
	refreshTickMsg time.Time
)

type action struct {
	key, label, desc string
	run              func(a *App, c *console) (screen, tea.Cmd)
}

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
	cursor     int
	actions    []action
	ticking    bool

	// Live traffic from the MetricsPort.
	last    metrics.Sample
	rate    metrics.Rate
	rates   []float64 // total bytes/s, oldest first
	liveErr error
}

func newConsole() *console {
	c := &console{}
	c.actions = []action{
		{"r", "Refresh", "Re-check everything now", func(a *App, c *console) (screen, tea.Cmd) {
			c.dirAt = time.Time{} // ask Tor Metrics again too
			return c, c.refresh(a)
		}},
		{"l", "Live logs", "Follow the Tor log in place", func(a *App, c *console) (screen, tea.Cmd) {
			v := newLogView(c)
			return v, v.start(a)
		}},
		{"f", "Relay family", "Keys, FamilyIds, share, import", func(a *App, c *console) (screen, tea.Cmd) {
			return newFamilyView(a, c), nil
		}},
		{"e", "Edit settings", "Nickname, contact, bandwidth, metrics", newEditView},
		{"s", "Restart Tor", "Restart and verify the service", func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Restart Tor", restartTask(false))
		}},
		{"o", "Reload Tor", "Re-read torrc without a restart", func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Reload Tor", reloadTask())
		}},
		{"p", "Stop / start Tor", "Take the relay offline, or bring it back", func(a *App, c *console) (screen, tea.Cmd) {
			if c.report.Service.Active {
				return newConfirmView(c, "Stop Tor? The relay goes offline until you start it again.", func() (screen, tea.Cmd) {
					return newTask(a, c, "Stop Tor", stopTask())
				}), nil
			}
			return newTask(a, c, "Start Tor", startTask())
		}},
		{"u", "Update Tor", "Refresh apt and upgrade tor", func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Update Tor", updateTask())
		}},
		{"b", "Back up keys", "Archive identity + family keys to /root", func(a *App, c *console) (screen, tea.Cmd) {
			return newTask(a, c, "Back up keys", backupTask(c.report.Family.KeyDirectory))
		}},
		{"w", "Reconfigure", "Run the full setup wizard again", func(a *App, c *console) (screen, tea.Cmd) {
			prefill := config.Default()
			if data, err := a.opt.Host.ReadFile(torrcPath); err == nil {
				prefill = config.FromDocument(relay.ParseDocument(data))
			}
			w := newWizard(a, prefill)
			return w, w.init(a)
		}},
		{"q", "Quit", "", func(a *App, c *console) (screen, tea.Cmd) { return c, quit(nil) }},
	}
	return c
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
		return sampleMsg{sample: s, err: err}
	}
}

// background handles the console's own data messages and timers. It runs
// whether or not the console is on screen; ok is false for other messages.
func (c *console) background(a *App, msg tea.Msg) (cmd tea.Cmd, ok bool) {
	switch msg := msg.(type) {
	case reportMsg:
		first := !c.loaded
		c.report, c.loaded, c.updated = status.Report(msg), true, time.Now()
		if first {
			return tea.Batch(c.lookup(a), c.scrape()), true
		}
		if !c.dirLoading && (c.dirAt.IsZero() || time.Since(c.dirAt) > directoryEvery) {
			return c.lookup(a), true
		}
		return nil, true
	case directoryMsg:
		c.dir, c.dirErr, c.dirLoading, c.dirAt = msg.relay, msg.err, false, time.Now()
		return nil, true
	case historyMsg:
		if msg.err == nil {
			c.history = msg.bw
		}
		return nil, true
	case sampleMsg:
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
	c.last = s
}

func (c *console) refresh(a *App) tea.Cmd {
	h := a.opt.Host
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return reportMsg(status.Collect(ctx, h, status.Options{TorrcPath: torrcPath}))
	}
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
	return tea.Batch(
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			r, err := status.Directory(ctx, client, fp)
			return directoryMsg{relay: r, err: err}
		},
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			bw, err := client.Bandwidth(ctx, fp)
			return historyMsg{bw: bw, err: err}
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
	switch key.String() {
	case "up", "k":
		c.cursor = (c.cursor - 1 + len(c.actions)) % len(c.actions)
	case "down", "j", "tab":
		c.cursor = (c.cursor + 1) % len(c.actions)
	case "enter":
		return c.actions[c.cursor].run(a, c)
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
	if stacked {
		return cards + "\n" + menuPanel
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, menuPanel, " ", cards)
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
	relayCard := panel(t, "Relay", kv(t, [][2]string{
		{"Nickname", r.Relay.Nickname},
		{"Fingerprint", fp},
		{"Mode", mode},
		{"ORPort", ports},
	}), cw, false)

	reach := t.Subtle.Render("no self-test in the last 24 h")
	switch {
	case r.Reachability.IPv4 && r.Reachability.IPv6:
		reach = statusIcon(t, true, false) + " reachable (IPv4 + IPv6)"
	case r.Reachability.IPv4:
		reach = statusIcon(t, true, false) + " reachable"
	case r.Reachability.Failed:
		reach = statusIcon(t, false, false) + " not reachable from outside"
	}
	version := r.Tor.Version
	if version == "" {
		version = "not installed"
	}
	health := panel(t, "Health", kv(t, [][2]string{
		{"Service", statusIcon(t, r.Service.Active, false) + " " + map[bool]string{true: "running", false: "stopped"}[r.Service.Active]},
		{"tor", statusIcon(t, r.Tor.Supported, r.Tor.Installed) + " " + version},
		{"Listener", statusIcon(t, r.Listener.IPv4 || r.Listener.IPv6, false) + " TCP " + itoa(r.Relay.ORPort)},
		{"Reachability", reach},
	}), cwRight, false)

	famBody := t.Subtle.Render("single relay (no FamilyId)")
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
	trafficRows = append(trafficRows, [2]string{"Sandbox", yesNo(r.Relay.Sandbox)})
	traffic := panel(t, "Traffic", kv(t, trafficRows), cwRight, false)

	var dirBody string
	switch {
	case c.dirLoading:
		dirBody = a.spin.View() + " " + t.Subtle.Render("asking Tor Metrics…")
	case c.dirErr != nil:
		dirBody = statusIcon(t, false, true) + " " + t.Subtle.Render(truncate(c.dirErr.Error(), cw-6))
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
	if len(r.Warnings) > 0 {
		var wb strings.Builder
		for i, w := range r.Warnings {
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
