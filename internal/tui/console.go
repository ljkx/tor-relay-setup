package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

const torrcPath = "/etc/tor/torrc"

type (
	reportMsg    status.Report
	directoryMsg struct {
		relay *onionoo.Relay
		err   error
	}
)

type action struct {
	key, label, desc string
	run              func(a *App, c *console) (screen, tea.Cmd)
}

// console is the operator dashboard for an existing relay.
type console struct {
	report     status.Report
	loaded     bool
	dir        *onionoo.Relay
	dirErr     error
	dirLoading bool
	cursor     int
	actions    []action
}

func newConsole() *console {
	c := &console{}
	c.actions = []action{
		{"r", "Refresh", "Re-check everything", func(a *App, c *console) (screen, tea.Cmd) { return c, c.refresh(a) }},
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

func (c *console) init(a *App) tea.Cmd { return c.refresh(a) }

func (c *console) refresh(a *App) tea.Cmd {
	h := a.opt.Host
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return reportMsg(status.Collect(ctx, h, status.Options{TorrcPath: torrcPath}))
	}
}

func (c *console) lookup() tea.Cmd {
	fp := c.report.Relay.Fingerprint
	if fp == "" {
		return nil
	}
	c.dirLoading = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		r, err := status.Directory(ctx, onionoo.Client{}, fp)
		return directoryMsg{relay: r, err: err}
	}
}

func (c *console) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case reportMsg:
		first := !c.loaded
		c.report, c.loaded = status.Report(msg), true
		if first || c.dir == nil {
			return c, c.lookup()
		}
	case directoryMsg:
		c.dir, c.dirErr, c.dirLoading = msg.relay, msg.err, false
	case tea.KeyPressMsg:
		switch msg.String() {
		case "up", "k":
			c.cursor = (c.cursor - 1 + len(c.actions)) % len(c.actions)
		case "down", "j", "tab":
			c.cursor = (c.cursor + 1) % len(c.actions)
		case "enter":
			return c.actions[c.cursor].run(a, c)
		default:
			for i, act := range c.actions {
				if msg.String() == act.key {
					c.cursor = i
					return act.run(a, c)
				}
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
	traffic := panel(t, "Traffic", kv(t, [][2]string{
		{"Rate", bw},
		{"Accounting", acct},
		{"MetricsPort", metrics},
		{"Sandbox", yesNo(r.Relay.Sandbox)},
	}), cwRight, false)

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
		dirBody = kv(t, [][2]string{
			{"Status", statusIcon(t, d.Running, false) + " " + map[bool]string{true: "running", false: "not running"}[d.Running]},
			{"Flags", truncate(strings.Join(d.Flags, " "), cw-16)},
			{"Advertised", humanBandwidth(d.AdvertisedBandwidth)},
			{"Weight", fmt.Sprintf("%d", d.ConsensusWeight)},
			{"First seen", d.FirstSeen},
		})
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
	return []string{"↑/↓", "select", "enter", "run", "r", "refresh", "q", "quit"}
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
