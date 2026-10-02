package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// review shows everything that will happen before anything happens.
type review struct {
	setup   config.Setup
	back    *wizard
	vp      viewport.Model
	ready   bool
	confirm bool
	problem string
}

func newReview(a *App, s config.Setup, back *wizard) *review {
	// The MetricsPort address this host gets (another relay instance may
	// already use 9035); preflight picks the same one.
	s.Relay.MetricsAddress = plan.ResolveMetricsAddress(a.opt.Host, s)
	r := &review{setup: s, back: back, vp: viewport.New()}
	if err := s.Validate(); err != nil {
		r.problem = err.Error()
	} else if err := plan.Conflicts(s, plan.OtherInstances(a.opt.Host, s.Instance())); err != nil {
		r.problem = err.Error()
	}
	r.resize(a)
	return r
}

func (r *review) resize(a *App) {
	r.vp.SetWidth(a.contentWidth())
	r.vp.SetHeight(clamp(a.height-7, 5, 400))
	r.vp.SetContent(r.render(a))
	r.ready = true
}

func (r *review) render(a *App) string {
	t := a.theme
	s := r.setup
	w := a.contentWidth()
	col := w
	twoCol := w >= 110
	if twoCol {
		col = (w - 1) / 2
	}

	mode := "Guard / middle relay"
	if s.IsExit() {
		mode = "Exit relay · " + s.Exit.Policy + " policy"
		if s.Exit.Unbound {
			mode += " · local Unbound DNS"
		}
		if s.Exit.Notice {
			mode += " · exit notice on port 80"
		}
	}
	ipv6 := "disabled"
	if s.Relay.IPv6 != "" {
		ipv6 = "[" + s.Relay.IPv6 + "]:" + itoa(s.Relay.ORPort)
	}
	fam := "none"
	switch s.Family.Mode {
	case "generate":
		fam = "new key " + s.Family.KeyName + " (generated during apply)"
	case "import":
		fam = "import " + s.Family.ImportKey
	}
	orport := itoa(s.Relay.ORPort) + " (IPv4) · IPv6 " + ipv6
	var bridgeRows [][2]string
	if s.IsBridge() {
		fam = "none (bridges never join one)"
		mode = "Bridge · obfs4 · distribution " + s.Distribution()
		bridgeRows = [][2]string{{"obfs4 port", itoa(s.Bridge.Obfs4Port)}}
		if s.IsWebTunnel() {
			mode = "Bridge · WebTunnel · distribution " + s.Distribution()
			orport = "127.0.0.1:auto (behind the website)"
			web := "nginx (managed) · certificate " + s.Bridge.Certificate
			if !s.ManagedNginx() {
				web = "your own web server (snippet below)"
			}
			bridgeRows = [][2]string{{"URL", truncate(s.WebTunnelURL(), col-18)}, {"Web server", web}}
		}
	}
	var relayRows [][2]string
	if inst := s.Instance(); !inst.IsDefault() {
		relayRows = append(relayRows, [2]string{"Instance", inst.Name + " · " + inst.Unit})
	}
	relayRows = append(relayRows, [][2]string{
		{"Mode", mode},
		{"Nickname", s.Relay.Nickname},
		{"ContactInfo", truncate(s.Relay.Contact, col-18)},
		{"ORPort", orport},
	}...)
	relayRows = append(relayRows, bridgeRows...)
	relayRows = append(relayRows, [2]string{"Family", fam})
	if s.Relay.OfflineMasterKey {
		relayRows = append(relayRows, [2]string{"Identity", "offline master key (OfflineMasterKey 1)"})
	}

	bw, _ := s.Bandwidth.Resolve()
	bwText, capText := "no limit", "none"
	switch bw.Mode {
	case relay.BandwidthSteady:
		bwText = fmt.Sprintf("≈ %.1f Mbit/s steady", relay.MbitFromKBytes(bw.RateKBytes))
		capText = fmt.Sprintf("%d GBytes/month (safety cap)", bw.AccountingMaxGBytes)
	case relay.BandwidthManual:
		bwText = fmt.Sprintf("%d Mbit/s, burst %d", bw.RateMbit, bw.BurstMbit)
	case relay.BandwidthAccounting:
		bwText = "full speed"
	}
	if capText == "none" && bw.AccountingMaxGBytes > 0 {
		capText = fmt.Sprintf("%d GBytes/month", bw.AccountingMaxGBytes)
	}
	host := "unchanged"
	if s.System.Hostname != "" {
		host = s.System.Hostname
	}
	sysRows := [][2]string{
		{"Bandwidth", bwText},
		{"Monthly cap", capText},
		{"Updates", yesNo(s.System.UnattendedUpgrades) + " (security + Tor Project)"},
		{"Firewall", s.System.Firewall},
		{"MetricsPort", map[bool]string{true: s.RelayConfig(nil).MetricsPort + " (local only)", false: "off"}[s.Relay.MetricsPort]},
		{"Sandbox", yesNo(s.Relay.Sandbox)},
		{"Nyx", yesNo(s.System.Nyx)},
		{"Hostname", host},
	}
	if s.System.Tuning {
		sysRows = append(sysRows, [2]string{"Tuning", "kernel limits for a fast relay"})
	}

	steps := plan.Build(s, a.checks.Facts)
	var changes strings.Builder
	wrap := lipgloss.NewStyle().Width(max(w-7, 20)) // panel frame 4, number 3
	for i, c := range plan.Changes(steps) {
		if i > 0 {
			changes.WriteString("\n")
		}
		// Long changes wrap with a hanging indent under their text.
		lines := strings.Split(wrap.Render(c), "\n")
		changes.WriteString(t.Faintly.Render(fmt.Sprintf("%2d ", i+1)) + strings.TrimRight(lines[0], " "))
		for _, l := range lines[1:] {
			changes.WriteString("\n   " + strings.TrimRight(l, " "))
		}
	}

	cfg := s.RelayConfig(nil)
	torrc := highlightTorrc(t, string(cfg.Render(program(a.opt.Version), time.Now())), w-6)

	var top string
	if twoCol {
		left, right := kv(t, relayRows), kv(t, sysRows)
		lines := max(lipgloss.Height(left), lipgloss.Height(right))
		left += strings.Repeat("\n", lines-lipgloss.Height(left))
		right += strings.Repeat("\n", lines-lipgloss.Height(right))
		top = lipgloss.JoinHorizontal(lipgloss.Top,
			panel(t, "Relay", left, col, false), " ",
			panel(t, "System", right, col, false))
	} else {
		top = panel(t, "Relay", kv(t, relayRows), w, false) + "\n" + panel(t, "System", kv(t, sysRows), w, false)
	}
	parts := []string{top}
	if r.problem != "" {
		parts = append(parts, panel(t, "Needs attention", t.BadText.Render(r.problem), w, true))
	}
	if advice := s.Warnings(); len(advice) > 0 {
		var ab strings.Builder
		for i, line := range advice {
			if i > 0 {
				ab.WriteString("\n")
			}
			ab.WriteString(t.WarnText.Render(iconWarn + " " + line))
		}
		parts = append(parts, panel(t, "Advice", ab.String(), w, false))
	}
	parts = append(parts,
		panel(t, fmt.Sprintf("What will change (%d)", len(plan.Changes(steps))), changes.String(), w, false),
		panel(t, s.Instance().TorrcPath, torrc, w, false),
	)
	if s.IsWebTunnel() && !s.ManagedNginx() {
		snippet := "Inside the HTTPS server block for " + s.Bridge.Domain + " (nginx; translate for other servers):\n\n" +
			strings.TrimRight(plan.NginxLocation(s.Bridge.Path, s.WebTunnelPort()), "\n")
		parts = append(parts, panel(t, "Your web server needs this", t.Subtle.Render(snippet), w, false))
	}
	return strings.Join(parts, "\n")
}

func (r *review) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg, factsMsg:
		r.resize(a)
	case tea.KeyPressMsg:
		if r.confirm {
			switch msg.String() {
			case "y", "enter":
				ap := newApply(a, r.setup)
				return ap, ap.start(a)
			default:
				r.confirm = false
				return r, nil
			}
		}
		switch msg.String() {
		case "a", "enter":
			if r.problem != "" {
				return r, toast("Fix the highlighted problem first (b goes back).")
			}
			r.confirm = true
			return r, nil
		case "b", "esc":
			r.back.form = r.back.build(a)
			return r.back, r.back.form.Init()
		case "s":
			return r, r.save(a)
		case "q":
			return r, quit(ErrAborted)
		}
	}
	var cmd tea.Cmd
	r.vp, cmd = r.vp.Update(msg)
	return r, cmd
}

func (r *review) save(a *App) tea.Cmd {
	path := a.opt.ConfigPath
	if path == "" {
		path = "relay.toml"
	}
	data, err := r.setup.Marshal()
	if err == nil {
		err = os.WriteFile(path, data, 0o600)
	}
	if err != nil {
		return toast("Could not save: " + err.Error())
	}
	return toast("Saved " + path + " — replay with: tor-relay-setup apply --config " + path)
}

func (r *review) view(a *App) string {
	t := a.theme
	title := t.Title.Render(" Review") + t.Subtle.Render(" · nothing has changed yet")
	if a.opt.DryRun {
		title += t.Subtle.Render(" · dry run: apply only shows what would happen")
	}
	body := r.vp.View()
	if r.confirm {
		prompt := t.Brand.Render(" Apply these changes now?") + "  " + t.Key.Render("y") + t.KeyDesc.Render(" apply") + "   " + t.Key.Render("any other key") + t.KeyDesc.Render(" cancel")
		return title + "\n" + body + "\n" + prompt
	}
	return title + "\n" + body
}

func (r *review) keys(a *App) []string {
	return []string{"a", "apply", "s", "save as relay.toml", "b", "back to edit", "↑/↓", "scroll", "q", "quit"}
}
