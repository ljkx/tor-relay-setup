package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// bridgeView shows the bridge line in a copy-friendly form, with how the
// bridge is handed out and how to check that censored users can reach it.
type bridgeView struct {
	back *console
}

func newBridgeView(back *console) *bridgeView { return &bridgeView{back: back} }

func (v *bridgeView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok {
		b := v.back.report.Bridge
		switch k.String() {
		case "esc", "q", "backspace", "enter":
			return v.back, v.back.refresh(a)
		case "y":
			if b == nil || b.Line == "" {
				return v, toast("No bridge line yet.")
			}
			return v, tea.Batch(tea.SetClipboard(b.Line), toast("Copied to the clipboard (OSC 52: most terminals, also over SSH)."))
		case "w":
			if b == nil || b.Line == "" {
				return v, toast("No bridge line yet.")
			}
			path := bridgeLineFile(v.back.selected())
			if _, err := a.opt.Host.WriteFile(path, []byte(b.Line+"\n"), host.FileOptions{Mode: 0o600}); err != nil {
				return v, toast("Could not write " + path + ": " + err.Error())
			}
			if a.opt.DryRun {
				return v, toast("Dry run: would write " + path)
			}
			return v, toast("Wrote " + path + " (mode 600): cat it to copy the line")
		}
	}
	return v, nil
}

// bridgeLineFile is where "w" saves the bridge line.
func bridgeLineFile(inst relay.Instance) string {
	if inst.OrDefault().IsDefault() {
		return "/root/tor-bridge-line.txt"
	}
	return "/root/tor-bridge-line-" + inst.Name + ".txt"
}

func (v *bridgeView) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	r := v.back.report
	b := r.Bridge
	title := t.Title.Render(" Bridge line") + t.Subtle.Render(instanceTitle(v.back.selected()))
	if b == nil {
		return title + "\n\n" + t.Subtle.Render("This relay is not a bridge.")
	}
	title += t.Subtle.Render(" · " + b.Transport)

	// The line itself is printed bare, without borders or colour, so a
	// terminal selection copies exactly the line.
	var line string
	switch {
	case b.Line == "":
		line = t.Subtle.Render("No bridge line yet: tor writes it once it has started the transport. Start Tor, then refresh.")
	case !b.LineComplete:
		line = b.Line + "\n\n" + t.WarnText.Render(iconWarn+" Replace <IP ADDRESS> with this server's public IPv4 address before sharing; the address is not known yet (Tor has not confirmed reachability).")
	default:
		line = b.Line
	}

	var share []string
	switch b.Distribution {
	case "none":
		share = append(share, t.WarnText.Render(iconWarn+" BridgeDistribution none: the Tor Project never hands this bridge out. Give the line privately to the people who need it."))
	default:
		share = append(share, "The Tor Project hands this bridge out ("+b.Distribution+"). You can also give the line to people directly; each copy you share is one more way for a censor to learn it.")
	}
	share = append(share, "Users paste it in Tor Browser: Settings → Connection → Bridges → Add a bridge manually.")

	var check []string
	if b.Transport == string(relay.TransportObfs4) {
		check = append(check, "Test the obfs4 port from outside: "+b.ScanURL(r.PublicIPv4))
	} else {
		check = append(check, "Add the line to Tor Browser on another network and connect; there is no scanner for WebTunnel.")
	}
	if b.HashedFingerprint != "" {
		check = append(check,
			"Bridge authority test results: "+relay.BridgeStatusURL+b.HashedFingerprint,
			"Tor Metrics (after ~3 hours): https://metrics.torproject.org/rs.html#details/"+b.HashedFingerprint)
	}

	var status [][2]string
	status = append(status,
		[2]string{"Transport", statusIcon(t, b.Listening, false) + " " + b.Transport + map[bool]string{true: " listening", false: " not listening"}[b.Listening]},
		[2]string{"Hashed fingerprint", b.HashedFingerprint},
	)
	if d := v.back.bridgeDir; d != nil {
		status = append(status, bridgeDirRows(t, d, w-26)...)
	}

	line = lipgloss.NewStyle().Width(w - 1).Render(line)
	return title + "\n\n" + t.Bold.Render(" Share this line") + t.Subtle.Render("  (y copies it, w saves it to "+bridgeLineFile(v.back.selected())+")") + "\n\n" + indentLines(line, " ") + "\n\n" +
		panel(t, "Handing it out", strings.Join(share, "\n"), w, false) + "\n" +
		panel(t, "Check that it works", strings.Join(check, "\n"), w, false) + "\n" +
		panel(t, "Status", kv(t, status), w, false)
}

func (v *bridgeView) keys(a *App) []string {
	return []string{"y", "copy line", "w", "save to file", "esc", "back"}
}

// bridgeDirRows are the Tor Metrics rows of a bridge.
func bridgeDirRows(t Theme, d *onionoo.Bridge, valueW int) [][2]string {
	dist := d.Distributor
	if dist == "" {
		dist = t.Subtle.Render("not assigned yet (new bridges show none for about a day)")
	}
	rows := [][2]string{
		{"Status", statusIcon(t, d.Running, false) + " " + map[bool]string{true: "running", false: "not running"}[d.Running]},
		{"Flags", truncate(strings.Join(d.Flags, " "), valueW)},
		{"Transports", strings.Join(d.Transports, ", ")},
		{"Distributor", dist},
		{"Advertised", humanBandwidth(d.AdvertisedBandwidth)},
		{"First seen", d.FirstSeen},
	}
	if d.VersionStatus != "" {
		rows = append(rows, [2]string{"Version", d.Version + " (" + d.VersionStatus + ")"})
	}
	if len(d.Blocklist) > 0 {
		rows = append(rows, [2]string{"Blocked in", t.WarnText.Render(strings.Join(d.Blocklist, ", ") + " (not handed out there)")})
	}
	return rows
}

// indentLines prefixes every line of s.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
