package monitor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// Local mode (`monitor install --local`) runs the same stack without Caddy
// and without opening any port, for operators who host it on one of their
// non-exit relays: Grafana, Prometheus and fleet serve listen on loopback
// only, and operators reach Grafana through an SSH tunnel.

// Placeholders in the tunnel command when the login or the address of
// this server cannot be told.
const (
	TunnelUserPlaceholder = "USER"
	TunnelHostPlaceholder = "SERVER"
)

// Tunnel is the SSH tunnel an operator opens to reach Grafana in local mode.
type Tunnel struct {
	User string // login on this server
	Host string // this server's public address
	Port int    // SSH port; 0 or 22 is the default
}

// Command is the ssh command that forwards localhost:3000 to Grafana.
func (t Tunnel) Command() string {
	cmd := "ssh -N -L 3000:" + GrafanaListen
	if t.Port != 0 && t.Port != 22 {
		cmd += " -p " + strconv.Itoa(t.Port)
	}
	return cmd + " " + t.User + "@" + t.Host
}

// Rows are the label/text pairs install and status print for local mode
// after the Grafana line.
func (t Tunnel) Rows() [][2]string {
	port := ""
	if t.Port != 0 && t.Port != 22 {
		port = ", SSH port " + strconv.Itoa(t.Port)
	}
	rows := [][2]string{
		{"SSH tunnel", t.Command() + "   (leave it running, then open " + LocalGrafanaURL + ")"},
		{"Termius", "Port forwarding: local 3000 → 127.0.0.1:3000 through host " + t.Host + port + ", then open " + LocalGrafanaURL},
		{"Fleet UI", "http://localhost:9850/ (add -L 9850:" + ServeListen + " to the tunnel; logins: sudo tor-relay-setup fleet serve passwd NAME)"},
	}
	if t.User == TunnelUserPlaceholder || t.Host == TunnelHostPlaceholder {
		rows = append(rows, [2]string{"", "Replace " + TunnelUserPlaceholder + " with your SSH login and " + TunnelHostPlaceholder + " with this server's address."})
	}
	return rows
}

var loginRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// DetectTunnel works out the tunnel command for this server: the login
// from SUDO_USER, the address and port from SSH_CONNECTION (the address
// the operator connected to) when it is public, else the relay's torrc
// Address, else the first public interface address. Whatever is unknown
// stays a placeholder.
func DetectTunnel(h host.Host, f system.Facts, getenv func(string) string) Tunnel {
	if getenv == nil {
		getenv = os.Getenv
	}
	t := Tunnel{User: TunnelUserPlaceholder, Host: TunnelHostPlaceholder}
	if u := getenv("SUDO_USER"); u != "root" && loginRE.MatchString(u) {
		t.User = u
	}
	if c := strings.Fields(getenv("SSH_CONNECTION")); len(c) == 4 {
		if ip := net.ParseIP(c[2]); system.IsPublicIPv4(ip) || system.IsGlobalIPv6(ip) {
			t.Host = ip.String()
		}
		if p, err := strconv.Atoi(c[3]); err == nil && p > 0 && p < 65536 {
			t.Port = p
		}
	}
	if t.Host == TunnelHostPlaceholder {
		t.Host = torrcAddress(h)
	}
	switch {
	case t.Host != TunnelHostPlaceholder:
	case len(f.IPv4) > 0:
		t.Host = f.IPv4[0]
	case len(f.IPv6) > 0:
		t.Host = f.IPv6[0]
	}
	if t.Port == 0 && len(f.SSHPorts) > 0 && !slices.Contains(f.SSHPorts, 22) {
		t.Port = f.SSHPorts[0]
	}
	return t
}

var addressRE = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)

// torrcAddress returns the first Address a relay on this host sets, or the
// placeholder.
func torrcAddress(h host.Host) string {
	configs, _ := relay.DiscoverConfigs(h)
	for _, c := range configs {
		v, _ := c.Doc.Get("Address")
		if f := strings.Fields(relay.Unquote(v)); len(f) > 0 && addressRE.MatchString(f[0]) {
			if ip := net.ParseIP(f[0]); ip == nil || system.IsPublicIPv4(ip) || system.IsGlobalIPv6(ip) {
				return f[0]
			}
		}
	}
	return TunnelHostPlaceholder
}

// checkRelaysLocal refuses local mode on an exit relay and notes that the
// stack shares a non-exit relay.
func (in *Install) checkRelaysLocal(h host.Host, r plan.Reporter) error {
	configs, _ := relay.DiscoverConfigs(h)
	var exits, names []string
	for _, c := range configs {
		names = append(names, c.Name)
		if c.Doc.ActsAsExit() {
			exits = append(exits, c.Name+" ("+c.TorrcPath+")")
		}
	}
	if len(exits) > 0 {
		return fmt.Errorf("this server runs an exit relay: %s. monitor install --local does not put Grafana and Prometheus on an exit: "+
			"exits attract abuse complaints, scans and denial-of-service attacks, and their addresses are on public exit lists, so keep the monitoring off them. "+
			"Run it on a non-exit relay, or on a separate management server with monitor install --domain NAME", strings.Join(exits, ", "))
	}
	if len(names) == 0 {
		return nil
	}
	r.Note(plan.Info, fmt.Sprintf("This server runs %d non-exit Tor relay(s) (%s): Grafana and Prometheus will share this relay; they listen on 127.0.0.1 only and open no port", len(names), strings.Join(names, ", ")))
	if need := 1024 + system.RequiredRAMMiB(false)*len(names); in.Facts.MemTotalMiB > 0 && in.Facts.MemTotalMiB < need {
		r.Note(plan.Warn, fmt.Sprintf("%d MiB RAM: %d relay(s) plus Grafana and Prometheus want about %d MiB", in.Facts.MemTotalMiB, len(names), need))
	}
	return nil
}

// Firewall rule comments of the public mode's ports. Switching to local
// mode removes only rules that carry them.
const (
	httpRuleLabel  = "HTTP (Caddy: ACME and redirect)"
	httpsRuleLabel = "HTTPS (Caddy: Grafana)"
)

func publicPorts() []system.Port {
	return []system.Port{{Number: 80, Label: httpRuleLabel}, {Number: 443, Label: httpsRuleLabel}}
}

// switchingToLocal reports whether this run turns a public install into a
// local one.
func (in *Install) switchingToLocal() bool {
	return in.Opt.Local && in.Previous.Installed() && !in.Previous.Local()
}

// retirePublicStep undoes what public mode published when an install
// switches to local mode: Caddy is stopped and disabled, the Caddyfile this
// tool wrote is moved to a backup, and the TCP 80/443 rules carrying this
// tool's comments are removed unless something else still listens there.
// Anything this tool cannot prove it added is left alone and named.
func (in *Install) retirePublicStep() plan.Step {
	return plan.Step{
		ID: "retire-public", Title: "Take Grafana off the internet (switch to local mode)", Weight: 2,
		Changes: []string{
			"Stop and disable caddy; move " + Caddyfile + " (written by monitor install for " + orUnknown(in.Previous.Domain) + ") to a .bak.* copy next to it",
			"Remove the TCP 80 and 443 firewall rules monitor install added (ufw or nftables rules with its comments), unless another service still listens there",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			data, err := h.ReadFile(Caddyfile)
			if err == nil && !bytes.HasPrefix(data, []byte("# "+header)) {
				r.Note(plan.Warn, Caddyfile+" was not written by monitor install: caddy and its configuration are left alone (systemctl disable --now caddy, if it served only Grafana)")
			} else {
				// A missing or already stopped unit is fine.
				_, _ = h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"disable", "--now", "caddy"}, Mutates: true})
				if err == nil {
					bak := Caddyfile + ".bak." + e.Now().UTC().Format("20060102T150405Z")
					if _, err := h.CopyFile(Caddyfile, bak, host.FileOptions{Mode: 0o644}); err != nil {
						return err
					}
					if err := h.Remove(Caddyfile); err != nil {
						return err
					}
					r.Note(plan.Success, "Caddy is stopped and disabled; its configuration is kept as "+bak)
				}
			}
			return in.closePublicPorts(ctx, h, r)
		},
	}
}

// closePublicPorts removes the public mode's firewall rules that this tool
// can recognise by their comments.
func (in *Install) closePublicPorts(ctx context.Context, h host.Host, r plan.Reporter) error {
	manual := "close TCP 80 and 443 yourself if nothing else needs them"
	switch in.Facts.Firewall.Kind {
	case system.KindUFW:
		res, err := h.Run(ctx, host.Command{Name: "ufw", Args: []string{"status"}})
		if err != nil {
			r.Note(plan.Warn, "Could not read the ufw rules: "+manual+" (ufw status numbered; ufw delete N)")
			return nil
		}
		for _, p := range publicPorts() {
			if !strings.Contains(res.Output, "# "+p.Label) || keepPort(h, p.Number, r) {
				continue
			}
			if _, err := h.Run(ctx, host.Command{Name: "ufw", Args: []string{"delete", "allow", strconv.Itoa(p.Number) + "/tcp"}, Mutates: true}); err != nil {
				return err
			}
		}
	case system.KindNFTables:
		res, err := h.Run(ctx, host.Command{Name: "nft", Args: []string{"-a", "list", "chain", "inet", "filter", "input"}})
		if err != nil {
			r.Note(plan.Info, "No nftables input chain to clean up")
			return nil
		}
		for _, p := range publicPorts() {
			handles := nftHandles(res.Output, p.Label+" "+strconv.Itoa(p.Number))
			if len(handles) == 0 || keepPort(h, p.Number, r) {
				continue
			}
			for _, hd := range handles {
				if _, err := h.Run(ctx, host.Command{Name: "nft", Args: []string{"delete", "rule", "inet", "filter", "input", "handle", hd}, Mutates: true}); err != nil {
					return err
				}
			}
		}
	case system.KindFirewalld:
		r.Note(plan.Warn, "firewalld rules do not say who added them: "+manual+" (firewall-cmd --permanent --remove-port=80/tcp --remove-port=443/tcp && firewall-cmd --reload)")
	default:
		r.Note(plan.Info, "No firewall rules to remove; "+manual+" in your provider's firewall too")
	}
	return nil
}

// keepPort reports (and notes) that another service still listens on port
// once Caddy is stopped, so its firewall rule stays. A dry run cannot know
// (Caddy was not stopped), and an unreadable socket table keeps the rule.
func keepPort(h host.Host, port int, r plan.Reporter) bool {
	if h.DryRun() {
		return false
	}
	v4, v6, err := system.Listening(h, port)
	if err == nil && !v4 && !v6 {
		return false
	}
	r.Note(plan.Warn, fmt.Sprintf("TCP %d stays open in the firewall: something else listens on it (or the socket table is unreadable)", port))
	return true
}

var nftHandleRE = regexp.MustCompile(`# handle (\d+)\s*$`)

// nftHandles returns the handles of the rules in `nft -a list chain`
// output whose comment is exactly comment.
func nftHandles(listing, comment string) []string {
	var out []string
	for l := range strings.Lines(listing) {
		if !strings.Contains(l, `comment "`+comment+`"`) {
			continue
		}
		if m := nftHandleRE.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}
