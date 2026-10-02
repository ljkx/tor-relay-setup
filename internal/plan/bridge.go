package plan

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
)

// Bridges, following the Tor Project's guides:
//
//   - obfs4 (community.torproject.org/relay/setup/bridge/debian-ubuntu/):
//     Debian's obfs4proxy package, or its successor lyrebird where Debian
//     packages it. A port below 1024 needs `setcap cap_net_bind_service=+ep`
//     on the binary and NoNewPrivileges=no for the tor unit, because tor
//     starts the transport after dropping root and NoNewPrivileges=yes makes
//     the kernel ignore file capabilities. Debian's AppArmor profile for tor
//     grants no net_bind_service, so the default instance also gets that
//     capability in /etc/apparmor.d/local/system_tor.
//   - WebTunnel (community.torproject.org/relay/setup/webtunnel/ and
//     .../webtunnel/source/): the Tor Project's webtunnel package
//     (/usr/bin/webtunnel-server), nginx proxying a secret path to the
//     webtunnel server on 127.0.0.1, a TLS certificate for the domain, and
//     an AppArmor rule letting tor execute the transport (the packaged
//     profile only lists obfs4proxy, lyrebird and snowflake).
const (
	// AppArmorLocal holds site additions to tor's AppArmor profile; tor's
	// postinst creates it and system_tor includes it.
	AppArmorLocal   = "/etc/apparmor.d/local/system_tor"
	appArmorProfile = "/etc/apparmor.d/system_tor"
	appArmorBegin   = "# BEGIN tor-relay-setup (managed; edit outside these lines)"
	appArmorEnd     = "# END tor-relay-setup"

	bridgeDropIn = "60-tor-relay-setup-bridge.conf"

	// letsEncryptLive is where certbot keeps the current certificate.
	letsEncryptLive = "/etc/letsencrypt/live/"
)

// bridgePackages lists the packages a bridge adds to the apt transaction.
// "obfs4proxy" is swapped for lyrebird at apply time where apt has it.
func bridgePackages(s config.Setup) []string {
	switch {
	case s.IsWebTunnel():
		pkgs := []string{"webtunnel"}
		if s.ManagedNginx() {
			pkgs = append(pkgs, "nginx")
		}
		if s.UsesCertbot() {
			pkgs = append(pkgs, "certbot", "python3-certbot-nginx")
		}
		return pkgs
	case s.IsBridge():
		pkgs := []string{"obfs4proxy"}
		if lowObfs4Port(s) {
			pkgs = append(pkgs, "libcap2-bin") // setcap, getcap
		}
		return pkgs
	}
	return nil
}

func lowObfs4Port(s config.Setup) bool {
	return s.IsBridge() && !s.IsWebTunnel() && s.Bridge.Obfs4Port > 0 && s.Bridge.Obfs4Port < 1024
}

// bridgeStepNeeded reports whether the bridge needs system changes beyond
// packages and torrc.
func bridgeStepNeeded(s config.Setup) bool {
	return lowObfs4Port(s) || (s.IsWebTunnel() && s.Instance().IsDefault())
}

// appArmorRules returns the lines the bridge needs in AppArmorLocal. Named
// instances run without an AppArmor profile (tor@.service sets none).
func appArmorRules(s config.Setup) []string {
	if !s.Instance().IsDefault() {
		return nil
	}
	switch {
	case s.IsWebTunnel():
		return []string{s.Plugin() + " ix,"}
	case lowObfs4Port(s):
		return []string{"capability net_bind_service,"}
	}
	return nil
}

// ApplyAppArmorBlock puts rules into the managed block of an AppArmor local
// include, keeping everything outside the block; no rules removes it.
func ApplyAppArmorBlock(old []byte, rules []string) []byte {
	var kept []string
	in := false
	for line := range strings.Lines(string(old)) {
		t := strings.TrimRight(line, "\n")
		switch {
		case t == appArmorBegin:
			in = true
		case t == appArmorEnd:
			in = false
		case !in:
			kept = append(kept, t)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	if len(rules) > 0 {
		if len(kept) > 0 {
			kept = append(kept, "")
		}
		kept = append(kept, appArmorBegin)
		kept = append(kept, rules...)
		kept = append(kept, appArmorEnd)
	}
	if len(kept) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(kept, "\n") + "\n")
}

func bridgeStep(s config.Setup) Step {
	inst := s.Instance()
	unit, dropInDir := noFileUnit(inst)
	var changes []string
	if lowObfs4Port(s) {
		changes = append(changes,
			fmt.Sprintf("Let the obfs4 transport bind port %d: setcap cap_net_bind_service=+ep on its binary, and NoNewPrivileges=no for %s in %s/%s (Tor's bridge guide)",
				s.Bridge.Obfs4Port, unit, dropInDir, bridgeDropIn))
	}
	if rules := appArmorRules(s); len(rules) > 0 {
		changes = append(changes, fmt.Sprintf("Add %q to %s and reload tor's AppArmor profile", strings.Join(rules, " "), AppArmorLocal))
	}
	return Step{
		ID:      "bridge",
		Title:   "Prepare the " + s.Bridge.Transport + " transport",
		Changes: changes,
		Weight:  1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			h := e.Host
			if lowObfs4Port(e.Setup) {
				plugin := e.Setup.Plugin()
				if _, err := h.Run(ctx, host.Command{Name: "setcap", Args: []string{"cap_net_bind_service=+ep", plugin}, Mutates: true}); err != nil {
					return fmt.Errorf("setcap on %s: %w", plugin, err)
				}
				if err := writeDropIn(ctx, h, dropInDir, bridgeDropIn, noNewPrivilegesDropIn); err != nil {
					return err
				}
				r.Note(Info, fmt.Sprintf("%s may bind port %d; a package upgrade can drop the capability (the console warns)", plugin, e.Setup.Bridge.Obfs4Port))
			} else if err := removeDropIn(ctx, h, dropInDir, bridgeDropIn); err != nil {
				return err
			}
			return applyAppArmor(ctx, h, r, appArmorRules(e.Setup))
		},
	}
}

const noNewPrivilegesDropIn = `# Managed by tor-relay-setup: the obfs4 transport binds a port below 1024 with
# a file capability (setcap), which NoNewPrivileges=yes would make the kernel
# ignore. See https://community.torproject.org/relay/setup/bridge/debian-ubuntu/
[Service]
NoNewPrivileges=no
`

// writeDropIn writes a systemd drop-in and reloads systemd when it changed.
func writeDropIn(ctx context.Context, h host.Host, dir, name, content string) error {
	if err := h.MkdirAll(dir, 0o755, ""); err != nil {
		return err
	}
	ch, err := h.WriteFile(dir+"/"+name, []byte(content), host.FileOptions{Mode: 0o644, Backup: true})
	if err != nil || ch.Unchanged {
		return err
	}
	_, err = h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"daemon-reload"}, Mutates: true})
	return err
}

// removeDropIn removes a drop-in this tool wrote earlier, if any.
func removeDropIn(ctx context.Context, h host.Host, dir, name string) error {
	p := dir + "/" + name
	if _, err := h.Stat(p); err != nil {
		return nil
	}
	if err := h.Remove(p); err != nil {
		return err
	}
	_, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"daemon-reload"}, Mutates: true})
	return err
}

// applyAppArmor updates the managed block in AppArmorLocal and reloads the
// profile. Hosts without tor's AppArmor profile are left alone.
func applyAppArmor(ctx context.Context, h host.Host, r Reporter, rules []string) error {
	old, err := h.ReadFile(AppArmorLocal)
	if err != nil && len(rules) == 0 {
		return nil
	}
	if _, err := h.Stat(appArmorProfile); err != nil {
		if len(rules) > 0 {
			r.Note(Info, "No AppArmor profile for tor ("+appArmorProfile+"); nothing to allow")
		}
		return nil
	}
	ch, err := h.WriteFile(AppArmorLocal, ApplyAppArmorBlock(old, rules), host.FileOptions{Mode: 0o644, Backup: true})
	if err != nil || ch.Unchanged {
		return err
	}
	if _, err := h.LookPath("apparmor_parser"); err != nil {
		r.Note(Warn, "apparmor_parser is missing: reload the profile yourself with apparmor_parser -r "+appArmorProfile)
		return nil
	}
	if _, err := h.Run(ctx, host.Command{Name: "apparmor_parser", Args: []string{"-r", appArmorProfile}, Mutates: true}); err != nil {
		return fmt.Errorf("reload tor's AppArmor profile: %w", err)
	}
	if len(rules) > 0 {
		r.Note(Success, "AppArmor allows "+strings.Join(rules, " "))
	}
	return nil
}

// pathAlphabet is the alphabet of the guide's secret path generator.
const pathAlphabet = "qwertyuiopasdfghjklzxcvbnmMNBVCXZLKJHGFDSAQWERTUIOP0987654321"

// NewWebTunnelPath returns a random 24-character secret path, like the
// guide's `tr -cd ... </dev/urandom | head -c 24`.
func NewWebTunnelPath() string {
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pathAlphabet))))
		if err != nil {
			panic(err) // crypto/rand does not fail on Linux
		}
		b[i] = pathAlphabet[n.Int64()]
	}
	return string(b)
}

// resolveWebTunnelPath fills in an empty WebTunnel path: the one the
// instance's torrc already uses for the same domain (so the bridge line
// stays the same), otherwise a new random one. It reports whether the path
// was generated.
func resolveWebTunnelPath(h host.Host, s *config.Setup) (generated bool) {
	if !s.IsWebTunnel() || s.Bridge.Path != "" {
		return false
	}
	if data, err := h.ReadFile(s.Instance().TorrcPath); err == nil {
		if b, ok := relay.ParseDocument(data).BridgeSettings(); ok {
			if d, p, ok := relay.SplitWebTunnelURL(b.URL); ok && d == s.Bridge.Domain {
				s.Bridge.Path = p
				return false
			}
		}
	}
	s.Bridge.Path = NewWebTunnelPath()
	return true
}

// CertPaths returns the certificate chain and key nginx uses.
func CertPaths(s config.Setup) (cert, key string) {
	if s.Bridge.Certificate == config.CertCertbot {
		return letsEncryptLive + s.Bridge.Domain + "/fullchain.pem", letsEncryptLive + s.Bridge.Domain + "/privkey.pem"
	}
	return s.Bridge.CertFile, s.Bridge.KeyFile
}

// NginxLocation is the location block that hands the secret path to the
// webtunnel server, exactly as the Tor Project's WebTunnel guide writes it.
func NginxLocation(path string, port int) string {
	return fmt.Sprintf(`    location = /%s {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;

        ### Set WebSocket headers ###
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        ### Set Proxy headers ###
        proxy_set_header Accept-Encoding "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Front-End-Https on;

        proxy_redirect off;
        access_log off;
        error_log /dev/null;
    }
`, path, port)
}

// NginxSite renders the managed nginx site of a WebTunnel bridge. Without
// tls (before certbot has a certificate) it only answers HTTP for the ACME
// challenge.
func NginxSite(s config.Setup, tls bool) []byte {
	d := s.Bridge.Domain
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by tor-relay-setup: WebTunnel bridge front for tor instance %s.\n", s.Instance().Name)
	b.WriteString("# The secret path goes to the webtunnel server; everything else is an ordinary\n")
	b.WriteString("# website (put real content in /var/www/html). Follows the Tor Project's guide:\n")
	b.WriteString("# https://community.torproject.org/relay/setup/webtunnel/\n")
	b.WriteString("server {\n    listen 80;\n    listen [::]:80;\n")
	fmt.Fprintf(&b, "    server_name %s;\n", d)
	if tls {
		b.WriteString("    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n\n")
		cert, key := CertPaths(s)
		b.WriteString("server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n")
		fmt.Fprintf(&b, "    server_name %s;\n\n", d)
		fmt.Fprintf(&b, "    ssl_certificate %s;\n    ssl_certificate_key %s;\n", cert, key)
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_tickets off;\n\n")
		b.WriteString("    root /var/www/html;\n    index index.html index.htm index.nginx-debian.html;\n\n")
		b.WriteString(NginxLocation(s.Bridge.Path, s.WebTunnelPort()))
	} else {
		b.WriteString("    root /var/www/html;\n")
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func webTunnelStep(s config.Setup) Step {
	inst := s.Instance()
	cert, key := CertPaths(s)
	changes := []string{fmt.Sprintf("Write and enable nginx site %s: HTTPS for %s, the secret path proxied to the webtunnel server on 127.0.0.1:%d (nginx -t before every reload; the previous site is restored if it fails)",
		inst.WebTunnelSite(), s.Bridge.Domain, s.WebTunnelPort())}
	if s.UsesCertbot() {
		mail := "without an email address"
		if s.Bridge.CertbotEmail != "" {
			mail = "with email " + s.Bridge.CertbotEmail
		}
		changes = append(changes, fmt.Sprintf("Request a Let's Encrypt certificate for %s with certbot certonly --nginx, %s, accepting the Let's Encrypt Subscriber Agreement as you confirmed (skipped while %s exists; renewals reload nginx)",
			s.Bridge.Domain, mail, cert))
	} else {
		changes = append(changes, "Use the certificate "+cert+" and key "+key)
	}
	return Step{
		ID:      "webtunnel",
		Title:   "Configure nginx for WebTunnel",
		Changes: changes,
		Weight:  4,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			h := e.Host
			s := e.Setup
			cert, key := CertPaths(s)
			if s.UsesCertbot() {
				if _, err := h.Stat(cert); err != nil {
					r.Progress(20, "certbot certonly --nginx -d "+s.Bridge.Domain)
					if err := installSite(ctx, h, r, s, false); err != nil {
						return err
					}
					args := []string{"certonly", "--nginx", "-d", s.Bridge.Domain, "--non-interactive", "--agree-tos", "--deploy-hook", "systemctl reload nginx"}
					if s.Bridge.CertbotEmail != "" {
						args = append(args, "-m", s.Bridge.CertbotEmail)
					} else {
						args = append(args, "--register-unsafely-without-email")
					}
					if _, err := h.Run(ctx, host.Command{Name: "certbot", Args: args, Mutates: true}); err != nil {
						return fmt.Errorf("certbot could not get a certificate for %s (does the domain point at this server, and is port 80 reachable?): %w", s.Bridge.Domain, err)
					}
					if !h.DryRun() {
						r.Note(Success, "Let's Encrypt certificate for "+s.Bridge.Domain)
					}
				}
			} else if !h.DryRun() {
				for _, p := range []string{cert, key} {
					if _, err := h.Stat(p); err != nil {
						return fmt.Errorf("%s is missing; put the certificate there first: %w", p, err)
					}
				}
			}
			r.Progress(70, "nginx -t")
			if err := installSite(ctx, h, r, s, true); err != nil {
				return err
			}
			if !h.DryRun() {
				r.Note(Success, "nginx serves https://"+s.Bridge.Domain+"/ with the bridge behind its secret path")
			}
			return nil
		},
	}
}

// installSite writes the nginx site, enables it, tests the whole nginx
// configuration and reloads nginx; a failing test restores what was there.
func installSite(ctx context.Context, h host.Host, r Reporter, s config.Setup, tls bool) error {
	inst := s.Instance()
	site, link := inst.WebTunnelSite(), inst.WebTunnelSiteLink()
	old, oldErr := h.ReadFile(site)
	ch, err := h.WriteFile(site, NginxSite(s, tls), host.FileOptions{Mode: 0o644, Backup: true})
	if err != nil {
		return err
	}
	if _, err := h.Readlink(link); err != nil {
		if err := h.Symlink(site, link); err != nil {
			return err
		}
	}
	if _, err := h.Run(ctx, host.Command{Name: "nginx", Args: []string{"-t"}, Mutates: true}); err != nil {
		if oldErr == nil {
			_, _ = h.WriteFile(site, old, host.FileOptions{Mode: 0o644})
		} else {
			_ = h.Remove(link)
			_ = h.Remove(site)
		}
		return fmt.Errorf("nginx rejected the WebTunnel site, so it was taken back: %w", err)
	}
	if ch.BackupOf != "" {
		r.Note(Info, "Previous site saved as "+ch.BackupOf)
	}
	nginx := service.Tor{Host: h, Unit: "nginx"}
	if err := nginx.Enable(ctx); err != nil {
		return err
	}
	if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"reload-or-restart", "nginx"}, Mutates: true}); err != nil {
		return fmt.Errorf("reload nginx: %w", err)
	}
	return nil
}

// ReadWebServer fills in how a WebTunnel bridge read back from torrc is
// served: nginx when this tool's site exists (with the certificate it
// names), else manual.
func ReadWebServer(h host.Host, s *config.Setup) {
	if !s.IsWebTunnel() {
		return
	}
	data, err := h.ReadFile(s.Instance().WebTunnelSite())
	if err != nil {
		s.Bridge.WebServer = config.WebServerManual
		return
	}
	s.Bridge.WebServer = config.WebServerNginx
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "ssl_certificate":
			s.Bridge.CertFile = f[1]
		case "ssl_certificate_key":
			s.Bridge.KeyFile = f[1]
		}
	}
	// A certificate certbot manages keeps renewing on its own; reconfiguring
	// treats it as an existing certificate so certbot is not asked again.
	s.Bridge.Certificate = config.CertExisting
}

func exitNoticeStep(s config.Setup) Step {
	page := s.Instance().ExitNoticePath()
	return Step{
		ID:      "exit-notice",
		Title:   "Write the exit notice page",
		Changes: []string{fmt.Sprintf("Create the exit notice %s (kept as it is if it exists; tor serves it on port %d)", page, relay.ExitNoticePort)},
		Weight:  1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			page := e.instance().ExitNoticePath()
			if _, err := e.Host.Stat(page); err == nil {
				r.Note(Info, "Keeping the existing exit notice "+page)
				return nil
			}
			if _, err := e.Host.WriteFile(page, relay.RenderExitNotice(e.Setup.Relay.Nickname, e.Setup.Relay.Contact), host.FileOptions{Mode: 0o644}); err != nil {
				return err
			}
			r.Note(Success, "Exit notice "+page+": edit it to add details about your organisation")
			return nil
		},
	}
}

// errNoPath guards against rendering a WebTunnel torrc before preflight
// resolved the secret path.
var errNoPath = errors.New("the WebTunnel path was not resolved")
