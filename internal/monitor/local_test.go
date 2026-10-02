package monitor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

const (
	nonExitTorrc = "Nickname relay1\nORPort 9001\nAddress 198.51.100.7\nExitRelay 0\nExitPolicy reject *:*\n"
	// procNetTCP lists listeners as /proc/net/tcp does: 9001 (0x2329) and,
	// with listen443, 443 (0x01BB).
	procNetTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	listen9001       = "   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 1 1 0000000000000000 100 0 0 10 0\n"
	listen443        = "   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0\n"
)

func jammyNoFirewall() system.Facts {
	f := noble()
	f.Codename, f.VersionID, f.PrettyName = "jammy", "22.04", "Ubuntu 22.04"
	f.EUID = 0
	return f
}

func hasNote(rec *recorder, subs ...string) bool {
	return slices.ContainsFunc(rec.notes, func(n string) bool {
		for _, s := range subs {
			if !strings.Contains(n, s) {
				return false
			}
		}
		return true
	})
}

func TestNormalizeLocal(t *testing.T) {
	o := Options{Local: true}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	if o.URL() != "http://localhost:3000/" || o.Mode() != ModeLocal || o.Inventory != DefaultInventory {
		t.Errorf("local options: %+v %s", o, o.URL())
	}
	for _, tt := range []struct {
		o    Options
		want string
	}{
		{Options{Local: true, Domain: "g.example.org"}, "--domain is not used with --local"},
		{Options{Local: true, Email: "ops@example.org"}, "--email is not used with --local"},
		{Options{Local: true, FleetPath: "/fleet"}, "--fleet-path is not used with --local"},
		{Options{Local: true, AdminUser: "admin"}, "--admin-user"},
	} {
		if err := tt.o.Normalize(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%+v: %v, want %q", tt.o, err, tt.want)
		}
	}
}

func TestLocalMode(t *testing.T) {
	local, public, none := State{Mode: ModeLocal}, State{Mode: ModePublic, Domain: "g.example.org"}, State{}
	for _, tt := range []struct {
		prev              State
		localFlag, domain bool
		want              bool
	}{
		{none, false, true, false},
		{none, true, false, true},
		{local, false, false, true}, // re-run without flags keeps local
		{local, false, true, false}, // --domain switches to public
		{public, false, false, false},
		{public, true, false, true}, // --local switches to local
		{State{Domain: "g.example.org"}, false, false, false},
	} {
		if got := LocalMode(tt.prev, tt.localFlag, tt.domain); got != tt.want {
			t.Errorf("LocalMode(%+v, %v, %v) = %v", tt.prev, tt.localFlag, tt.domain, got)
		}
	}
	if !local.Installed() || !public.Installed() || none.Installed() || !(State{Domain: "x"}).Installed() {
		t.Error("State.Installed")
	}
}

func TestGrafanaINILocal(t *testing.T) {
	o := Options{Local: true}
	_ = o.Normalize()
	ini := string(GrafanaINIFile(o, "s3cret"))
	for _, want := range []string{
		"http_addr = 127.0.0.1\n", "http_port = 3000\n", "domain = localhost\n", "enforce_domain = false\n",
		"root_url = http://localhost:3000/\n", "cookie_secure = false\n", "cookie_samesite = strict\n",
		"strict_transport_security = false\n", "allow_embedding = false\n", "x_content_type_options = true\n",
		"content_security_policy = true\n", "allow_sign_up = false\n", "allow_org_create = false\n",
		"[auth.anonymous]\nenabled = false\n", "[auth.basic]\n; No HTTP basic authentication on the API: log in through the form.\nenabled = false\n",
		"[snapshots]\nenabled = false\nexternal_enabled = false\n", "[public_dashboards]\nenabled = false\n",
		"plugin_admin_enabled = false\n", "reporting_enabled = false\n", "disable_gravatar = true\n",
		"data_source_proxy_whitelist = 127.0.0.1:9090\n", "admin_user = tor-admin\n", "secret_key = s3cret\n",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("local grafana.ini lacks %q", want)
		}
	}
	for _, bad := range []string{"cookie_secure = true", "enforce_domain = true", "strict_transport_security = true", "https://", "Caddy talks"} {
		if strings.Contains(ini, bad) {
			t.Errorf("local grafana.ini has %q", bad)
		}
	}
	// Only the server block and the transport settings differ from public mode.
	pub := Options{Domain: "grafana.example.org"}
	_ = pub.Normalize()
	pubINI := string(GrafanaINIFile(pub, "s3cret"))
	if i, j := strings.Index(ini, "[analytics]"), strings.Index(pubINI, "[analytics]"); i < 0 || j < 0 || stripTransport(ini[i:]) != stripTransport(pubINI[j:]) {
		t.Error("local and public grafana.ini differ beyond [server] and the cookie/HSTS settings")
	}
}

// stripTransport drops the lines local mode changes in [security].
func stripTransport(ini string) string {
	var out []string
	for l := range strings.Lines(ini) {
		if !strings.HasPrefix(l, "cookie_secure") && !strings.HasPrefix(l, "strict_transport_security =") && !strings.HasPrefix(l, ";") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "")
}

func TestServeConfigLocal(t *testing.T) {
	o := Options{Local: true}
	_ = o.Normalize()
	got := string(ServeConfig(nil, o, "aaa"))
	for _, want := range []string{`listen = "127.0.0.1:9850"`, `base_path = ""`, `trusted_proxies = []`, `metrics_auth = true`, `metrics_token_sha256 = "aaa"`} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("local serve.toml lacks %s:\n%s", want, got)
		}
	}
	// A public serve.toml becomes local: the proxy is no longer trusted.
	pub := Options{Domain: "g.example.org", FleetPath: "/fleet"}
	_ = pub.Normalize()
	got = string(ServeConfig(ServeConfig(nil, pub, "aaa"), o, "aaa"))
	if strings.Contains(got, "127.0.0.1\", \"::1\"") || strings.Contains(got, "/fleet/") || strings.Count(got, "trusted_proxies =") != 1 {
		t.Errorf("public to local serve.toml:\n%s", got)
	}
}

func TestLocalInstallPlan(t *testing.T) {
	s := newFakeServer()
	f := jammyNoFirewall()
	s.Files["/etc/tor/torrc"] = []byte(nonExitTorrc)
	s.Files[DefaultInventory] = []byte("[[host]]\naddress = \"relay2.example.org\"\n")
	s.Modes[DefaultInventory] = 0o644
	in, rec := runInstallEnv(t, s, f, Options{Local: true}, map[string]string{"SUDO_USER": "alice"})

	// No Caddy at all: no package, no repository (even on jammy), no
	// Caddyfile, no caddy command; no firewall change and no ufw install.
	if !s.Ran("apt-get", "--no-install-recommends install prometheus grafana openssh-client") {
		t.Errorf("packages: %q", s.CommandLines())
	}
	for _, l := range s.CommandLines() {
		if strings.Contains(l, "caddy") || strings.Contains(l, "ufw") || strings.Contains(l, "firewall-cmd") || strings.Contains(l, "nft ") {
			t.Errorf("local install ran %s", l)
		}
	}
	for _, p := range []string{Caddyfile, CaddyRepo.SourcesPath, CaddyRepo.KeyringPath} {
		if _, ok := s.Files[p]; ok {
			t.Errorf("local install wrote %s", p)
		}
	}
	if _, ok := s.Files[GrafanaRepo.SourcesPath]; !ok {
		t.Error("Grafana repository missing")
	}
	ini := string(s.Files[GrafanaINI])
	for _, want := range []string{"root_url = http://localhost:3000/\n", "domain = localhost\n", "enforce_domain = false\n", "cookie_secure = false\n", "strict_transport_security = false\n", "cookie_samesite = strict\n", "[auth.anonymous]\nenabled = false\n"} {
		if !strings.Contains(ini, want) {
			t.Errorf("grafana.ini lacks %q", want)
		}
	}
	serve := string(s.Files[ServeConfigPath])
	for _, want := range []string{`listen = "127.0.0.1:9850"`, `base_path = ""`, `trusted_proxies = []`} {
		if !strings.Contains(serve, want+"\n") {
			t.Errorf("serve.toml lacks %s:\n%s", want, serve)
		}
	}
	if !s.Ran("systemctl restart grafana-server") || !s.Ran("systemctl restart prometheus") || !s.Ran("systemctl restart tor-relay-setup-fleet") {
		t.Errorf("services: %q", s.CommandLines())
	}
	if !hasNote(rec, "non-exit Tor relay", "default", "Grafana and Prometheus will share this relay", "127.0.0.1 only") {
		t.Errorf("no note about sharing the relay: %q", rec.notes)
	}
	if hasNote(rec, "resolves") || hasNote(rec, "A separate management server is recommended") {
		t.Errorf("public-mode notes in local mode: %q", rec.notes)
	}
	st, err := ReadState(s)
	if err != nil || st.Mode != ModeLocal || st.Domain != "" || !st.Local() || slices.Contains(st.Repos, CaddyRepo.SourcesPath) {
		t.Errorf("state %+v %v", st, err)
	}
	sum := strings.Join(in.SummaryLines(), "\n")
	for _, want := range []string{
		"Grafana        http://localhost:3000 via an SSH tunnel",
		"SSH tunnel     ssh -N -L 3000:127.0.0.1:3000 alice@198.51.100.7",
		"Termius        Port forwarding: local 3000 → 127.0.0.1:3000 through host 198.51.100.7",
		"-L 9850:127.0.0.1:9850", "fleet authorize --key 'ssh-ed25519",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "https://") || strings.Contains(sum, "Replace USER") {
		t.Errorf("summary:\n%s", sum)
	}

	// Re-running without flags keeps local mode (the CLI resolves it with
	// LocalMode) and changes nothing.
	if !LocalMode(st, false, false) {
		t.Fatal("state does not keep local mode")
	}
	before := len(s.Commands)
	runInstallEnv(t, s, f, Options{Local: LocalMode(st, false, false)}, nil)
	for _, l := range s.CommandLines()[before:] {
		if strings.Contains(l, "restart") || strings.Contains(l, "caddy") || strings.Contains(l, "reset-admin-password") {
			t.Errorf("second local run ran %s", l)
		}
	}
	if st2, _ := ReadState(s); st2.Mode != ModeLocal {
		t.Errorf("second run state %+v", st2)
	}

	// --domain switches to public mode: Caddy and TCP 80/443 come (back).
	runInstall(t, s, f, Options{Domain: "grafana.example.org"})
	if _, ok := s.Files[Caddyfile]; !ok || !s.Ran("ufw allow 443/tcp") || !strings.Contains(string(s.Files[GrafanaINI]), "cookie_secure = true\n") {
		t.Errorf("switch to public: %q", s.CommandLines())
	}
	if st3, _ := ReadState(s); st3.Mode != ModePublic || st3.Domain != "grafana.example.org" {
		t.Errorf("public state %+v", st3)
	}
}

func runInstallEnv(t *testing.T, s *fakeServer, f system.Facts, o Options, env map[string]string) (*Install, *recorder) {
	t.Helper()
	in, rec, err := tryInstall(t, s, f, o, env)
	if err != nil {
		t.Fatalf("install: %v\nnotes: %q", err, rec.notes)
	}
	return in, rec
}

func TestLocalInstallRefusesExitRelay(t *testing.T) {
	for name, files := range map[string]map[string][]byte{
		"ExitRelay 1":  {"/etc/tor/torrc": []byte("ORPort 443\nExitRelay 1\nExitPolicy accept *:80, accept *:443, reject *:*\n")},
		"policy only":  {"/etc/tor/torrc": []byte("ORPort 443\nExitPolicy accept *:*\n")},
		"named exit":   {"/etc/tor/torrc": []byte(nonExitTorrc), "/etc/tor/instances/exit2/torrc": []byte("ORPort 9002\nReducedExitPolicy 1\nExitRelay 1\n")},
		"reduced only": {"/etc/tor/instances/two/torrc": []byte("ORPort 9002\nReducedExitPolicy 1\n")},
	} {
		s := newFakeServer()
		for p, data := range files {
			s.Files[p] = data
		}
		_, rec, err := tryInstall(t, s, jammyNoFirewall(), Options{Local: true}, nil)
		if err == nil || !strings.Contains(err.Error(), "exit relay") || !strings.Contains(err.Error(), "abuse") || !strings.Contains(err.Error(), "denial-of-service") {
			t.Errorf("%s: err = %v (notes %q)", name, err, rec.notes)
		}
		if s.Ran("apt-get") || len(s.Files) != len(files) {
			t.Errorf("%s: changed something before refusing: %q", name, s.CommandLines())
		}
	}
	// Public mode on a relay only warns, as before.
	s := newFakeServer()
	s.Files["/etc/tor/torrc"] = []byte("ORPort 443\nExitRelay 1\n")
	_, rec := runInstall(t, s, noble(), Options{})
	if !hasNote(rec, "also runs a Tor relay") {
		t.Errorf("public mode: %q", rec.notes)
	}
}

func TestLocalInstallMemoryWarning(t *testing.T) {
	s := newFakeServer()
	s.Files["/etc/tor/torrc"] = []byte(nonExitTorrc)
	f := jammyNoFirewall()
	f.MemTotalMiB = 1200
	_, rec := runInstallEnv(t, s, f, Options{Local: true}, nil)
	if !hasNote(rec, "1200 MiB RAM", "1 relay(s) plus Grafana and Prometheus") {
		t.Errorf("notes %q", rec.notes)
	}
}

func TestLocalInstallDryRun(t *testing.T) {
	s := newFakeServer()
	s.Dry = true
	f := noble()
	f.EUID = 1000
	in, _ := runInstallEnv(t, s, f, Options{Local: true}, nil)
	if len(s.Files) != 0 {
		t.Errorf("dry run wrote %d files", len(s.Files))
	}
	changes := plan.Changes(in.Steps())
	all := strings.Join(changes, "\n")
	for _, want := range []string{
		"recommended packages: prometheus grafana openssh-client (", "no Caddy in local mode", "No firewall change: in local mode",
		"root_url http://localhost:3000/", "listen 127.0.0.1:9850",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("planned changes lack %q:\n%s", want, all)
		}
	}
	for _, bad := range []string{"Caddyfile", "443", "ufw", "Caddy's repository"} {
		if strings.Contains(all, bad) {
			t.Errorf("planned changes mention %q:\n%s", bad, all)
		}
	}
	if !s.Ran("useradd") || !s.Ran("systemctl restart grafana-server") || s.Ran("caddy") || s.Ran("ufw") {
		t.Errorf("dry run commands: %q", s.CommandLines())
	}
	// Without a known login or address, the summary has placeholders.
	sum := strings.Join(in.SummaryLines(), "\n")
	if !strings.Contains(sum, "ssh -N -L 3000:127.0.0.1:3000 -p 2222 USER@SERVER") && !strings.Contains(sum, "ssh -N -L 3000:127.0.0.1:3000 USER@SERVER") {
		t.Errorf("summary:\n%s", sum)
	}
	if !strings.Contains(sum, "Replace USER with your SSH login and SERVER") {
		t.Errorf("no placeholder hint:\n%s", sum)
	}
}

// publicThenLocal installs public mode with an active ufw whose status
// shows this tool's 80/443 rules, then switches to local mode.
func publicThenLocal(t *testing.T, procTCP string) (*fakeServer, *recorder) {
	t.Helper()
	s := newFakeServer()
	f := noble()
	f.EUID = 0
	f.Firewall = system.Firewall{Kind: system.KindUFW, Active: true, Detail: system.DetailActive}
	runInstall(t, s, f, Options{})
	if !strings.HasPrefix(string(s.Files[Caddyfile]), "# "+header) {
		t.Fatal("public install wrote no Caddyfile")
	}
	next := s.Handler
	s.Handler = func(c host.Command) (host.Result, error) {
		if c.String() == "ufw status" {
			return host.Result{Output: "Status: active\n\nTo                         Action      From\n--                         ------      ----\n" +
				"22/tcp                     ALLOW       Anywhere                   # SSH\n" +
				"9001/tcp                   ALLOW       Anywhere                   # Tor relay ORPort\n" +
				"80/tcp                     ALLOW       Anywhere                   # " + httpRuleLabel + "\n" +
				"443/tcp                    ALLOW       Anywhere                   # " + httpsRuleLabel + "\n" +
				"80/tcp (v6)                ALLOW       Anywhere (v6)              # " + httpRuleLabel + "\n"}, nil
		}
		return next(c)
	}
	s.Files["/proc/net/tcp"] = []byte(procTCP)
	s.Files["/etc/tor/torrc"] = []byte(nonExitTorrc)
	_, rec := runInstallEnv(t, s, f, Options{Local: true}, nil)
	return s, rec
}

func TestSwitchPublicToLocal(t *testing.T) {
	s, rec := publicThenLocal(t, procNetTCPHeader+listen9001)
	if !s.Ran("systemctl disable --now caddy") || !s.Ran("ufw delete allow 80/tcp") || !s.Ran("ufw delete allow 443/tcp") {
		t.Errorf("switch: %q", s.CommandLines())
	}
	if s.Ran("ufw delete allow 22") || s.Ran("ufw delete allow 9001") {
		t.Error("removed a rule that was not monitor install's")
	}
	if _, ok := s.Files[Caddyfile]; ok {
		t.Error("Caddyfile still in place")
	}
	bak := Caddyfile + ".bak.20261002T120000Z"
	if !strings.Contains(string(s.Files[bak]), "grafana.example.org {") {
		t.Errorf("no Caddyfile backup at %s", bak)
	}
	if !hasNote(rec, "Switching from public mode (https://grafana.example.org/) to local mode") || !hasNote(rec, "kept as "+bak) {
		t.Errorf("notes %q", rec.notes)
	}
	if !strings.Contains(string(s.Files[ServeConfigPath]), "trusted_proxies = []\n") || !strings.Contains(string(s.Files[GrafanaINI]), "cookie_secure = false\n") {
		t.Error("serve.toml or grafana.ini not switched")
	}
	if st, _ := ReadState(s); st.Mode != ModeLocal || st.Domain != "" || st.FleetPath != "" {
		t.Errorf("state %+v", st)
	}
	// Running local again does not try to retire Caddy again.
	n := len(s.Commands)
	runInstallEnv(t, s, noble(), Options{Local: true}, nil)
	for _, l := range s.CommandLines()[n:] {
		if strings.Contains(l, "caddy") || strings.Contains(l, "ufw") {
			t.Errorf("second local run ran %s", l)
		}
	}
}

func TestSwitchToLocalKeepsBusyPort(t *testing.T) {
	s, rec := publicThenLocal(t, procNetTCPHeader+listen9001+listen443)
	if !s.Ran("ufw delete allow 80/tcp") || s.Ran("ufw delete allow 443/tcp") {
		t.Errorf("busy 443: %q", s.CommandLines())
	}
	if !hasNote(rec, "TCP 443 stays open") {
		t.Errorf("notes %q", rec.notes)
	}
}

func TestSwitchToLocalLeavesForeignCaddyfile(t *testing.T) {
	s := newFakeServer()
	f := noble()
	f.Firewall = system.Firewall{Kind: system.KindFirewalld, Active: true, Detail: system.DetailActive}
	s.Files[StatePath] = []byte(`{"mode":"public","domain":"grafana.example.org","admin_user":"tor-admin","inventory":"/etc/tor-relay-setup/fleet.toml"}`)
	s.Files[Caddyfile] = []byte("example.org {\n\troot * /srv\n}\n")
	_, rec := runInstallEnv(t, s, f, Options{Local: true}, nil)
	if s.Ran("caddy") || s.Ran("firewall-cmd") || string(s.Files[Caddyfile]) != "example.org {\n\troot * /srv\n}\n" {
		t.Errorf("touched a foreign Caddyfile or firewalld: %q", s.CommandLines())
	}
	if !hasNote(rec, "was not written by monitor install") || !hasNote(rec, "firewall-cmd --permanent --remove-port=80/tcp") {
		t.Errorf("notes %q", rec.notes)
	}
}

func TestNFTHandles(t *testing.T) {
	listing := `table inet filter {
	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept # handle 4
		tcp dport 9001 accept comment "Tor relay ORPort 9001" # handle 5
		tcp dport 80 accept comment "HTTP (Caddy: ACME and redirect) 80" # handle 7
		tcp dport 443 accept comment "HTTPS (Caddy: Grafana) 443" # handle 8
		tcp dport 443 accept comment "nginx HTTPS port 443" # handle 9
	}
}
`
	if got := nftHandles(listing, httpsRuleLabel+" 443"); !slices.Equal(got, []string{"8"}) {
		t.Errorf("443: %q", got)
	}
	if got := nftHandles(listing, httpRuleLabel+" 80"); !slices.Equal(got, []string{"7"}) {
		t.Errorf("80: %q", got)
	}
	// The nftables cleanup deletes exactly those rules.
	s := newFakeServer()
	s.Handler = func(c host.Command) (host.Result, error) {
		if c.String() == "nft -a list chain inet filter input" {
			return host.Result{Output: listing}, nil
		}
		return host.Result{}, nil
	}
	s.Files["/proc/net/tcp"] = []byte(procNetTCPHeader)
	in := &Install{Facts: system.Facts{Firewall: system.Firewall{Kind: system.KindNFTables, Detail: system.DetailNFTChainFound}}}
	var rec recorder
	if err := in.closePublicPorts(context.Background(), s, reporterFunc(rec.events)); err != nil {
		t.Fatal(err)
	}
	if !s.Ran("nft delete rule inet filter input handle 7") || !s.Ran("nft delete rule inet filter input handle 8") || s.Ran("handle 9") || s.Ran("handle 5") {
		t.Errorf("nft: %q", s.CommandLines())
	}
}

func TestDetectTunnel(t *testing.T) {
	s := newFakeServer()
	f := noble() // SSH ports 22 and 2222
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, tt := range []struct {
		name  string
		env   map[string]string
		torrc string
		f     func(*system.Facts)
		want  string
	}{
		{"ssh connection", map[string]string{"SUDO_USER": "alice", "SSH_CONNECTION": "198.51.100.1 50000 203.0.113.9 2222"}, nonExitTorrc, nil,
			"ssh -N -L 3000:127.0.0.1:3000 -p 2222 alice@203.0.113.9"},
		{"private ssh address, torrc Address", map[string]string{"SUDO_USER": "alice", "SSH_CONNECTION": "10.0.0.2 50000 10.0.0.1 22"}, nonExitTorrc, nil,
			"ssh -N -L 3000:127.0.0.1:3000 alice@198.51.100.7"},
		{"interface IPv4", map[string]string{"SUDO_USER": "root"}, "ORPort 9001\n", func(f *system.Facts) { f.IPv4 = []string{"203.0.113.20"}; f.IPv6 = []string{"2001:db8::20"} },
			"ssh -N -L 3000:127.0.0.1:3000 USER@203.0.113.20"},
		{"interface IPv6, custom SSH port", nil, "", func(f *system.Facts) { f.IPv6 = []string{"2001:db8::20"}; f.SSHPorts = []int{2222} },
			"ssh -N -L 3000:127.0.0.1:3000 -p 2222 USER@2001:db8::20"},
		{"nothing known", map[string]string{"SUDO_USER": "bad user"}, "ORPort 9001\nAddress 10.1.2.3\n", nil,
			"ssh -N -L 3000:127.0.0.1:3000 USER@SERVER"},
	} {
		s.Files["/etc/tor/torrc"] = []byte(tt.torrc)
		ff := f
		if tt.f != nil {
			tt.f(&ff)
		}
		if got := DetectTunnel(s, ff, env(tt.env)).Command(); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestStatusLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health", "/-/ready":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"data":{"activeTargets":[{"labels":{"job":"tor-relay-fleet"},"health":"up"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := newFakeServer()
	for _, u := range []string{FleetUnit, "prometheus", "grafana-server"} {
		s.active[u] = true // caddy is not running, and need not be
	}
	s.Files[StatePath] = []byte(`{"mode":"local","domain":"","admin_user":"tor-admin","inventory":"/etc/tor-relay-setup/fleet.toml"}`)
	f := noble()
	f.IPv4 = []string{"203.0.113.9"}
	o := StatusOptions{PrometheusURL: srv.URL, GrafanaURL: srv.URL, Facts: f, Getenv: func(k string) string {
		return map[string]string{"SUDO_USER": "bob"}[k]
	}}
	st := CollectStatus(context.Background(), s, o)
	if !st.Installed || !st.Healthy() {
		t.Fatalf("local status %+v", st)
	}
	var b bytes.Buffer
	st.Write(&b)
	out := b.String()
	for _, want := range []string{
		"Grafana      http://localhost:3000 via an SSH tunnel", "SSH tunnel   ssh -N -L 3000:127.0.0.1:3000 bob@203.0.113.9",
		"Termius      Port forwarding: local 3000 → 127.0.0.1:3000", "✓ grafana-server", "Inventory    /etc/tor-relay-setup/fleet.toml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "caddy") || strings.Contains(out, "https://") {
		t.Errorf("local status mentions caddy or https:\n%s", out)
	}
	if s.Ran("is-active --quiet caddy") {
		t.Error("caddy checked in local mode")
	}
}

func TestUninstallLocal(t *testing.T) {
	s := newFakeServer()
	st := State{Mode: ModeLocal, NewPackages: []string{"grafana", "prometheus"}}
	steps := UninstallSteps(st, false)
	if c := strings.Join(plan.Changes(steps), "\n"); strings.Contains(c, "caddy") || !strings.Contains(c, "grafana-server") {
		t.Errorf("changes: %s", c)
	}
	if err := plan.Run(context.Background(), steps, &plan.Env{Host: s}, func(plan.Event) {}); err != nil {
		t.Fatal(err)
	}
	if s.Ran("caddy") || !s.Ran("systemctl disable --now grafana-server") || !s.Ran("systemctl disable --now tor-relay-setup-fleet") {
		t.Errorf("local uninstall: %q", s.CommandLines())
	}
	s.users[MonitorUser] = true
	if err := plan.Run(context.Background(), UninstallSteps(st, true), &plan.Env{Host: s}, func(plan.Event) {}); err != nil {
		t.Fatal(err)
	}
	if !s.Ran("apt-get", "purge grafana prometheus") || s.Ran("purge", "caddy") {
		t.Errorf("local purge: %q", s.CommandLines())
	}
}
