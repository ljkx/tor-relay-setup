package plan

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

func obfs4Setup() config.Setup {
	s := testSetup()
	s.Relay.Mode, s.Relay.ORPort, s.Relay.Sandbox = "bridge", config.DefaultBridgePort, false
	s.Bridge = config.Bridge{Transport: "obfs4", Obfs4Port: config.DefaultObfs4Port}
	return s
}

func webTunnelSetup() config.Setup {
	s := obfs4Setup()
	s.Bridge = config.Bridge{
		Transport: "webtunnel", Domain: "bridge.example.org", Path: "Abc123secretPath",
		WebServer: config.WebServerNginx, Certificate: config.CertCertbot, CertbotAgreeTOS: true,
		CertbotEmail: "ops@example.org",
	}
	return s
}

func TestBridgeBuildOrder(t *testing.T) {
	t.Parallel()
	lowPort := obfs4Setup()
	lowPort.Bridge.Obfs4Port = 443
	manual := webTunnelSetup()
	manual.Bridge.WebServer = config.WebServerManual
	named := webTunnelSetup()
	named.Relay.Instance = "relay2"
	exit := testSetup()
	exit.Relay.Mode, exit.Exit.ProviderPermission, exit.Exit.Unbound, exit.Exit.Notice = "exit", true, false, true
	tests := []struct {
		name string
		s    config.Setup
		want []string
	}{
		{"obfs4", obfs4Setup(), []string{"preflight", "repository", "update", "packages", "unattended", "torrc", "firewall", "service", "state"}},
		{"obfs4 below 1024", lowPort, []string{"preflight", "repository", "update", "packages", "unattended", "bridge", "torrc", "firewall", "service", "state"}},
		// certbot needs port 80 open, so the firewall comes first.
		{"webtunnel nginx", webTunnelSetup(), []string{"preflight", "repository", "update", "packages", "unattended", "bridge", "firewall", "webtunnel", "torrc", "service", "state"}},
		{"webtunnel manual", manual, []string{"preflight", "repository", "update", "packages", "unattended", "bridge", "torrc", "firewall", "service", "state"}},
		// Named instances have no AppArmor profile: no bridge step.
		{"webtunnel named", named, []string{"preflight", "repository", "update", "packages", "instance", "unattended", "firewall", "webtunnel", "torrc", "service", "state"}},
		{"exit notice", exit, []string{"preflight", "repository", "update", "packages", "unattended", "exit-notice", "torrc", "firewall", "service", "state"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.s.Validate(); err != nil {
				t.Fatal(err)
			}
			steps := Build(tt.s, testFacts())
			if got := stepIDs(steps); !slices.Equal(got, tt.want) {
				t.Errorf("steps = %v\nwant    %v", got, tt.want)
			}
		})
	}
	fw := findStep(t, Build(lowPort, testFacts()), "firewall")
	if fw.Title != "Open TCP 9443, 443 in ufw" || !slices.Equal(fw.Changes, []string{"ufw allow 9443/tcp comment 'Tor bridge ORPort'", "ufw allow 443/tcp comment 'Tor bridge obfs4'"}) {
		t.Errorf("firewall step = %q %q", fw.Title, fw.Changes)
	}
	fw = findStep(t, Build(webTunnelSetup(), testFacts()), "firewall")
	if !slices.Equal(fw.Changes, []string{"ufw allow 443/tcp comment 'Tor WebTunnel bridge HTTPS'", "ufw allow 80/tcp comment 'Tor WebTunnel ACME HTTP-01'"}) {
		t.Errorf("webtunnel firewall = %q", fw.Changes)
	}
}

func TestBridgePackages(t *testing.T) {
	t.Parallel()
	low := obfs4Setup()
	low.Bridge.Obfs4Port = 80
	manual := webTunnelSetup()
	manual.Bridge.WebServer = config.WebServerManual
	existing := webTunnelSetup()
	existing.Bridge.Certificate = config.CertExisting
	for _, tt := range []struct {
		name string
		s    config.Setup
		want []string
	}{
		{"obfs4", obfs4Setup(), []string{"obfs4proxy"}},
		{"obfs4 low port", low, []string{"obfs4proxy", "libcap2-bin"}},
		{"webtunnel certbot", webTunnelSetup(), []string{"webtunnel", "nginx", "certbot", "python3-certbot-nginx"}},
		{"webtunnel existing cert", existing, []string{"webtunnel", "nginx"}},
		{"webtunnel manual", manual, []string{"webtunnel"}},
		{"guard", testSetup(), nil},
	} {
		if got := bridgePackages(tt.s); !slices.Equal(got, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
	pkgs := findStep(t, Build(obfs4Setup(), testFacts()), "packages")
	if !strings.Contains(pkgs.Changes[0], "lyrebird instead of obfs4proxy") {
		t.Errorf("packages change = %q", pkgs.Changes[0])
	}
}

func TestApplyAppArmorBlock(t *testing.T) {
	t.Parallel()
	user := "# Site-specific additions\n/srv/thing r,\n"
	got := string(ApplyAppArmorBlock([]byte(user), []string{"/usr/bin/webtunnel-server ix,"}))
	want := user + "\n" + appArmorBegin + "\n/usr/bin/webtunnel-server ix,\n" + appArmorEnd + "\n"
	if got != want {
		t.Fatalf("block =\n%s\nwant\n%s", got, want)
	}
	if again := string(ApplyAppArmorBlock([]byte(got), []string{"/usr/bin/webtunnel-server ix,"})); again != got {
		t.Errorf("not idempotent:\n%s", again)
	}
	if removed := string(ApplyAppArmorBlock([]byte(got), nil)); removed != user {
		t.Errorf("removal left %q", removed)
	}
	if empty := ApplyAppArmorBlock(nil, nil); len(empty) != 0 {
		t.Errorf("empty = %q", empty)
	}
}

func TestBridgeStepLowPort(t *testing.T) {
	t.Parallel()
	s := obfs4Setup()
	s.Bridge.Obfs4Port = 443
	s.Bridge.Plugin = relay.LyrebirdPath
	f := host.NewFake()
	f.Paths["apparmor_parser"] = true
	f.Files[appArmorProfile] = []byte("profile system_tor {}")
	f.Files[AppArmorLocal] = []byte("# local\n")
	env := NewEnv(f, testFacts(), s, "p")
	var rec safeRecorder
	if err := bridgeStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]string{
		{"setcap", "cap_net_bind_service=+ep", "/usr/bin/lyrebird"},
		{"systemctl", "daemon-reload"},
		{"apparmor_parser", "-r", "/etc/apparmor.d/system_tor"},
	} {
		if !f.Ran(want...) {
			t.Errorf("no %q in %q", want, f.CommandLines())
		}
	}
	dropIn := "/etc/systemd/system/tor@default.service.d/" + bridgeDropIn
	if !strings.Contains(string(f.Files[dropIn]), "NoNewPrivileges=no") {
		t.Errorf("drop-in = %q", f.Files[dropIn])
	}
	if !strings.Contains(string(f.Files[AppArmorLocal]), "capability net_bind_service,") {
		t.Errorf("AppArmor = %q", f.Files[AppArmorLocal])
	}

	// Moving the port above 1024 undoes both.
	s.Bridge.Obfs4Port = 8443
	env.Setup = s
	if err := bridgeStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Files[dropIn]; ok {
		t.Error("drop-in not removed")
	}
	if string(f.Files[AppArmorLocal]) != "# local\n" {
		t.Errorf("AppArmor block not removed: %q", f.Files[AppArmorLocal])
	}
}

func TestWebTunnelStep(t *testing.T) {
	t.Parallel()
	s := webTunnelSetup()
	cert, key := CertPaths(s)
	if cert != "/etc/letsencrypt/live/bridge.example.org/fullchain.pem" || key != "/etc/letsencrypt/live/bridge.example.org/privkey.pem" {
		t.Fatalf("CertPaths = %s %s", cert, key)
	}
	f := host.NewFake()
	var sites []string
	f.Handler = func(c host.Command) (host.Result, error) {
		switch c.Name {
		case "nginx":
			sites = append(sites, string(f.Files[s.Instance().WebTunnelSite()]))
		case "certbot":
			f.Files[cert], f.Files[key] = []byte("chain"), []byte("key")
		}
		return host.Result{}, nil
	}
	env := NewEnv(f, testFacts(), s, "p")
	var rec safeRecorder
	if err := webTunnelStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if !f.Ran("certbot", "certonly", "--nginx", "-d", "bridge.example.org", "--non-interactive", "--agree-tos", "--deploy-hook", "-m", "ops@example.org") {
		t.Errorf("certbot not run as expected: %q", f.CommandLines())
	}
	if len(sites) != 2 || strings.Contains(sites[0], "listen 443") || !strings.Contains(sites[1], "listen 443 ssl") {
		t.Fatalf("nginx -t saw %d sites; HTTP first, then HTTPS:\n%s", len(sites), strings.Join(sites, "\n----\n"))
	}
	site := string(f.Files["/etc/nginx/sites-available/tor-webtunnel-default"])
	for _, want := range []string{
		"server_name bridge.example.org;",
		"ssl_certificate " + cert + ";",
		"location = /Abc123secretPath {",
		"proxy_pass http://127.0.0.1:15000;",
		"proxy_http_version 1.1;",
		"proxy_set_header Upgrade $http_upgrade;",
		`proxy_set_header Connection "upgrade";`,
	} {
		if !strings.Contains(site, want) {
			t.Errorf("site lacks %q:\n%s", want, site)
		}
	}
	if f.Links["/etc/nginx/sites-enabled/tor-webtunnel-default"] != "/etc/nginx/sites-available/tor-webtunnel-default" {
		t.Errorf("site not enabled: %v", f.Links)
	}
	if !f.Ran("systemctl", "reload-or-restart", "nginx") || !f.Ran("systemctl", "enable", "nginx") {
		t.Errorf("nginx not reloaded: %q", f.CommandLines())
	}

	// Second run: the certificate exists, certbot is not asked again.
	f.Commands = nil
	if err := webTunnelStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if f.Ran("certbot") {
		t.Error("certbot ran although the certificate exists")
	}

	// nginx -t fails: the previous site is put back.
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "nginx" {
			return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1, Output: "nginx: [emerg] bad"}
		}
		return host.Result{}, nil
	}
	changed := webTunnelSetup()
	changed.Bridge.Path = "OtherSecretPath123"
	env.Setup = changed
	err := webTunnelStep(changed).Run(context.Background(), env, stepReporter{rec: &rec})
	if err == nil || !strings.Contains(err.Error(), "taken back") {
		t.Fatalf("err = %v", err)
	}
	if string(f.Files["/etc/nginx/sites-available/tor-webtunnel-default"]) != site {
		t.Error("the previous site was not restored")
	}
}

func TestWebTunnelStepExistingCertificate(t *testing.T) {
	t.Parallel()
	s := webTunnelSetup()
	s.Bridge.Certificate, s.Bridge.CertFile, s.Bridge.KeyFile = config.CertExisting, "/etc/ssl/bridge.pem", "/etc/ssl/bridge.key"
	f := host.NewFake()
	env := NewEnv(f, testFacts(), s, "p")
	var rec safeRecorder
	if err := webTunnelStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err == nil || !strings.Contains(err.Error(), "/etc/ssl/bridge.pem is missing") {
		t.Fatalf("missing certificate: %v", err)
	}
	if _, ok := f.Files[s.Instance().WebTunnelSite()]; ok {
		t.Error("site written without a certificate")
	}
	f.Files["/etc/ssl/bridge.pem"], f.Files["/etc/ssl/bridge.key"] = []byte("c"), []byte("k")
	if err := webTunnelStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if f.Ran("certbot") || !strings.Contains(string(f.Files[s.Instance().WebTunnelSite()]), "ssl_certificate_key /etc/ssl/bridge.key;") {
		t.Error("existing certificate not used")
	}

	// Reading the site back gives the same web server settings.
	back := s
	back.Bridge.WebServer, back.Bridge.CertFile, back.Bridge.KeyFile, back.Bridge.Certificate = "", "", "", ""
	ReadWebServer(f, &back)
	if back.Bridge.WebServer != config.WebServerNginx || back.Bridge.Certificate != config.CertExisting || back.Bridge.CertFile != "/etc/ssl/bridge.pem" || back.Bridge.KeyFile != "/etc/ssl/bridge.key" {
		t.Errorf("ReadWebServer = %+v", back.Bridge)
	}
	none := webTunnelSetup()
	ReadWebServer(host.NewFake(), &none)
	if none.Bridge.WebServer != config.WebServerManual {
		t.Errorf("no site = %q", none.Bridge.WebServer)
	}
}

func TestWebTunnelDryRun(t *testing.T) {
	t.Parallel()
	_, client := newRepo(t, realKey(t), map[string]int{"bookworm": http.StatusOK})
	s := webTunnelSetup()
	s.Bridge.Path = ""
	facts := testFacts()
	facts.EUID = 1000
	f := host.NewFake()
	f.Dry = true
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Mutates {
			t.Errorf("mutating command ran in a dry run: %s", c)
		}
		return host.Result{}, nil
	}
	env := NewEnv(f, facts, s, "tor-relay-setup vtest")
	env.HTTP, env.Now = client, func() time.Time { return fixedNow }
	var rec safeRecorder
	if err := Run(context.Background(), Build(s, facts), env, rec.emit); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(f.Files) != 0 || len(f.Links) != 0 {
		t.Errorf("dry run changed the host: %v %v", keys(f.Files), f.Links)
	}
	for _, want := range [][]string{
		{"apt-get", "install", "tor", "webtunnel", "nginx", "certbot", "python3-certbot-nginx"},
		{"ufw", "allow", "443/tcp"},
		{"ufw", "allow", "80/tcp"},
		{"certbot", "certonly", "--nginx", "-d", "bridge.example.org"},
		{"nginx", "-t"},
		{"systemctl", "reload-or-restart", "nginx"},
		{"systemctl", "restart", "tor@default"},
	} {
		if !f.Ran(want...) {
			t.Errorf("no %q; commands:\n%s", want, strings.Join(f.CommandLines(), "\n"))
		}
	}
	if !containsSubstring(rec.notes(), "Generated the secret WebTunnel path") {
		t.Errorf("notes %q", rec.notes())
	}
	if len(env.Setup.Bridge.Path) != 24 || !relay.ValidWebTunnelPath(env.Setup.Bridge.Path) {
		t.Errorf("generated path %q", env.Setup.Bridge.Path)
	}
}

func TestResolveWebTunnelPath(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	old := webTunnelSetup()
	f.Files["/etc/tor/torrc"] = old.RelayConfig(nil).Render("p", fixedNow)

	s := webTunnelSetup()
	s.Bridge.Path = ""
	if resolveWebTunnelPath(f, &s) || s.Bridge.Path != "Abc123secretPath" {
		t.Errorf("existing path not kept: %q", s.Bridge.Path)
	}
	s.Bridge.Path, s.Bridge.Domain = "", "other.example.org"
	if !resolveWebTunnelPath(f, &s) || s.Bridge.Path == "Abc123secretPath" {
		t.Errorf("a new domain should get a new path, got %q", s.Bridge.Path)
	}
	if a, b := NewWebTunnelPath(), NewWebTunnelPath(); a == b || len(a) != 24 {
		t.Errorf("NewWebTunnelPath = %q, %q", a, b)
	}
}

func TestBridgeConflicts(t *testing.T) {
	t.Parallel()
	other := func(torrc string) []relay.InstanceConfig {
		inst, _ := relay.Named("relay2")
		return []relay.InstanceConfig{{Instance: inst, Doc: relay.ParseDocument([]byte(torrc))}}
	}
	exit := testSetup()
	exit.Relay.Mode, exit.Exit.ProviderPermission, exit.Exit.Notice = "exit", true, true
	wt := webTunnelSetup()
	tests := []struct {
		name  string
		s     config.Setup
		torrc string
		want  string
	}{
		{"obfs4 port taken by an ORPort", obfs4Setup(), "ORPort 8443\n", "obfs4 port 8443 is already used by tor instance relay2"},
		{"ORPort taken by a transport", obfs4Setup(), "ORPort 9001\nServerTransportListenAddr obfs4 0.0.0.0:9443\n", "ORPort 9443 is already used"},
		{"notice port taken by a DirPort", exit, "ORPort 9002\nDirPort 80\n", "exit notice port 80"},
		{"nginx port taken", wt, "ORPort 443\n", "nginx HTTPS port 443"},
		{"same WebTunnel domain", wt, string(webTunnelSetup().RelayConfig(nil).Render("p", fixedNow)), "already runs a WebTunnel bridge on bridge.example.org"},
		{"no conflict", obfs4Setup(), "ORPort 9001\n", ""},
	}
	for _, tt := range tests {
		err := Conflicts(tt.s, other(tt.torrc))
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: %v", tt.name, err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

func TestPreflightPicksWebTunnelPortAndOfflineKey(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Files["/etc/tor/instances/relay2/torrc"] = []byte("ORPort 127.0.0.1:auto\nBridgeRelay 1\nServerTransportPlugin webtunnel exec /usr/bin/webtunnel-server\nServerTransportListenAddr webtunnel 127.0.0.1:15000\nServerTransportOptions webtunnel url=https://b2.example.org/Xyz123secretPath\n")
	f.Files["/var/lib/tor/keys/ed25519_master_id_public_key"] = []byte("pub")
	s := webTunnelSetup()
	env := NewEnv(f, testFacts(), s, "p")
	env.HTTP = &http.Client{Transport: failTransport{}}
	var rec safeRecorder
	// The repository probe fails (no network here); everything before it ran.
	_ = preflightStep(s, testFacts()).Run(context.Background(), env, stepReporter{rec: &rec})
	if env.Setup.Bridge.LocalPort != 15001 {
		t.Errorf("LocalPort = %d, want 15001 (15000 is taken)", env.Setup.Bridge.LocalPort)
	}
	if !env.Setup.Relay.OfflineMasterKey || !containsSubstring(rec.notes(), "keeping OfflineMasterKey 1") {
		t.Errorf("offline key not detected: %v %q", env.Setup.Relay.OfflineMasterKey, rec.notes())
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

func TestObfs4PackageAndTorrc(t *testing.T) {
	t.Parallel()
	s := obfs4Setup()
	f := host.NewFake()
	f.Dry = true
	f.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "apt-cache" && slices.Contains(c.Args, "lyrebird") {
			return host.Result{Output: "lyrebird:\n  Installed: (none)\n  Candidate: 0.8.1-1\n"}, nil
		}
		return host.Result{}, nil
	}
	env := NewEnv(f, testFacts(), s, "p")
	env.Now = func() time.Time { return fixedNow }
	var rec safeRecorder
	steps := Build(s, testFacts())
	for _, st := range selectSteps(t, steps, "packages", "torrc") {
		if err := st.Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
			t.Fatalf("%s: %v", st.ID, err)
		}
	}
	if !f.Ran("apt-get", "install", "tor", "deb.torproject.org-keyring", "nyx", "lyrebird") || f.Ran("obfs4proxy") {
		t.Errorf("lyrebird not chosen: %q", f.CommandLines())
	}
	if env.Setup.Bridge.Plugin != relay.LyrebirdPath {
		t.Errorf("plugin = %q", env.Setup.Bridge.Plugin)
	}
	torrc := string(env.Setup.RelayConfig(nil).Render("p", fixedNow))
	if !strings.Contains(torrc, "ServerTransportPlugin obfs4 exec /usr/bin/lyrebird\nServerTransportListenAddr obfs4 0.0.0.0:8443\n") {
		t.Errorf("torrc:\n%s", torrc)
	}
}

func TestExitNoticeStep(t *testing.T) {
	t.Parallel()
	s := testSetup()
	s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.Notice = "exit", true, true
	s.Relay.Instance = "relay2"
	f := host.NewFake()
	env := NewEnv(f, testFacts(), s, "p")
	var rec safeRecorder
	if err := exitNoticeStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	page := "/etc/tor/instances/relay2/tor-exit-notice.html"
	if !strings.Contains(string(f.Files[page]), "This is a Tor exit relay") || !strings.Contains(string(f.Files[page]), "TestRelay") {
		t.Fatalf("notice = %q", f.Files[page])
	}
	f.Files[page] = []byte("my own notice")
	if err := exitNoticeStep(s).Run(context.Background(), env, stepReporter{rec: &rec}); err != nil {
		t.Fatal(err)
	}
	if string(f.Files[page]) != "my own notice" {
		t.Error("an edited notice was overwritten")
	}
}

func TestFirewallCommandsFor(t *testing.T) {
	t.Parallel()
	nft := system.Firewall{Kind: system.KindNFTables, Active: true, Detail: system.DetailNFTChainFound}
	cmds := system.FirewallCommandsFor(nft, []system.Port{{Number: 9443}, {Number: 8443, Label: "Tor bridge obfs4"}, {Number: 9443}}, nil, false, false)
	var lines []string
	for _, c := range cmds {
		lines = append(lines, c.String())
	}
	want := []string{
		`nft add rule inet filter input tcp dport 9443 accept comment '"Tor relay ORPort 9443"'`,
		`nft add rule inet filter input tcp dport 8443 accept comment '"Tor bridge obfs4 8443"'`,
	}
	if !slices.Equal(lines, want) {
		t.Errorf("nft commands = %q", lines)
	}
}

// NginxSite never writes the TLS server before a certificate exists.
func TestNginxSiteHTTPOnly(t *testing.T) {
	t.Parallel()
	site := string(NginxSite(webTunnelSetup(), false))
	if strings.Contains(site, "443") || strings.Contains(site, "ssl_certificate") || strings.Contains(site, "Abc123secretPath") {
		t.Errorf("HTTP-only site:\n%s", site)
	}
}
