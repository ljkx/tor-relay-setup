package tui

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

const testBridgeLine = "obfs4 203.0.113.5:8443 9683BB02DA999159D376414EA8D0B4BBBAF95103 cert=Gqu7q1FpwhSbV6LegFzxcIIPqM6wHdJ3PTpTFd9pf9pBR5mgl02M2vjANqo4OasIPDUrIQ iat-mode=0"

func bridgeSetup() config.Setup {
	s := testSetup()
	s.Relay.Mode, s.Relay.ORPort, s.Relay.Sandbox = "bridge", config.DefaultBridgePort, false
	s.Bridge = config.Bridge{Transport: "obfs4", Obfs4Port: config.DefaultObfs4Port, Distribution: "any"}
	return s
}

func webTunnelSetup() config.Setup {
	s := bridgeSetup()
	s.Bridge = config.Bridge{
		Transport: "webtunnel", Domain: "bridge.example.org", Path: "Abc123secretPath", Distribution: "https",
		WebServer: config.WebServerNginx, Certificate: config.CertCertbot, CertbotAgreeTOS: true,
	}
	return s
}

func TestAnswersRoundTripBridgesAndExits(t *testing.T) {
	t.Parallel()
	existing := webTunnelSetup()
	existing.Bridge.Certificate, existing.Bridge.CertbotAgreeTOS = config.CertExisting, false
	existing.Bridge.CertFile, existing.Bridge.KeyFile = "/etc/ssl/b.pem", "/etc/ssl/b.key"
	manual := webTunnelSetup()
	manual.Bridge.WebServer, manual.Bridge.Certificate, manual.Bridge.CertbotAgreeTOS = config.WebServerManual, "", false
	manual.Bridge.LocalPort = 15001
	exit := testSetup()
	exit.Relay.Mode = "exit"
	exit.Exit = config.Exit{ProviderPermission: true, Policy: "custom", CustomPolicy: []string{"accept *:22", "accept *:443", "reject *:*"}, IPv6Exit: true, Unbound: true, Notice: true}
	exit.Relay.OfflineMasterKey = true
	for name, s := range map[string]config.Setup{
		"obfs4": bridgeSetup(), "webtunnel certbot": webTunnelSetup(), "webtunnel existing cert": existing,
		"webtunnel manual": manual, "exit custom policy": exit,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := answersFrom(s).setup(); !reflect.DeepEqual(got, s) {
				t.Errorf("round trip changed the setup:\n got %+v\nwant %+v", got, s)
			}
		})
	}

	// Choosing bridge mode drops the family and the sandbox.
	a := answersFrom(testSetup())
	a.Mode, a.FamilyMode, a.Sandbox = "bridge", "generate", true
	got := a.setup()
	if got.Family.Mode != "none" || got.Relay.Sandbox || got.Bridge.Obfs4Port != config.DefaultObfs4Port {
		t.Errorf("bridge answers = family %q sandbox %v port %d", got.Family.Mode, got.Relay.Sandbox, got.Bridge.Obfs4Port)
	}
	// A new WebTunnel setup gets a random path right away.
	if p := answersFrom(testSetup()).WTPath; !relay.ValidWebTunnelPath(p) || len(p) != 24 {
		t.Errorf("generated path %q", p)
	}
}

func TestNewInstanceNextToBridge(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Files["/etc/tor/torrc"] = bridgeSetup().RelayConfig(nil).Render("t", time.Now())
	s := NewInstanceSetup(f, relay.DefaultInstance())
	if s.Relay.Mode != "bridge" || s.Bridge.Transport != "obfs4" || s.Family.Mode != "none" {
		t.Fatalf("new instance = %+v", s)
	}
	if s.Relay.ORPort == config.DefaultBridgePort || s.Bridge.Obfs4Port == config.DefaultObfs4Port || s.Bridge.Obfs4Port == s.Relay.ORPort {
		t.Errorf("ports collide: ORPort %d obfs4 %d", s.Relay.ORPort, s.Bridge.Obfs4Port)
	}
	s.Bandwidth.MonthlyQuota = "10TB" // quota budgets are never copied to a new relay
	if err := s.Validate(); err != nil {
		t.Error(err)
	}
}

func TestWizardStepsPerMode(t *testing.T) {
	t.Parallel()
	a := testApp()
	labels := func(s config.Setup) []string { return newWizard(a, s).stepLabels() }
	if got := labels(bridgeSetup()); !slices.Equal(got, []string{"Relay", "Contact", "Network", "Bridge", "Bandwidth", "System", "Review"}) {
		t.Errorf("obfs4 steps = %v", got)
	}
	if got := labels(webTunnelSetup()); !slices.Equal(got, []string{"Relay", "Contact", "Bridge", "Bandwidth", "System", "Review"}) {
		t.Errorf("WebTunnel steps = %v", got)
	}
	exit := testSetup()
	exit.Relay.Mode = "exit"
	if got := labels(exit); !slices.Contains(got, "Exit") || slices.Contains(got, "Bridge") || !slices.Contains(got, "Family") {
		t.Errorf("exit steps = %v", got)
	}
	if err := validExitPolicyText("accept *:443\nreject *:*"); err != nil {
		t.Error(err)
	}
	if err := validExitPolicyText("accept *:443"); err == nil {
		t.Error("policy without catch-all accepted")
	}
	ans := &answers{ExitCustom: "accept *:443, reject *"}
	if got := exitPolicyPreview(ans); got != "ExitPolicy accept *:443\nExitPolicy reject *:*" {
		t.Errorf("preview = %q", got)
	}
	if opts := distributionOptions(true); opts[0].Value != "https" || len(opts) != len(relay.Distributions) {
		t.Errorf("WebTunnel distribution options = %v", opts)
	}
}

func bridgeReport() status.Report {
	r := consoleReport()
	r.Relay.Nickname, r.Relay.ORPort, r.Relay.IPv6, r.Relay.Sandbox, r.Relay.Bridge = "BridgeOne", 9443, false, false, true
	r.Relay.MetricsPort = ""
	r.Reachability.IPv6 = false
	r.PublicIPv4 = "203.0.113.5"
	r.Bridge = &status.Bridge{
		Transport: "obfs4", Plugin: relay.Obfs4ProxyPath, PluginInstalled: true, Port: 8443, Listening: true,
		Distribution: "any", HashedFingerprint: "B2331AC0CA67CCA67C104B892DCCFA531B3DF50A", Line: testBridgeLine, LineComplete: true,
	}
	return r
}

func bridgeConsole(a *App) *console {
	c := newConsole()
	a.screen, a.console = c, c
	c.report, c.loaded = bridgeReport(), true
	yes := true
	c.bridgeDir = &onionoo.Bridge{
		Nickname: "BridgeOne", Running: true, Flags: []string{"Running", "Stable", "Valid"}, Transports: []string{"obfs4"},
		Distributor: "settings", FirstSeen: "2026-09-01 10:00:00", AdvertisedBandwidth: 2_500_000,
		Version: "0.4.9.13", VersionStatus: "recommended", RecommendedVersion: &yes, Blocklist: []string{"ru"},
	}
	c.dirAt = time.Now()
	return c
}

func TestConsoleActionsPerMode(t *testing.T) {
	t.Parallel()
	keysOf := func(c *console) string {
		c.filterActions()
		var k []string
		for _, act := range c.actions {
			k = append(k, act.key)
		}
		return strings.Join(k, "")
	}
	c := newConsole()
	c.report = consoleReport()
	if got := keysOf(c); got != "rlfekcsopubwnq" {
		t.Errorf("guard actions = %q", got)
	}
	c.report.Relay.Exit = true
	if got := keysOf(c); got != "rlfxekcsopubwnq" {
		t.Errorf("exit actions = %q", got)
	}
	c.report = bridgeReport()
	if got := keysOf(c); got != "rlieksopubwnq" {
		t.Errorf("bridge actions = %q", got)
	}
	// Hidden actions have no shortcut either.
	a := testApp()
	if next, _ := c.update(a, tea.KeyPressMsg{Code: 'f', Text: "f"}); next != c {
		t.Errorf("f opened %T on a bridge", next)
	}
	if next, _ := c.update(a, tea.KeyPressMsg{Code: 'i', Text: "i"}); reflect.TypeOf(next) != reflect.TypeFor[*bridgeView]() {
		t.Errorf("i opened %T", next)
	}
}

func TestBridgeViewCopyAndSave(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width = 130
	c := bridgeConsole(a)
	v := newBridgeView(c)
	text := strip(v.view(a))
	for _, want := range []string{"Share this line", "iat-mode=0", "https://bridges.torproject.org/scan/?address=203.0.113.5&port=8443",
		"bridges.torproject.org/status?id=B2331AC0", "Distributor", "settings", "Blocked in"} {
		if !strings.Contains(text, want) {
			t.Errorf("bridge view lacks %q:\n%s", want, text)
		}
	}
	if _, cmd := v.update(a, tea.KeyPressMsg{Code: 'y', Text: "y"}); cmd == nil {
		t.Error("y returned no command")
	}
	v.update(a, tea.KeyPressMsg{Code: 'w', Text: "w"})
	f := a.opt.Host.(*host.Fake)
	if got := string(f.Files["/root/tor-bridge-line.txt"]); got != testBridgeLine+"\n" || f.Modes["/root/tor-bridge-line.txt"] != 0o600 {
		t.Errorf("saved line %q mode %o", got, f.Modes["/root/tor-bridge-line.txt"])
	}

	c.report.Bridge.Distribution = "none"
	c.report.Bridge.Line, c.report.Bridge.LineComplete = strings.Replace(testBridgeLine, "203.0.113.5", "<IP ADDRESS>", 1), false
	text = strip(v.view(a))
	if !strings.Contains(text, "never hands this bridge out") || !strings.Contains(text, "Replace <IP ADDRESS>") {
		t.Errorf("none / placeholder hints missing:\n%s", text)
	}
}

func TestGoldenConsoleBridge(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 140, 44
	bridgeConsole(a)
	golden(t, "console-bridge", a)
}

func TestGoldenBridgeLine(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 40
	a.screen = newBridgeView(bridgeConsole(a))
	golden(t, "bridge-line", a)
}

func TestGoldenReviewWebTunnel(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 80
	s := webTunnelSetup()
	s.Bridge.WebServer, s.Bridge.Certificate, s.Bridge.CertbotAgreeTOS = config.WebServerManual, "", false
	a.screen = newReview(a, s, nil)
	golden(t, "review-webtunnel", a)
}

func TestGoldenReviewObfs4(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 70
	s := bridgeSetup()
	s.Bridge.Obfs4Port = 443
	a.screen = newReview(a, s, nil)
	golden(t, "review-obfs4", a)
}

func TestReviewExitPolicyAndNotice(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 80
	s := testSetup()
	s.Relay.Mode, s.Exit.ProviderPermission, s.Exit.Notice = "exit", true, true
	s.Exit.Policy, s.Exit.CustomPolicy = "custom", []string{"accept *:443", "reject *:*"}
	r := newReview(a, s, nil)
	text := strip(r.render(a))
	for _, want := range []string{"custom policy", "exit notice on port 80", "ExitPolicy accept *:443", "DirPortFrontPage /etc/tor/tor-exit-notice.html", "Create the exit notice", "ufw allow 80/tcp"} {
		if !strings.Contains(text, want) {
			t.Errorf("review lacks %q:\n%s", want, text)
		}
	}
	if r.problem != "" {
		t.Errorf("problem: %s", r.problem)
	}
}

// keyFixture is a relay whose identity keys are the real test keys made
// with tor 0.4.9.13 (internal/keys/testdata), master key on disk.
func keyFixture(t *testing.T, offline bool) (*App, *console) {
	t.Helper()
	cert, err := os.ReadFile("../keys/testdata/ed25519_signing_cert")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("../keys/testdata/ed25519_master_id_public_key")
	if err != nil {
		t.Fatal(err)
	}
	a := testApp()
	f := a.opt.Host.(*host.Fake)
	f.Paths["tor"] = true
	torrc := "Nickname GoodRelay\nContactInfo x\nORPort 9001\n"
	if offline {
		torrc += "OfflineMasterKey 1\n"
	}
	f.Files["/etc/tor/torrc"] = []byte(torrc)
	f.Files["/var/lib/tor/keys/"+keys.SigningCert] = cert
	f.Files["/var/lib/tor/keys/"+keys.MasterPublic] = pub
	f.Files["/var/lib/tor/keys/"+keys.MasterSecret] = []byte("master-secret")
	c := newConsole()
	a.screen, a.console = c, c
	c.report, c.loaded = consoleReport(), true
	st := keys.Inspect(f, "/var/lib/tor/keys", offline)
	c.report.Keys = &st
	return a, c
}

func TestGoldenKeysView(t *testing.T) {
	t.Parallel()
	a, c := keyFixture(t, false)
	a.width, a.height = 110, 44
	st := *c.report.Keys
	st.CertExpires = time.Now().Add(20*24*time.Hour + 12*time.Hour)
	c.report.Keys = &st
	v := newKeysView(c)
	a.screen = v
	text := strip(a.screen.view(a))
	for _, want := range []string{"Take the master key offline", "Remove the master key", "Renew the signing key here", "on this server", "(20 days)"} {
		if !strings.Contains(text, want) {
			t.Errorf("keys view lacks %q:\n%s", want, text)
		}
	}
	// The expiry date moves with the clock; pin it for the snapshot.
	st.CertExpires = time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC)
	c.report.Keys = &st
	v.clock = func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }
	golden(t, "keys", a)
}

func TestKeysViewOfflineFlow(t *testing.T) {
	a, c := keyFixture(t, false)
	f := a.opt.Host.(*host.Fake)
	v := newKeysView(c)

	// Removing is refused until OfflineMasterKey is set.
	if next, cmd := v.update(a, tea.KeyPressMsg{Code: 'x', Text: "x"}); next != v || cmd == nil || v.form != nil {
		t.Fatalf("x before offline: %T form %v", next, v.form != nil)
	}

	// Step 1 sets OfflineMasterKey 1 and exports the key; nothing is removed.
	summary, err := offlineTask(c.selected(), "/var/lib/tor/keys")(t.Context(), f, func(string) {}, func(float64, string) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Files["/etc/tor/torrc"]), "OfflineMasterKey 1") {
		t.Errorf("torrc:\n%s", f.Files["/etc/tor/torrc"])
	}
	if _, ok := f.Files["/var/lib/tor/keys/"+keys.MasterSecret]; !ok {
		t.Fatal("step 1 removed the master key")
	}
	export := latestExport(f, c.selected())
	if export == "" || string(f.Files[export+"/"+keys.MasterSecret]) != "master-secret" {
		t.Fatalf("export %q: %v", export, f.Files[export+"/"+keys.MasterSecret])
	}
	if !strings.Contains(summary, "sha256sum") || !strings.Contains(summary, keys.Digest([]byte("master-secret"))[:12]) {
		t.Errorf("summary:\n%s", summary)
	}

	// Step 2 asks for the hash of the offline copy before removing.
	st := keys.Inspect(f, "/var/lib/tor/keys", true)
	c.report.Keys = &st
	v = newKeysView(c)
	v.update(a, tea.KeyPressMsg{Code: 'x', Text: "x"})
	if v.form == nil || v.mode != "remove" {
		t.Fatalf("x after offline: mode %q", v.mode)
	}
	v.form, v.typed = nil, "0000000000000000"
	next, _ := v.run(a)
	tk := finishTask(t, a, next)
	if tk.err == nil || !strings.Contains(tk.err.Error(), "does not match") {
		t.Fatalf("wrong hash: %v", tk.err)
	}
	if _, ok := f.Files["/var/lib/tor/keys/"+keys.MasterSecret]; !ok {
		t.Fatal("removed with a wrong hash")
	}
	v.typed = keys.Digest([]byte("master-secret"))[:16]
	next, _ = v.run(a)
	if tk := finishTask(t, a, next); tk.err != nil {
		t.Fatalf("remove: %v", tk.err)
	}
	if _, ok := f.Files["/var/lib/tor/keys/"+keys.MasterSecret]; ok {
		t.Error("master key still on the server")
	}
	if _, ok := f.Files[export+"/"+keys.MasterSecret]; ok {
		t.Error("export still on the server")
	}
	// Renewing now explains the offline procedure.
	c.report.Keys = nil
	v = newKeysView(c)
	v.update(a, tea.KeyPressMsg{Code: 'r', Text: "r"})
	if v.mode != "help" || !strings.Contains(strip(v.view(a)), "keys renew --from /root/tor-signing") {
		t.Errorf("renew without master: mode %q\n%s", v.mode, strip(v.view(a)))
	}
}

// finishTask runs a console task to completion.
func finishTask(t *testing.T, a *App, s screen) *task {
	t.Helper()
	tk, ok := s.(*task)
	if !ok {
		t.Fatalf("got %T, want a task", s)
	}
	for tk.running {
		msg := tk.listen()()
		tk.update(a, msg)
	}
	return tk
}

func TestExitPolicyView(t *testing.T) {
	a := testApp()
	f := a.opt.Host.(*host.Fake)
	f.Paths["tor"] = true
	c := newConsole()
	c.report = consoleReport()
	c.report.Relay.Exit = true
	cfg := relay.Config{Nickname: "GoodRelay", ContactInfo: "email:ops[]example.org", ORPort: 9001, Mode: relay.ModeExit, ExitPolicy: relay.PolicyReduced}
	f.Files["/etc/tor/torrc"] = cfg.Render("t", time.Now())
	next, _ := newExitPolicyView(a, c)
	e, ok := next.(*exitPolicyView)
	if !ok {
		t.Fatalf("got %T", next)
	}
	if e.ans.ExitPolicy != "reduced" {
		t.Errorf("read back %q", e.ans.ExitPolicy)
	}
	golden(t, "exit-policy", withScreen(a, e))

	e.ans.ExitPolicy, e.ans.ExitCustom, e.ans.ExitNotice = "custom", "accept *:22\naccept *:443\nreject *:*", true
	e.form.State = huh.StateCompleted
	next, _ = e.update(a, nil)
	if tk := finishTask(t, a, next); tk.err != nil {
		t.Fatal(tk.err)
	}
	torrc := string(f.Files["/etc/tor/torrc"])
	for _, want := range []string{"ExitRelay 1\nExitPolicy accept *:22\nExitPolicy accept *:443\nExitPolicy reject *:*\n", "DirPort 80\nDirPortFrontPage /etc/tor/tor-exit-notice.html"} {
		if !strings.Contains(torrc, want) {
			t.Errorf("torrc lacks %q:\n%s", want, torrc)
		}
	}
	if strings.Contains(torrc, "ReducedExitPolicy") {
		t.Error("ReducedExitPolicy left behind")
	}
	if !strings.Contains(string(f.Files["/etc/tor/tor-exit-notice.html"]), "GoodRelay") {
		t.Error("exit notice not written")
	}
	if !f.Ran("systemctl", "restart", "tor@default") {
		t.Errorf("enabling the notice must restart tor: %q", f.CommandLines())
	}
}

func withScreen(a *App, s screen) *App {
	a.screen = s
	a.width, a.height = 110, 40
	return a
}

func TestProofView(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 110, 50
	f := a.opt.Host.(*host.Fake)
	f.Files["/etc/tor/torrc"] = []byte("Nickname GoodRelay\nContactInfo \"email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 ciissversion:3\"\nFamilyId " + famID("A") + "\nORPort 9001\n")
	f.Files["/var/lib/tor/fingerprint"] = []byte("GoodRelay ABCDEF0123456789ABCDEF0123456789ABCDEF01\n")
	c := newConsole()
	c.report = consoleReport()
	p := newProofView(a, c)
	a.screen = p
	text := strip(p.view(a))
	for _, want := range []string{"https://example.org/.well-known/tor-relay/ed25519-family-id.txt", famID("A"), "rsa-fingerprint.txt", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"} {
		if !strings.Contains(text, want) {
			t.Errorf("proof view lacks %q:\n%s", want, text)
		}
	}
	p.update(a, proofCheckMsg{{URL: "https://example.org/.well-known/tor-relay/ed25519-family-id.txt", OK: true, Found: []string{famID("A")}}})
	golden(t, "proof", a)
}
