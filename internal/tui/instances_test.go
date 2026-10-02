package tui

import (
	"context"
	"strconv"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

func named(t *testing.T, name string) relay.Instance {
	t.Helper()
	inst, err := relay.Named(name)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// multiConsole is the live dashboard on a server with three relays; relay3
// needs attention.
func multiConsole(t *testing.T, a *App) *console {
	c := liveConsole(a)
	def := c.report
	def.Instance = "default"
	r2 := consoleReport()
	r2.Instance, r2.Service.Unit, r2.Relay.Nickname, r2.Relay.ORPort = "relay2", "tor@relay2", "GoodRelay2", 9002
	r3 := consoleReport()
	r3.Instance, r3.Service.Unit, r3.Relay.Nickname, r3.Relay.ORPort = "relay3", "tor@relay3", "GoodRelay3", 9003
	r3.Service.Active = false
	r3.Warnings = []string{"tor@relay3 is not running"}
	c.report = def
	c.instances = []relay.Instance{relay.DefaultInstance(), named(t, "relay2"), named(t, "relay3")}
	c.overview = []status.Report{def, r2, r3}
	return c
}

func TestGoldenConsoleMultiInstance(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 140, 46
	multiConsole(t, a)
	golden(t, "console-multi", a)
}

func TestGoldenReviewNamedInstance(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.width, a.height = 120, 70
	s := testSetup()
	s.Relay.Instance, s.Relay.ORPort, s.Relay.Nickname, s.Relay.MetricsPort = "relay2", 9002, "TestRelay2", true
	s.Bandwidth.Mode, s.Bandwidth.RateMbit = "manual", 400
	s.System.Tuning = true
	f := a.opt.Host.(*host.Fake)
	f.Files["/etc/tor/torrc"] = []byte("Nickname TestRelay\nORPort 9001\nMetricsPort 127.0.0.1:9035\n")
	a.screen = newReview(a, s, nil)
	golden(t, "review-instance", a)
}

func press(s string) tea.KeyPressMsg { return tea.KeyPressMsg{Code: rune(s[0]), Text: s} }

func TestConsoleInstanceSwitcher(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := multiConsole(t, a)

	view := strip(c.view(a))
	for _, want := range []string{
		"Relays  1 default ✓   2 relay2 ✓   3 relay3 !",
		"! 1 of 3 relays need attention: relay3 (tor@relay3 is not running)",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("multi-instance view lacks %q:\n%s", want, view)
		}
	}
	if keys := strings.Join(c.keys(a), " "); !strings.Contains(keys, "[/] relay default") {
		t.Errorf("footer keys = %q", keys)
	}

	tests := []struct {
		key, want string
	}{
		{"]", "relay2"},
		{"]", "relay3"},
		{"]", "default"}, // wraps
		{"[", "relay3"},  // wraps backwards
		{"2", "relay2"},
		{"1", "default"},
		{"9", "default"}, // no ninth relay
	}
	for _, tt := range tests {
		c.update(a, press(tt.key))
		if got := c.selected().Name; got != tt.want {
			t.Fatalf("after %q selected %q, want %q", tt.key, got, tt.want)
		}
		if c.report.Instance != tt.want {
			t.Errorf("after %q the cards show %q", tt.key, c.report.Instance)
		}
	}

	// Switching resets the per-relay live data and asks for fresh data.
	c.update(a, press("1"))
	_, cmd := c.update(a, press("3"))
	if cmd == nil || c.rates != nil || c.dir != nil || c.history != nil {
		t.Errorf("switch: cmd %v rates %v dir %v history %v", cmd != nil, c.rates, c.dir, c.history)
	}
	if c.report.Service.Active || c.report.Relay.Nickname != "GoodRelay3" {
		t.Errorf("relay3's card shows %+v", c.report.Relay)
	}
	if keys := strings.Join(c.keys(a), " "); !strings.Contains(keys, "relay relay3") {
		t.Errorf("footer keys = %q", keys)
	}
	// A late result for the previous relay is ignored.
	c.update(a, directoryMsg{fp: "0000000000000000000000000000000000000000"})
	c.update(a, sampleMsg{addr: "127.0.0.1:9999"})
	if !c.dirAt.IsZero() || len(c.rates) != 0 {
		t.Error("a result for another relay reached the cards")
	}

	// A refresh keeps the selection by name, and falls back when the
	// selected relay is gone.
	r2 := c.overview[1]
	c.update(a, instancesMsg{instances: []relay.Instance{relay.DefaultInstance(), named(t, "relay3")}, reports: []status.Report{c.overview[0], c.overview[2]}})
	if c.selected().Name != "relay3" || c.report.Instance != "relay3" {
		t.Errorf("selection after refresh = %q", c.selected().Name)
	}
	c.update(a, instancesMsg{instances: []relay.Instance{relay.DefaultInstance(), named(t, "relay2")}, reports: []status.Report{c.overview[0], r2}})
	if c.selected().Name != "default" {
		t.Errorf("selection after its relay vanished = %q", c.selected().Name)
	}

	// Back to one relay: no switcher.
	single := consoleReport()
	single.Instance = "default"
	c.update(a, reportMsg(single))
	if c.multi() || strings.Contains(strip(c.view(a)), "Relays ") {
		t.Errorf("single relay still shows the switcher:\n%s", strip(c.view(a)))
	}
	if _, cmd := c.update(a, press("]")); cmd != nil || c.selected().Name != "default" {
		t.Error("] switched with a single relay")
	}
}

func TestConsoleSingleInstanceHasNoSwitcher(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := liveConsole(a)
	view := strip(c.view(a))
	if strings.Contains(view, "Relays ") || strings.Contains(view, "relays on this server") {
		t.Errorf("single relay shows the switcher:\n%s", view)
	}
	if keys := strings.Join(c.keys(a), " "); strings.Contains(keys, "[/]") {
		t.Errorf("footer keys = %q", keys)
	}
}

// relayHost is a fake server running the default relay with a family key.
func relayHost(t *testing.T) *host.Fake {
	t.Helper()
	f := host.NewFake()
	f.Files["/etc/tor/torrc"] = []byte("Nickname MyRelay\nContactInfo \"ops@example.org\"\nFamilyId " + famID("A") + "\nORPort 9001\nORPort [2001:db8::1]:9001\nSandbox 1\nMetricsPort 127.0.0.1:9035\nRelayBandwidthRate 1640 KBytes\nRelayBandwidthBurst 8200 KBytes\nAccountingMax 8381 GBytes\n")
	key := make([]byte, 96)
	copy(key, family.KeyHeader)
	f.Files["/var/lib/tor/keys/fleet.secret_family_key"] = key
	f.Files["/var/lib/tor/keys/fleet.public_family_id"] = []byte(famID("A") + "\n")
	return f
}

func TestConsoleRefreshFindsInstances(t *testing.T) {
	t.Parallel()
	a := testApp()
	f := relayHost(t)
	a.opt.Host = f
	c := newConsole()
	if _, ok := c.refresh(a)().(reportMsg); !ok {
		t.Fatal("one relay should produce a reportMsg")
	}
	f.Files["/etc/tor/instances/relay2/torrc"] = []byte("Nickname MyRelay2\nORPort 9002\n")
	msg, ok := c.refresh(a)().(instancesMsg)
	if !ok || len(msg.instances) != 2 || msg.reports[1].Instance != "relay2" || msg.reports[1].Relay.ORPort != 9002 {
		t.Fatalf("refresh = %+v", msg)
	}
	c.update(a, msg)
	if !c.multi() || c.selected().Name != "default" || c.report.Relay.Nickname != "MyRelay" {
		t.Errorf("after refresh: multi %v selected %q", c.multi(), c.selected().Name)
	}
}

func TestAddRelayOpensNewInstanceWizard(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.opt.Host = relayHost(t)
	c := newConsole()
	a.screen = c
	next, _ := c.update(a, press("n"))
	w, ok := next.(*wizard)
	if !ok {
		t.Fatalf("n opened %T", next)
	}
	ans := w.ans
	if !ans.NewInstance || ans.Instance != "relay2" || ans.ORPort != "9002" || ans.Nickname != "MyRelay2" {
		t.Errorf("answers: new %v instance %q ORPort %q nickname %q", ans.NewInstance, ans.Instance, ans.ORPort, ans.Nickname)
	}
	if ans.ContactFree != "ops@example.org" || ans.IPv6Manual != "2001:db8::1" || !ans.Metrics || !ans.Sandbox {
		t.Errorf("not copied: contact %q ipv6 %q metrics %v sandbox %v", ans.ContactFree, ans.IPv6Manual, ans.Metrics, ans.Sandbox)
	}
	if ans.FamilyMode != "generate" || ans.FamilyKey != "fleet" || len(ans.Keep) != 0 {
		t.Errorf("family: mode %q key %q keep %v; want the server's key shared", ans.FamilyMode, ans.FamilyKey, ans.Keep)
	}
	if ans.BandwidthMode != "steady" || ans.Quota != "" {
		t.Errorf("a quota budget was copied: %q %q", ans.BandwidthMode, ans.Quota)
	}
	if w.metrics != "127.0.0.1:9036" {
		t.Errorf("metrics address = %q", w.metrics)
	}
	view := strip(w.view(a))
	for _, want := range []string{"Name of the new relay instance", "instance relay2"} {
		if !strings.Contains(view, want) {
			t.Errorf("wizard lacks %q:\n%s", want, view)
		}
	}
	s := ans.setup()
	if s.Instance().Unit != "tor@relay2" {
		t.Errorf("setup instance = %+v", s.Instance())
	}

	// Reconfigure keeps editing the selected relay, without a name field.
	next, _ = c.update(a, press("w"))
	if w := next.(*wizard); w.ans.NewInstance || w.ans.Instance != "" {
		t.Errorf("reconfigure: new %v instance %q", w.ans.NewInstance, w.ans.Instance)
	}
}

func TestAddRelayRefusesBeyondPerIPLimit(t *testing.T) {
	t.Parallel()
	a := testApp()
	f := relayHost(t)
	for i := 2; i <= relay.MaxRelaysPerIPv4; i++ {
		f.Files["/etc/tor/instances/r"+strconv.Itoa(i)+"/torrc"] = []byte("ORPort " + strconv.Itoa(9000+i) + "\n")
	}
	a.opt.Host = f
	c := newConsole()
	next, cmd := c.update(a, press("n"))
	if next != c || cmd == nil {
		t.Fatalf("n with %d relays opened %T", relay.MaxRelaysPerIPv4, next)
	}
	if msg, _ := cmd().(toastMsg); !strings.Contains(string(msg), "the most the directory authorities list per IPv4 address") {
		t.Errorf("toast = %q", msg)
	}
}

func TestNewInstanceSetup(t *testing.T) {
	t.Parallel()
	f := relayHost(t)
	f.Files["/etc/tor/instances/relay2/torrc"] = []byte("Nickname MyRelay2\nORPort 9002\nMetricsPort 127.0.0.1:9036\n")
	s := NewInstanceSetup(f, named(t, "relay2"))
	if s.Relay.Instance != "relay3" || s.Relay.ORPort != 9003 || s.Relay.Nickname != "MyRelay3" {
		t.Errorf("instance %q ORPort %d nickname %q", s.Relay.Instance, s.Relay.ORPort, s.Relay.Nickname)
	}
	// relay2 has no family key: nothing to share from it.
	if s.Family.Mode != "none" {
		t.Errorf("family mode = %q", s.Family.Mode)
	}

	// A manual rate per relay is copied.
	f.Files["/etc/tor/torrc"] = []byte("Nickname A\nContactInfo x\nORPort 9001\nRelayBandwidthRate 50 MBits\nRelayBandwidthBurst 100 MBits\n")
	s = NewInstanceSetup(f, relay.DefaultInstance())
	if s.Bandwidth.Mode != "manual" || s.Bandwidth.RateMbit != 50 {
		t.Errorf("bandwidth = %+v", s.Bandwidth)
	}

	if got := InstancePrefill(f, "relay2"); got.Relay.Instance != "relay2" || got.Relay.Nickname != "MyRelay2" {
		t.Errorf("prefill of an existing instance = %+v", got.Relay)
	}
	if got := InstancePrefill(f, "relay7"); got.Relay.Instance != "relay7" || got.Relay.ORPort != 9003 {
		t.Errorf("prefill of a new instance = %+v", got.Relay)
	}
}

func TestNumberedNickname(t *testing.T) {
	t.Parallel()
	tests := []struct {
		base string
		n    int
		want string
	}{
		{"MyRelay", 2, "MyRelay2"},
		{"MyRelay1", 2, "MyRelay2"},
		{"ABCDEFGHIJKLMNOPQRS", 3, "ABCDEFGHIJKLMNOPQR3"},
		{"ABCDEFGHIJKLMNOPQRS", 12, "ABCDEFGHIJKLMNOPQ12"},
		{"", 2, ""},
		{"123", 2, ""},
	}
	for _, tt := range tests {
		if got := numberedNickname(tt.base, tt.n); got != tt.want || len(got) > 19 {
			t.Errorf("numberedNickname(%q, %d) = %q, want %q", tt.base, tt.n, got, tt.want)
		}
	}
}

func TestWriteTorrcForNamedInstance(t *testing.T) {
	t.Parallel()
	f := host.NewFake()
	f.Paths["tor"] = true
	f.Files[relay.InstanceDefaultsTemplate] = []byte("User _tor-@@NAME@@\n")
	inst := named(t, "relay2")
	var out []string
	if err := writeTorrc(context.Background(), f, inst, []byte("ORPort 9002\n"), false, func(s string) { out = append(out, s) }); err != nil {
		t.Fatal(err)
	}
	if string(f.Files["/etc/tor/instances/relay2/torrc"]) != "ORPort 9002\n" {
		t.Errorf("files = %v", f.Files)
	}
	if _, ok := f.Files["/etc/tor/torrc"]; ok {
		t.Error("the default torrc was written")
	}
	if !f.Ran("systemctl reload tor@relay2") || f.Ran("tor@default") {
		t.Errorf("commands = %q", f.CommandLines())
	}
	if !strings.Contains(f.CommandLines()[0], "--defaults-torrc") {
		t.Errorf("verify did not use the instance defaults: %q", f.CommandLines()[0])
	}
}

func TestInstanceTasks(t *testing.T) {
	t.Parallel()
	inst := named(t, "relay2")
	tests := []struct {
		name string
		fn   taskFunc
		want string
	}{
		{"stop", stopTask(inst), "systemctl stop tor@relay2"},
		{"start", startTask(inst), "systemctl start tor@relay2"},
		{"reload", reloadTask(inst), "systemctl reload tor@relay2"},
	}
	for _, tt := range tests {
		f := host.NewFake()
		if _, err := tt.fn(context.Background(), f, func(string) {}, func(float64, string) {}); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !f.Ran(tt.want) || f.Ran("tor@default") {
			t.Errorf("%s: commands = %q", tt.name, f.CommandLines())
		}
	}
	f := host.NewFake()
	f.Dry = true
	summary, err := backupTask(inst, "")(context.Background(), f, func(string) {}, func(float64, string) {})
	if err != nil || !strings.Contains(summary, "/var/lib/tor-instances/relay2/keys to /root/tor-relay-keys-relay2-") {
		t.Errorf("backup summary = %q, %v", summary, err)
	}
}

func TestWizardTuningQuestion(t *testing.T) {
	t.Parallel()
	ans := answersFrom(testSetup()) // 10TB steady budget: ~33 Mbit/s
	ans.Tuning = true
	if ans.setup().System.Tuning {
		t.Error("tuning kept for a slow relay whose question is hidden")
	}
	ans.BandwidthMode, ans.RateMbit = "manual", "500"
	if !ans.setup().System.Tuning {
		t.Error("tuning dropped for a 500 Mbit/s relay")
	}
}
