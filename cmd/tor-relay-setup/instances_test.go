package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/status"
)

const relay2Torrc = `Nickname SecondRelay
ContactInfo "ops@example.org"
ORPort 9002
SocksPort 0
ExitRelay 0
`

// multiRoot is fixtureRoot plus a second relay instance "relay2" on 9002;
// withDefault false leaves /etc/tor/torrc without a relay.
func multiRoot(t *testing.T, withDefault bool) string {
	t.Helper()
	torrc := ""
	if withDefault {
		torrc = strings.Replace(fixtureTorrc, "FAMILY", famA, 1)
	}
	root := fixtureRoot(t, torrc)
	files := map[string]string{
		"etc/tor/instances/relay2/torrc": relay2Torrc,
		// 0x2329 = 9001 and 0x232A = 9002, both in LISTEN (0A) state.
		"proc/net/tcp": "  sl  local_address rem_address   st\n" +
			"   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n" +
			"   1: 00000000:232A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1\n",
	}
	for p, data := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func decodeReports(t *testing.T, out string) []status.Report {
	t.Helper()
	var reports []status.Report
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reports); err != nil {
		t.Fatalf("status --all --json is not an array of Reports: %v\n%s", err, out)
	}
	return reports
}

func TestStatusAllJSON(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", multiRoot(t, true))

	code, out, errOut := runCLI(t, "status", "--dry-run", "--all", "--format", "json")
	if code != 0 {
		t.Errorf("exit %d (stderr %q)\n%s", code, errOut, out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Fatalf("--all JSON is not an array:\n%s", out)
	}
	reports := decodeReports(t, out)
	if len(reports) != 2 {
		t.Fatalf("got %d reports", len(reports))
	}
	if r := reports[0]; r.Instance != "default" || r.Service.Unit != "tor@default" || r.Relay.Nickname != "FixtureRelay" {
		t.Errorf("first report = %q %q %q", r.Instance, r.Service.Unit, r.Relay.Nickname)
	}
	if r := reports[1]; r.Instance != "relay2" || r.Service.Unit != "tor@relay2" || r.Relay.ORPort != 9002 || !r.Listener.IPv4 {
		t.Errorf("second report = %q %q %d listener %v", r.Instance, r.Service.Unit, r.Relay.ORPort, r.Listener.IPv4)
	}
	if !strings.Contains(out, `"instance": "relay2"`) {
		t.Errorf("JSON lacks the instance key:\n%s", out)
	}

	// Without --all: one object, the default instance (unchanged contract).
	code, out, _ = runCLI(t, "status", "--dry-run", "--json")
	var one status.Report
	if err := json.Unmarshal([]byte(out), &one); err != nil || code != 0 || one.Instance != "default" {
		t.Errorf("status --json: exit %d, instance %q, err %v\n%s", code, one.Instance, err, out)
	}
	// --instance picks one.
	_, out, _ = runCLI(t, "status", "--dry-run", "--json", "--instance", "relay2")
	if err := json.Unmarshal([]byte(out), &one); err != nil || one.Instance != "relay2" || one.Relay.Nickname != "SecondRelay" {
		t.Errorf("--instance relay2: %q %v\n%s", one.Instance, err, out)
	}
}

func TestStatusAllSingleRelayIsStillAnArray(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1)))
	_, out, _ := runCLI(t, "status", "--dry-run", "--all", "--json")
	if reports := decodeReports(t, out); len(reports) != 1 || reports[0].Instance != "default" {
		t.Errorf("reports = %+v", reports)
	}
	// Text for a single relay has no instance header, as before.
	_, out, _ = runCLI(t, "status", "--dry-run", "--all")
	if strings.Contains(out, "Instance") || !strings.HasPrefix(out, "Relay        FixtureRelay") {
		t.Errorf("single-relay text:\n%s", out)
	}
}

func TestStatusAllPrometheusAndText(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", multiRoot(t, true))

	code, out, _ := runCLI(t, "status", "--dry-run", "--all", "--format", "prometheus")
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{
		"# TYPE tor_relay_setup_up gauge\ntor_relay_setup_up{tor_instance=\"default\"} 1\ntor_relay_setup_up{tor_instance=\"relay2\"} 1\n",
		`tor_relay_setup_info{tor_instance="relay2",version="0.4.9.3",nickname="SecondRelay",fingerprint=""} 1`,
		`tor_relay_setup_listener{tor_instance="relay2",family="ipv4"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "# TYPE tor_relay_setup_warnings gauge") != 1 {
		t.Errorf("metric families repeat:\n%s", out)
	}

	code, out, _ = runCLI(t, "status", "--dry-run", "--all")
	if code != 0 {
		t.Errorf("text exit %d", code)
	}
	for _, want := range []string{
		"Instance     default (/etc/tor/torrc)\nRelay        FixtureRelay",
		"\n\nInstance     relay2 (/etc/tor/instances/relay2/torrc)\nRelay        SecondRelay (guard/middle)",
		"Service      ✓ tor@relay2",
		"Listener     ✓ TCP 9002",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}

	// One unhealthy instance makes the whole report exit 1.
	if err := os.WriteFile(filepath.Join(os.Getenv("TOR_RELAY_SETUP_ROOT"), "etc/tor/instances/relay2/torrc"), []byte(strings.Replace(relay2Torrc, "9002", "9003", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "status", "--dry-run", "--all", "--json")
	if code != 1 {
		t.Errorf("exit %d with relay2 not listening\n%s", code, out)
	}
	if code, _, _ := runCLI(t, "status", "--dry-run", "--all", "--format", "prometheus"); code != 0 {
		t.Errorf("prometheus exit %d, want 0", code)
	}
}

func TestOnlyNamedInstance(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", multiRoot(t, false))
	// status without --instance reports the only relay there is.
	_, out, _ := runCLI(t, "status", "--dry-run", "--json")
	var r status.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Instance != "relay2" {
		t.Errorf("status --json = %q %v", r.Instance, err)
	}
	// The default command sees a configured relay: console, not setup.
	code, out, errOut := runCLI(t, "--dry-run", "--plain")
	if code != 0 || !strings.Contains(out, "Instance     relay2 (/etc/tor/instances/relay2/torrc)") || !strings.Contains(out, "Relay        SecondRelay") {
		t.Errorf("exit %d, stderr %q, output:\n%s", code, errOut, out)
	}
	// The default instance on its own reports that it is not configured.
	_, out, _ = runCLI(t, "status", "--dry-run", "--instance", "default")
	if !strings.Contains(out, "No relay is configured in /etc/tor/torrc") {
		t.Errorf("--instance default:\n%s", out)
	}
}

func TestInstanceUsageErrors(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"--all outside status", []string{"console", "--all"}, "--all is only used with status"},
		{"--all with --instance", []string{"status", "--all", "--instance", "relay2"}, "--all conflicts with --instance"},
		{"invalid instance name", []string{"status", "--instance", "relay-2"}, `invalid instance name "relay-2"`},
		{"--instance with uninstall", []string{"uninstall", "--instance", "relay2"}, "--instance is only used with status, console, setup and apply"},
		{"--instance with --host", []string{"apply", "--config", "x.toml", "--host", "relay-1", "--instance", "relay2"}, "--instance cannot be combined with --host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, stderr %q; want 2 and %q", code, errOut, tt.want)
			}
			if out != "" {
				t.Errorf("unexpected stdout %q", out)
			}
		})
	}
}

func TestApplyInstanceOverride(t *testing.T) {
	stubPath(t)
	root := fixtureRoot(t, "")
	osRelease := "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOR_RELAY_SETUP_ROOT", root)
	cfg := filepath.Join(t.TempDir(), "relay.toml")
	toml := "[relay]\nnickname = \"Second\"\ncontact = \"ops@example.org\"\nor_port = 9002\n[bandwidth]\nmode = \"none\"\n"
	if err := os.WriteFile(cfg, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	// The plan is printed before the (refused, non-interactive) confirmation.
	_, out, _ := runCLI(t, "apply", "--dry-run", "--config", cfg, "--instance", "relay2")
	for _, want := range []string{"tor-instance-create relay2", "/etc/tor/instances/relay2/torrc", "Enable and restart tor@relay2"} {
		if !strings.Contains(out, want) {
			t.Errorf("planned changes lack %q:\n%s", want, out)
		}
	}
}
