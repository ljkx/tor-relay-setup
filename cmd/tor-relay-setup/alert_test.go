package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/alert"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

func TestAlertArgs(t *testing.T) {
	tests := []struct {
		args []string
		want []string
		ok   bool
	}{
		{[]string{"alert", "run"}, []string{"run"}, true},
		{[]string{"--dry-run", "alert", "run", "--config", "x"}, []string{"run", "--config", "x", "--dry-run"}, true},
		{[]string{"--plain", "-dry-run", "alert"}, []string{"-dry-run"}, true},
		{[]string{"status"}, nil, false},
		{[]string{"--json", "alert"}, nil, false}, // other global flags keep the main parser's errors
		{[]string{}, nil, false},
		{[]string{"--dry-run"}, nil, false},
	}
	for _, tt := range tests {
		got, ok := alertArgs(tt.args)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("alertArgs(%q) = %q, %v; want %q, %v", tt.args, got, ok, tt.want, tt.ok)
		}
	}
}

func TestAlertUsage(t *testing.T) {
	clearRoot(t)
	for _, args := range [][]string{{"alert", "--help"}, {"alert", "help"}, {"alert", "run", "-h"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 0 || !strings.Contains(out, "tor-relay-setup alert install [--every 5m]") || errOut != "" {
			t.Errorf("%q: exit %d, stderr %q", args, code, errOut)
		}
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"alert"}, "alert needs a command"},
		{"unknown subcommand", []string{"alert", "frob"}, `unknown alert command "frob"`},
		{"extra argument", []string{"alert", "run", "extra"}, `unexpected argument "extra"`},
		{"--every outside install", []string{"alert", "run", "--every", "5m"}, "--every is only used with alert install"},
		{"bad --every", []string{"alert", "install", "--every", "often"}, "invalid value"},
		{"unknown flag", []string{"alert", "test", "--bogus"}, "-bogus"},
		{"relative config for install", []string{"alert", "install", "--config", "alerts.toml"}, "absolute --config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.want) || out != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want 2 and %q", code, out, errOut, tt.want)
			}
		})
	}
}

func TestAlertOverridesNeedDryRun(t *testing.T) {
	t.Setenv("TOR_RELAY_SETUP_ROOT", t.TempDir())
	code, _, errOut := runCLI(t, "alert", "run")
	if code != 2 || !strings.Contains(errOut, "TOR_RELAY_SETUP_ROOT is only allowed together with --dry-run") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// hookServer records webhook bodies.
func hookServer(t *testing.T) (url string, bodies func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

func writeAlertConfig(t *testing.T, root, body string) string {
	t.Helper()
	p := filepath.Join(root, "etc/tor-relay-setup/alerts.toml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAlertRunDryRunFromFixture(t *testing.T) {
	stubPath(t)
	t.Setenv("STUB_SYSTEMCTL_EXIT", "3") // tor is down
	root := fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1))
	t.Setenv("TOR_RELAY_SETUP_ROOT", root)
	url, bodies := hookServer(t)
	writeAlertConfig(t, root, "[[webhook]]\nurl = \""+url+"/hook\"\n")

	for _, args := range [][]string{{"alert", "run", "--dry-run"}, {"--dry-run", "alert", "run"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 0 {
			t.Fatalf("%q: exit %d, stderr %q\n%s", args, code, errOut, out)
		}
		for _, want := range []string{
			"Dry run: would send to 1 notifier(s), state not updated.",
			"Subject: FixtureRelay: [CRITICAL] tor@default is not running",
			"-> webhook[0] (127.0.0.1)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%q: output lacks %q:\n%s", args, want, out)
			}
		}
	}
	if len(bodies()) != 0 {
		t.Error("a dry run sent a notification")
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/tor-relay-setup/alert-state.json")); err == nil {
		t.Error("a dry run wrote the state file")
	}

	// A healthy relay has nothing to send.
	t.Setenv("STUB_SYSTEMCTL_EXIT", "0")
	if code, out, _ := runCLI(t, "alert", "run", "--dry-run"); code != 0 || !strings.Contains(out, "Nothing to send (0 open problem(s)).") {
		t.Errorf("healthy: exit %d\n%s", code, out)
	}
}

func TestAlertConfigProblems(t *testing.T) {
	stubPath(t)
	root := fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1))
	t.Setenv("TOR_RELAY_SETUP_ROOT", root)
	tests := []struct {
		name, config, want string
	}{
		{"missing", "", "error: no alert configuration at /etc/tor-relay-setup/alerts.toml"},
		{"no notifier", "min_severity = \"info\"\n", "configures no notifier"},
		{"unknown key", "[[ntfy]]\nurl = \"https://ntfy.sh/x\"\ntopic = \"y\"\n", "unknown alert config keys: ntfy.topic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(root, "etc/tor-relay-setup/alerts.toml")
			_ = os.Remove(p)
			if tt.config != "" {
				writeAlertConfig(t, root, tt.config)
			}
			code, _, errOut := runCLI(t, "alert", "run", "--dry-run")
			if code != 1 || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, stderr %q; want 1 and %q", code, errOut, tt.want)
			}
		})
	}
}

func TestAlertTestSends(t *testing.T) {
	clearRoot(t)
	url, bodies := hookServer(t)
	cfg := filepath.Join(t.TempDir(), "alerts.toml")
	if err := os.WriteFile(cfg, []byte("name = \"fra-1\"\n[[webhook]]\nurl = \""+url+"/hook\"\nformat = \"slack\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "alert", "test", "--config", cfg)
	if code != 0 || !strings.Contains(out, "sent 1 alert(s) to webhook[0] (127.0.0.1)") {
		t.Fatalf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	if !strings.Contains(errOut, "is readable by other users and may hold tokens: chmod 600") {
		t.Errorf("no permission warning: %q", errOut)
	}
	got := bodies()
	if len(got) != 1 || !strings.Contains(got[0], `"text":"fra-1: [TEST] test notification`) {
		t.Errorf("bodies %q", got)
	}

	// A notifier that fails makes the command fail.
	if err := os.WriteFile(cfg, []byte("[[webhook]]\nurl = \"http://127.0.0.1:1/hook\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCLI(t, "alert", "test", "--config", cfg)
	if code != 1 || !strings.Contains(errOut, "error: 1 of 1 notifiers failed") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestAlertInstallDryRun(t *testing.T) {
	root := fixtureRoot(t, "")
	t.Setenv("TOR_RELAY_SETUP_ROOT", root)
	orig := executable
	t.Cleanup(func() { executable = orig })
	executable = func() (string, error) { return "/usr/local/bin/tor-relay-setup", nil }

	code, out, errOut := runCLI(t, "alert", "install", "--dry-run", "--every", "10m")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(errOut, "warning: no alert configuration") {
		t.Errorf("stderr %q", errOut)
	}
	for _, want := range []string{
		"would write /etc/systemd/system/tor-relay-setup-alert.service:",
		"ExecStart=/usr/local/bin/tor-relay-setup alert run --config /etc/tor-relay-setup/alerts.toml",
		"would write /etc/systemd/system/tor-relay-setup-alert.timer:",
		"OnUnitActiveSec=600s",
		"would run systemctl enable --now tor-relay-setup-alert.timer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/tor-relay-setup-alert.service")); err == nil {
		t.Error("a dry run wrote the unit")
	}

	code, out, _ = runCLI(t, "alert", "uninstall", "--dry-run")
	if code != 0 || !strings.Contains(out, "The alert timer is not installed.") {
		t.Errorf("uninstall: exit %d\n%s", code, out)
	}
	if code, _, errOut := runCLI(t, "alert", "install", "--dry-run", "--every", "10s"); code != 1 || !strings.Contains(errOut, "--every must be between 1m0s and 24h0m0s") {
		t.Errorf("short interval: exit %d, %q", code, errOut)
	}
}

func TestAlertNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: alert run would check the real relay")
	}
	clearRoot(t)
	for _, sub := range []string{"run", "install", "uninstall"} {
		code, _, errOut := runCLI(t, "alert", sub)
		if code != 1 || !strings.Contains(errOut, "must run as root") {
			t.Errorf("%s: exit %d, stderr %q", sub, code, errOut)
		}
	}
}

func TestAlertStatePathPerInstance(t *testing.T) {
	if got := alertStatePath(relay.DefaultInstance()); got != alert.DefaultStatePath {
		t.Errorf("default = %q", got)
	}
	inst, _ := relay.Named("relay2")
	if got := alertStatePath(inst); got != "/var/lib/tor-relay-setup/alert-state-relay2.json" {
		t.Errorf("relay2 = %q", got)
	}
}
