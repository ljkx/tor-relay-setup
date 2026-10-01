package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// These tests change process-wide environment variables with t.Setenv, so
// none of them run in parallel.

var famA = strings.Repeat("A", 42) + "a"

// runCLI runs the command with a clean TOR_RELAY_SETUP_ROOT unless the test
// set one itself.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

func clearRoot(t *testing.T) { t.Setenv("TOR_RELAY_SETUP_ROOT", "") }

func TestHelp(t *testing.T) {
	clearRoot(t)
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"setup", "--help"}, {"help", "--dry-run"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 0 {
			t.Errorf("%q: exit %d, want 0 (stderr %q)", args, code, errOut)
		}
		for _, want := range []string{"Usage:", "tor-relay-setup apply --config FILE", "--dry-run", "status [--json]"} {
			if !strings.Contains(out, want) {
				t.Errorf("%q: usage lacks %q:\n%s", args, want, out)
			}
		}
		if errOut != "" {
			t.Errorf("%q: unexpected stderr %q", args, errOut)
		}
	}
}

func TestVersion(t *testing.T) {
	clearRoot(t)
	for _, args := range [][]string{{"version"}, {"--version"}, {"status", "--version"}} {
		code, out, _ := runCLI(t, args...)
		if code != 0 || !strings.HasPrefix(out, "tor-relay-setup ") || !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
			t.Errorf("%q: exit %d, output %q; want one version line", args, code, out)
		}
	}
	if v := buildVersion(); v == "" {
		t.Error("buildVersion() is empty")
	}
}

func TestUsageErrors(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown command", []string{"frobnicate"}, `unknown command "frobnicate"`},
		{"unknown flag", []string{"--bogus"}, "flag provided but not defined: -bogus"},
		{"unknown flag after a command", []string{"status", "--frob"}, "-frob"},
		{"unexpected argument", []string{"status", "extra"}, `unexpected argument "extra"`},
		{"extra argument after the command", []string{"status", "extra"}, `unexpected argument "extra"`},
		{"apply without --config", []string{"apply", "--dry-run"}, "apply needs --config FILE"},
		{"missing flag value", []string{"apply", "--config"}, "flag needs an argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != 2 {
				t.Errorf("exit %d, want 2 (stdout %q, stderr %q)", code, out, errOut)
			}
			if !strings.Contains(errOut, tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", errOut, tt.want)
			}
			if out != "" {
				t.Errorf("usage errors should not write to stdout, got %q", out)
			}
		})
	}
}

func TestRootOverrideNeedsDryRun(t *testing.T) {
	t.Setenv("TOR_RELAY_SETUP_ROOT", t.TempDir())
	for _, args := range [][]string{{"status"}, {"status", "--json"}, {"setup"}, {"apply", "--config", "relay.toml"}, {"uninstall"}} {
		code, _, errOut := runCLI(t, args...)
		if code != 2 || !strings.Contains(errOut, "TOR_RELAY_SETUP_ROOT is only allowed together with --dry-run") {
			t.Errorf("%q: exit %d, stderr %q; want 2 and the refusal", args, code, errOut)
		}
	}
	// Help and version never touch the machine.
	if code, _, _ := runCLI(t, "version"); code != 0 {
		t.Errorf("version with TOR_RELAY_SETUP_ROOT: exit %d", code)
	}
}

func TestNonRootIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: these commands would really change the system")
	}
	clearRoot(t)
	for _, args := range [][]string{{}, {"setup"}, {"apply", "--config", "relay.toml"}, {"console"}, {"uninstall"}} {
		code, out, errOut := runCLI(t, args...)
		if code != 1 || !strings.Contains(errOut, "must run as root") || !strings.Contains(errOut, "--dry-run") {
			t.Errorf("%q: exit %d, stderr %q; want 1 and the root message", args, code, errOut)
		}
		if out != "" {
			t.Errorf("%q: unexpected stdout %q", args, out)
		}
	}
}

func TestApplyConfigErrors(t *testing.T) {
	clearRoot(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name, path, want string
	}{
		{"missing file", filepath.Join(dir, "absent.toml"), "no such file"},
		{"unknown key", write("typo.toml", "[relay]\nnickame = \"X\"\n"), "unknown config keys: relay.nickame"},
		{"invalid answers", write("invalid.toml", "[relay]\nnickname = \"bad name\"\n"), "relay.nickname"},
		{"broken TOML", write("broken.toml", "[relay\n"), "parse config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, "apply", "--dry-run", "--yes", "--config", tt.path)
			if code != 1 || !strings.HasPrefix(errOut, "error: ") || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, stderr %q; want 1 and %q", code, errOut, tt.want)
			}
			if strings.Contains(out, "Planned changes") {
				t.Errorf("an invalid config reached the plan:\n%s", out)
			}
		})
	}
}

// fixtureRoot builds a relay file tree for TOR_RELAY_SETUP_ROOT. It has no
// fingerprint file, so status never asks Tor Metrics over the network.
func fixtureRoot(t *testing.T, torrc string) string {
	t.Helper()
	root := t.TempDir()
	key := make([]byte, 96)
	copy(key, family.KeyHeader)
	files := map[string][]byte{
		"var/lib/tor/keys/fam.secret_family_key": key,
		"var/lib/tor/keys/fam.public_family_id":  []byte(famA + "\n"),
		// 0x2329 = 9001 in LISTEN (0A) state.
		"proc/net/tcp": []byte("  sl  local_address rem_address   st\n   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n"),
	}
	if torrc != "" {
		files["etc/tor/torrc"] = []byte(torrc)
	}
	for p, data := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const fixtureTorrc = `Nickname FixtureRelay
ContactInfo "ops@example.org"
FamilyId ` + "FAMILY" + `
ORPort 9001
SocksPort 0
ExitRelay 0
Sandbox 1
`

// stubPath replaces PATH with stub tor, systemctl and journalctl scripts,
// so status never runs the real programs. STUB_SYSTEMCTL_EXIT picks the
// exit code of `systemctl is-active`.
func stubPath(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	stubs := map[string]string{
		"tor":        "#!/bin/sh\necho 'Tor version 0.4.9.3.'\n",
		"systemctl":  "#!/bin/sh\nexit ${STUB_SYSTEMCTL_EXIT:-0}\n",
		"journalctl": "#!/bin/sh\necho '2026-03-04T05:10:00+0000 relay Tor[812]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent.'\n",
	}
	for name, script := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("STUB_SYSTEMCTL_EXIT", "0")
}

func TestStatusJSONFromFixture(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1)))

	code, out, errOut := runCLI(t, "status", "--dry-run", "--json")
	if code != 0 {
		t.Errorf("exit %d, want 0 for a healthy relay (stderr %q)\n%s", code, errOut, out)
	}
	var r status.Report
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("status --json is not a Report: %v\n%s", err, out)
	}
	if !r.Tor.Installed || r.Tor.Version != "0.4.9.3" || !r.Tor.Supported {
		t.Errorf("tor = %+v", r.Tor)
	}
	if r.Service.Unit != "tor@default" || !r.Service.Active {
		t.Errorf("service = %+v", r.Service)
	}
	if !r.Relay.Configured || r.Relay.Nickname != "FixtureRelay" || r.Relay.Contact != "ops@example.org" || r.Relay.ORPort != 9001 || !r.Relay.Sandbox || r.Relay.Exit {
		t.Errorf("relay = %+v", r.Relay)
	}
	if !r.Listener.IPv4 || r.Listener.IPv6 {
		t.Errorf("listener = %+v", r.Listener)
	}
	if !r.Reachability.IPv4 || !r.Reachability.Seen || r.Reachability.Failed {
		t.Errorf("reachability = %+v", r.Reachability)
	}
	if !reflect.DeepEqual(r.Family.IDs, []string{famA}) || len(r.Family.MissingKeys) != 0 || len(r.Family.Keys) != 1 || r.Family.KeyDirectory != "/var/lib/tor/keys" {
		t.Errorf("family = %+v", r.Family)
	}
	if r.Relay.Fingerprint != "" || r.Directory != nil || r.DirectoryError != "" {
		t.Errorf("no fingerprint should mean no directory lookup: %q %v %q", r.Relay.Fingerprint, r.Directory, r.DirectoryError)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings = %q", r.Warnings)
	}
	for _, key := range []string{`"collected_at"`, `"or_port": 9001`, `"legacy_myfamily": 0`} {
		if !strings.Contains(out, key) {
			t.Errorf("JSON lacks %s:\n%s", key, out)
		}
	}
}

func TestStatusTextFromFixture(t *testing.T) {
	stubPath(t)
	t.Setenv("STUB_SYSTEMCTL_EXIT", "3") // inactive
	// A FamilyId without a key on disk.
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", strings.Repeat("B", 43), 1)))

	code, out, errOut := runCLI(t, "status", "--dry-run")
	if code != 1 {
		t.Errorf("exit %d, want 1 when the relay needs attention (stderr %q)", code, errOut)
	}
	for _, want := range []string{
		"Relay        FixtureRelay (guard/middle)",
		"tor          ✓ 0.4.9.3",
		"Service      ✗ tor@default",
		"Listener     ✓ TCP 9001",
		"Reachability ✓ reachable from outside",
		"Family       " + strings.Repeat("B", 43),
		"! tor@default is not running",
		"! no family key installed for FamilyId " + strings.Repeat("B", 43),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Fingerprint") || strings.Contains(out, "Tor Metrics") {
		t.Errorf("no fingerprint, so no fingerprint or Tor Metrics line:\n%s", out)
	}
}

func TestStatusWithoutRelay(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, ""))
	code, out, _ := runCLI(t, "status", "--dry-run")
	if code != 0 || !strings.Contains(out, "No relay is configured in /etc/tor/torrc") {
		t.Errorf("exit %d, output %q", code, out)
	}
}

func TestDefaultCommandShowsStatusWithoutTerminal(t *testing.T) {
	stubPath(t)
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1)))
	code, out, errOut := runCLI(t, "--dry-run", "--plain")
	if code != 0 || !strings.Contains(out, "Relay        FixtureRelay") {
		t.Errorf("exit %d, stderr %q, output:\n%s", code, errOut, out)
	}

	t.Setenv("STUB_SYSTEMCTL_EXIT", "3")
	code, _, errOut = runCLI(t, "console", "--dry-run", "--plain")
	if code != 1 || !strings.Contains(errOut, "error: the relay needs attention") {
		t.Errorf("console on an unhealthy relay: exit %d, stderr %q", code, errOut)
	}
}

func TestUninstallDryRunKeepsFiles(t *testing.T) {
	clearRoot(t)
	root := fixtureRoot(t, "")
	state := filepath.Join(root, "var/lib/tor-relay-setup")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOR_RELAY_SETUP_ROOT", root)

	code, out, errOut := runCLI(t, "uninstall", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "/var/lib/tor-relay-setup") || strings.Contains(out, "/var/log/tor-relay-setup") {
		t.Errorf("output should mention only the existing state directory:\n%s", out)
	}
	if !strings.Contains(out, "Tor, torrc, keys, and firewall rules were left alone") {
		t.Errorf("output lacks the reassurance:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "state.json")); err != nil {
		t.Errorf("a dry-run uninstall removed files: %v", err)
	}
}

func TestFlagsBeforeCommand(t *testing.T) {
	var out, errOut strings.Builder
	code := run([]string{"--json", "version"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "tor-relay-setup") {
		t.Fatalf("--json version: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}
