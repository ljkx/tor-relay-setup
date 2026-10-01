package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/remote"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/update"
)

func TestHelpListsNewCommands(t *testing.T) {
	clearRoot(t)
	code, out, _ := runCLI(t, "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"tor-relay-setup apply --config FILE --host [user@]HOST [--host ...] [--keep-going]",
		"tor-relay-setup status --format text|json|prometheus",
		"tor-relay-setup uninstall [--yes]",
		"tor-relay-setup self-update [--check]",
		"tor-relay-setup status --format prometheus > /var/lib/prometheus/node-exporter/tor_relay.prom",
		"10 self-update --check: a newer release is available",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestNewUsageErrors(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"--host without apply", []string{"status", "--host", "relay-1"}, "--host is only used with apply"},
		{"--host with setup", []string{"setup", "--dry-run", "--host", "relay-1"}, "--host is only used with apply"},
		{"apply --host without --config", []string{"apply", "--host", "relay-1"}, "apply needs --config FILE"},
		{"option injection as host", []string{"apply", "--config", "x.toml", "--host", "-oProxyCommand=sh"}, "is not an ssh destination"},
		{"host with a space", []string{"apply", "--config", "x.toml", "--host", "relay 1"}, "is not an ssh destination"},
		{"--keep-going without --host", []string{"apply", "--config", "x.toml", "--keep-going"}, "--keep-going needs --host"},
		{"unknown format", []string{"status", "--format", "xml"}, `unknown --format "xml"`},
		{"conflicting formats", []string{"status", "--json", "--format", "prometheus"}, "--json conflicts with --format prometheus"},
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

func TestStatusPrometheusFromFixture(t *testing.T) {
	stubPath(t)
	t.Setenv("STUB_SYSTEMCTL_EXIT", "3") // inactive: the relay needs attention
	t.Setenv("TOR_RELAY_SETUP_ROOT", fixtureRoot(t, strings.Replace(fixtureTorrc, "FAMILY", famA, 1)))

	code, out, errOut := runCLI(t, "status", "--dry-run", "--format", "prometheus")
	if code != 0 {
		t.Errorf("exit %d, want 0: the problems are in the metrics (stderr %q)", code, errOut)
	}
	for _, want := range []string{
		"# TYPE tor_relay_setup_up gauge\ntor_relay_setup_up 1\n",
		`tor_relay_setup_info{version="0.4.9.3",nickname="FixtureRelay",fingerprint=""} 1`,
		"tor_relay_setup_service_active 0\n",
		`tor_relay_setup_listener{family="ipv4"} 1`,
		`tor_relay_setup_reachable{family="ipv4"} 1`,
		"tor_relay_setup_family_ids 1\n",
		"tor_relay_setup_family_keys_missing 0\n",
		"tor_relay_setup_warnings 1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "directory_") {
		t.Errorf("no fingerprint, so no Tor Metrics gauges:\n%s", out)
	}

	// --format json is --json.
	_, viaFormat, _ := runCLI(t, "status", "--dry-run", "--format", "json")
	_, viaFlag, _ := runCLI(t, "status", "--dry-run", "--json")
	var a, b status.Report
	if err := json.Unmarshal([]byte(viaFormat), &a); err != nil {
		t.Fatalf("--format json: %v\n%s", err, viaFormat)
	}
	if err := json.Unmarshal([]byte(viaFlag), &b); err != nil {
		t.Fatal(err)
	}
	a.CollectedAt = b.CollectedAt
	if !reflect.DeepEqual(a, b) {
		t.Errorf("--format json and --json differ:\n%s\n%s", viaFormat, viaFlag)
	}
	if code, out, _ := runCLI(t, "status", "--dry-run", "--format", "text"); code != 1 || !strings.Contains(out, "Service      ✗ tor@default") {
		t.Errorf("--format text: exit %d\n%s", code, out)
	}
}

// fakeUpdater points self-update at a fake GitHub serving latestTag.
func fakeUpdater(t *testing.T, latestTag string, dpkgOwns bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/releases/latest" && latestTag != "" {
			fmt.Fprintf(w, `{"tag_name":%q}`, latestTag)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	exe := filepath.Join(t.TempDir(), "tor-relay-setup")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := newUpdater
	t.Cleanup(func() { newUpdater = orig })
	newUpdater = func(current string, out io.Writer, dryRun bool) *update.Updater {
		u := update.New(current, out, dryRun)
		u.HTTP = srv.Client()
		u.BaseAPI, u.BaseDownload = srv.URL+"/api", srv.URL+"/dl"
		u.GOOS, u.GOARCH = "linux", "amd64"
		u.Executable = func() (string, error) { return exe, nil }
		u.LookPath = func(string) (string, error) { return "", errors.New("not found") }
		u.Run = func(_ context.Context, c host.Command) (host.Result, error) {
			if c.Name == "dpkg-query" && dpkgOwns {
				return host.Result{}, nil
			}
			return host.Result{ExitCode: 1}, &host.ExitError{Command: c.String(), ExitCode: 1}
		}
		return u
	}
}

func setVersion(t *testing.T, v string) {
	t.Helper()
	orig := version
	version = v
	t.Cleanup(func() { version = orig })
}

func TestSelfUpdateCheckExitCodes(t *testing.T) {
	clearRoot(t)
	tests := []struct {
		current, latest string
		code            int
		want            string
	}{
		{"v3.0.0", "v3.1.0", 10, "current  v3.0.0\nlatest   v3.1.0\nAn update is available: sudo tor-relay-setup self-update\n"},
		{"v3.1.0", "v3.1.0", 0, "current  v3.1.0\nlatest   v3.1.0\nUp to date.\n"},
		{"dev", "v3.1.0", 10, "current  dev (not a release build; the version is unknown)\nlatest   v3.1.0\nThe latest release may be newer"},
	}
	for _, tt := range tests {
		fakeUpdater(t, tt.latest, false)
		setVersion(t, tt.current)
		code, out, errOut := runCLI(t, "self-update", "--check")
		if code != tt.code || !strings.HasPrefix(out, tt.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d and %q", tt.current, code, out, errOut, tt.code, tt.want)
		}
	}

	fakeUpdater(t, "", false) // the API fails
	if code, _, errOut := runCLI(t, "self-update", "--check"); code != 1 || !strings.Contains(errOut, "error: look up the latest release") {
		t.Errorf("API failure: exit %d, stderr %q", code, errOut)
	}
}

func TestSelfUpdateRefusesDebianPackage(t *testing.T) {
	clearRoot(t)
	fakeUpdater(t, "v3.1.0", true)
	setVersion(t, "v3.0.0")
	code, _, errOut := runCLI(t, "self-update")
	want := "error: installed from the .deb package — update with: sudo apt install ./tor-relay-setup_3.1.0_amd64.deb (or apt upgrade when using the apt repository)"
	if code != 1 || !strings.Contains(errOut, want) {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	// Up to date: nothing to refuse.
	setVersion(t, "v3.1.0")
	if code, out, _ := runCLI(t, "self-update"); code != 0 || !strings.Contains(out, "is up to date") {
		t.Errorf("up to date: exit %d, %q", code, out)
	}
}

// fakeFleet routes apply --host to a Fake host that answers like a relay.
func fakeFleet(t *testing.T) *host.Fake {
	t.Helper()
	fake := host.NewFake()
	fake.Handler = func(c host.Command) (host.Result, error) {
		script := c.Args[len(c.Args)-1]
		switch {
		case c.Name == "ssh" && strings.Contains(script, "TRS-ARCH"):
			return host.Result{Output: "TRS-ARCH x86_64\nTRS-UID 0\nTRS-TMP /tmp/tor-relay-setup.x\n"}, nil
		case c.Name == "ssh" && strings.Contains(script, "apply --config"):
			return host.Result{Output: "Dry run complete. Nothing was changed.\n"}, nil
		}
		return host.Result{}, nil
	}
	exe := filepath.Join(t.TempDir(), "tor-relay-setup")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := newFleet
	t.Cleanup(func() { newFleet = orig })
	newFleet = func(out io.Writer) *remote.Fleet {
		f := remote.New(out)
		f.Host, f.GOOS, f.GOARCH = fake, "linux", "amd64"
		f.Executable = func() (string, error) { return exe, nil }
		return f
	}
	return fake
}

func TestApplyRemote(t *testing.T) {
	clearRoot(t)
	fake := fakeFleet(t)
	cfg := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(cfg, []byte("[relay]\nnickname = \"Fleet\"\ncontact = \"ops@example.org\"\n[bandwidth]\nmonthly_quota = \"10TB\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "apply", "--dry-run", "--config", cfg, "--host", "root@relay-1", "--host", "relay-2")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{"==> [1/2] root@relay-1", "[relay-2] Dry run complete.", "Summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !fake.Ran("ssh", "--yes --plain --dry-run") || !fake.Ran("scp", "relay-2:/tmp/tor-relay-setup.x/") {
		t.Errorf("commands:\n%s", strings.Join(fake.CommandLines(), "\n"))
	}

	// A failing host: exit 1 with the count.
	fake.Handler = func(c host.Command) (host.Result, error) {
		return host.Result{ExitCode: 255}, &host.ExitError{ExitCode: 255}
	}
	code, _, errOut = runCLI(t, "apply", "--config", cfg, "--host", "relay-1", "--host", "relay-2", "--keep-going")
	if code != 1 || !strings.Contains(errOut, "error: 2 of 2 relays failed, 0 skipped") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestRemoteApplyNeedsNoLocalRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	clearRoot(t)
	fakeFleet(t)
	code, _, errOut := runCLI(t, "apply", "--config", "missing.toml", "--host", "relay-1")
	if strings.Contains(errOut, "must run as root") || code != 1 {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func uninstallFake(t *testing.T, exe string, dpkgOwns bool) *host.Fake {
	t.Helper()
	orig := executable
	t.Cleanup(func() { executable = orig })
	executable = func() (string, error) { return exe, nil }
	fake := host.NewFake()
	fake.Files[exe] = []byte("bin")
	fake.Files["/var/lib/tor-relay-setup/state.json"] = []byte("{}")
	fake.Dirs["/var/lib/tor-relay-setup"] = true
	fake.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "dpkg-query" && dpkgOwns {
			return host.Result{Output: "tor-relay-setup: " + exe}, nil
		}
		return host.Result{ExitCode: 1}, &host.ExitError{ExitCode: 1}
	}
	return fake
}

func TestUninstallRemovesProgram(t *testing.T) {
	const exe = "/opt/trs-test/tor-relay-setup"
	tests := []struct {
		name     string
		opt      uninstallOptions
		dry      bool
		dpkg     bool
		removed  bool
		wantText string
	}{
		{name: "yes", opt: uninstallOptions{Yes: true}, removed: true, wantText: "removed " + exe},
		{name: "confirmed", opt: uninstallOptions{Terminal: true, In: strings.NewReader("y\n")}, removed: true, wantText: "Remove " + exe + " too? [y/N] removed " + exe},
		{name: "declined", opt: uninstallOptions{Terminal: true, In: strings.NewReader("\n")}, wantText: "Kept " + exe},
		{name: "no terminal", opt: uninstallOptions{In: strings.NewReader("y\n")}, wantText: "To remove this program too: sudo rm " + exe},
		{name: "dry run", opt: uninstallOptions{Yes: true}, dry: true, wantText: "would remove " + exe},
		{name: "deb package", opt: uninstallOptions{Yes: true}, dpkg: true, wantText: "remove it with: sudo apt remove tor-relay-setup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := uninstallFake(t, exe, tt.dpkg)
			fake.Dry = tt.dry
			var out bytes.Buffer
			tt.opt.Out = &out
			if err := uninstall(context.Background(), fake, tt.opt); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.wantText) || !strings.Contains(out.String(), "Tor, torrc, keys, and firewall rules were left alone.") {
				t.Errorf("output:\n%s\nwant %q", out.String(), tt.wantText)
			}
			if _, still := fake.Files[exe]; still == tt.removed {
				t.Errorf("program present = %v, want removed = %v", still, tt.removed)
			}
			if !fake.Ran("dpkg-query -S " + exe) {
				t.Error("dpkg ownership was not checked")
			}
			if !tt.dry {
				if _, ok := fake.Files["/var/lib/tor-relay-setup/state.json"]; ok {
					t.Error("state was not removed")
				}
			}
		})
	}
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(strings.NewReader("")) {
		t.Error("a strings.Reader is no terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file is no terminal")
	}
}
