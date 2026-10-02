package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
)

var (
	testID  = strings.Repeat("F", 42) + "a"
	testKey = func() []byte {
		k := make([]byte, 96)
		copy(k, family.KeyHeader)
		for i := len(family.KeyHeader); i < len(k); i++ {
			k[i] = byte(i)
		}
		return k
	}()
)

const baseConfig = `[relay]
nickname = "FleetRelay"
contact = "ops@example.org"

[bandwidth]
monthly_quota = "10TB"
`

const generateConfig = baseConfig + `
[family]
mode = "generate"
key_name = "fleet"
`

// sim plays a set of remote hosts behind ssh and scp.
type sim struct {
	mu        sync.Mutex
	arch      map[string]string // uname -m, default x86_64
	user      map[string]bool   // non-root hosts
	noSudo    map[string]bool
	failApply map[string]bool
	badKey    bool
	uploads   map[string]map[string][]byte // host → file name → content
	calls     []string                     // "host kind"
}

func newSim() *sim {
	return &sim{arch: map[string]string{}, user: map[string]bool{}, noSudo: map[string]bool{}, failApply: map[string]bool{}, uploads: map[string]map[string][]byte{}}
}

func tmpFor(dest string) string { return "/tmp/tor-relay-setup." + strings.ReplaceAll(dest, "@", "_") }

func (s *sim) handle(c host.Command) (host.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(code int, out string) (host.Result, error) {
		return host.Result{Output: out, ExitCode: code}, &host.ExitError{Command: c.String(), ExitCode: code, Output: out}
	}
	switch c.Name {
	case "scp":
		target := c.Args[len(c.Args)-1]
		dest, _, _ := strings.Cut(target, ":")
		s.calls = append(s.calls, dest+" scp")
		if s.uploads[dest] == nil {
			s.uploads[dest] = map[string][]byte{}
		}
		start := 0
		for i, a := range c.Args {
			if a == "--" {
				start = i + 1
				break
			}
		}
		for _, src := range c.Args[start : len(c.Args)-1] {
			data, err := os.ReadFile(src)
			if err != nil {
				return fail(1, err.Error())
			}
			s.uploads[dest][filepath.Base(src)] = data
		}
		return host.Result{}, nil
	case "ssh":
		dest, script := c.Args[len(c.Args)-2], c.Args[len(c.Args)-1]
		switch {
		case strings.Contains(script, "TRS-ARCH"):
			s.calls = append(s.calls, dest+" probe")
			arch := s.arch[dest]
			if arch == "" {
				arch = "x86_64"
			}
			out := "Warning: Permanently added '" + dest + "' to the list of known hosts.\nTRS-ARCH " + arch + "\n"
			if s.user[dest] {
				sudo := "yes"
				if s.noSudo[dest] {
					sudo = "no"
				}
				out += "TRS-UID 1000\nTRS-SUDO " + sudo + "\n"
			} else {
				out += "TRS-UID 0\n"
			}
			return host.Result{Output: out + "TRS-TMP " + tmpFor(dest) + "\n"}, nil
		case strings.Contains(script, "apply --config"):
			s.calls = append(s.calls, dest+" apply")
			if s.failApply[dest] {
				return fail(1, "[1/9] Checking the system\n      FAILED: boom\n")
			}
			return host.Result{Output: "[1/9] Checking the system\nRelay configured.\n"}, nil
		case strings.Contains(script, "TRS-KEY-BEGIN"):
			s.calls = append(s.calls, dest+" fetch")
			key := base64.StdEncoding.EncodeToString(testKey)
			if s.badKey {
				key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("not a key "), 10))
			}
			return host.Result{Output: "TRS-KEY-BEGIN\n" + key[:40] + "\n" + key[40:] + "\nTRS-KEY-END\nTRS-ID " + testID + "\n"}, nil
		case strings.HasPrefix(script, "sh -c 'rm -rf -- "):
			s.calls = append(s.calls, dest+" cleanup")
			return host.Result{}, nil
		}
	}
	return fail(127, "unexpected command "+c.String())
}

type fixture struct {
	sim   *sim
	fake  *host.Fake
	fleet *Fleet
	out   *bytes.Buffer
	exe   string
	dir   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "tor-relay-setup-local-build")
	if err := os.WriteFile(exe, []byte("BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fixture{sim: newSim(), fake: host.NewFake(), out: &bytes.Buffer{}, exe: exe, dir: dir}
	f.fake.Handler = f.sim.handle
	f.fleet = &Fleet{Host: f.fake, Out: f.out, Executable: func() (string, error) { return exe, nil }, GOOS: "linux", GOARCH: "amd64"}
	return f
}

func (f *fixture) config(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(f.dir, "relay.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) apply(t *testing.T, opt Options) ([]HostResult, error) {
	t.Helper()
	return f.fleet.Apply(context.Background(), opt)
}

func outcomes(results []HostResult) string {
	parts := make([]string, len(results))
	for i, r := range results {
		parts[i] = r.Host + "=" + string(r.Outcome)
	}
	return strings.Join(parts, " ")
}

func TestFleetGenerateSharesTheFamily(t *testing.T) {
	f := newFixture(t)
	f.sim.user["admin@relay-2"] = true
	cfg := f.config(t, generateConfig)
	hosts := []string{"root@relay-1", "admin@relay-2", "relay-3"}
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: hosts})
	if err != nil {
		t.Fatalf("Apply: %v\n%s", err, f.out)
	}
	if got := outcomes(results); got != "root@relay-1=ok admin@relay-2=ok relay-3=ok" {
		t.Errorf("outcomes = %s", got)
	}
	wantCalls := "root@relay-1 probe|root@relay-1 scp|root@relay-1 apply|root@relay-1 fetch|" +
		"admin@relay-2 probe|admin@relay-2 scp|admin@relay-2 apply|relay-3 probe|relay-3 scp|relay-3 apply"
	if got := strings.Join(f.sim.calls, "|"); got != wantCalls {
		t.Errorf("calls:\n%s\nwant:\n%s", got, wantCalls)
	}

	// Host 1 gets the config byte for byte and no key.
	up1 := f.sim.uploads["root@relay-1"]
	if string(up1["relay.toml"]) != generateConfig || string(up1["tor-relay-setup"]) != "BINARY" || len(up1) != 2 {
		t.Errorf("host 1 uploads: %q", keys(up1))
	}
	// Further hosts import the key fetched from host 1.
	for _, h := range hosts[1:] {
		up := f.sim.uploads[h]
		if !bytes.Equal(up["fleet.secret_family_key"], testKey) || string(up["fleet.public_family_id"]) != testID+"\n" {
			t.Errorf("%s: key files not uploaded: %q", h, keys(up))
		}
		s, err := config.Parse(up["relay.toml"])
		if err != nil {
			t.Fatalf("%s: derived config does not parse: %v\n%s", h, err, up["relay.toml"])
		}
		if s.Family.Mode != "import" || s.Family.ImportKey != tmpFor(h)+"/fleet.secret_family_key" || s.Family.FamilyID != testID {
			t.Errorf("%s: derived family = %+v", h, s.Family)
		}
		if s.Relay.Nickname != "FleetRelay" || s.Bandwidth.MonthlyQuota != "10TB" {
			t.Errorf("%s: derived config lost settings: %+v", h, s)
		}
		if err := s.Validate(); err != nil {
			t.Errorf("%s: derived config is invalid: %v", h, err)
		}
	}

	// argv: separate entries, ConnectTimeout, no host key overrides.
	for _, c := range f.fake.Commands {
		joined := strings.Join(c.Args, " ")
		if !strings.Contains(joined, "-o ConnectTimeout=10 --") || strings.Contains(joined, "StrictHostKeyChecking") || strings.Contains(joined, "BatchMode") {
			t.Errorf("unexpected options: %s", c.String())
		}
	}
	probe := f.fake.Commands[0]
	if probe.Name != "ssh" || probe.Args[3] != "root@relay-1" || !strings.HasPrefix(probe.Args[4], "sh -c '") {
		t.Errorf("probe argv = %q", probe.Args)
	}
	scp := f.fake.Commands[1]
	if scp.Name != "scp" || scp.Args[0] != "-q" || scp.Args[len(scp.Args)-1] != "root@relay-1:"+tmpFor("root@relay-1")+"/" {
		t.Errorf("scp argv = %q", scp.Args)
	}
	apply1, apply2 := f.fake.Commands[2].Args[4], f.fake.Commands[6].Args[4]
	if strings.Contains(apply1, "sudo") || !strings.Contains(apply1, `apply --config "$tmp/relay.toml" --yes --plain`) || strings.Contains(apply1, "--dry-run") {
		t.Errorf("root host apply = %s", apply1)
	}
	if !strings.Contains(apply2, `sudo -n "$tmp/tor-relay-setup" apply`) {
		t.Errorf("sudo host apply = %s", apply2)
	}

	out := f.out.String()
	for _, want := range []string{
		"==> [1/3] root@relay-1",
		"[root@relay-1] Warning: Permanently added",
		"[admin@relay-2] Relay configured.",
		"[root@relay-1] fetched FamilyId " + testID,
		"Summary:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "TRS-") || strings.Contains(out, base64.StdEncoding.EncodeToString(testKey)[:20]) {
		t.Errorf("protocol lines or the secret key leaked into the output:\n%s", out)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestFleetDryRun(t *testing.T) {
	f := newFixture(t)
	f.sim.user["relay-2"], f.sim.noSudo["relay-2"] = true, true
	cfg := f.config(t, generateConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2"}, DryRun: true})
	if err != nil {
		t.Fatalf("Apply: %v\n%s", err, f.out)
	}
	if outcomes(results) != "relay-1=ok relay-2=ok" {
		t.Errorf("outcomes = %s", outcomes(results))
	}
	for _, c := range f.sim.calls {
		if strings.HasSuffix(c, " fetch") {
			t.Errorf("a dry run fetched the family key: %q", f.sim.calls)
		}
	}
	for _, c := range f.fake.Commands {
		if c.Name == "ssh" && strings.Contains(c.Args[4], "apply --config") {
			if !strings.Contains(c.Args[4], "--yes --plain --dry-run") || strings.Contains(c.Args[4], "sudo") {
				t.Errorf("dry-run apply = %s", c.Args[4])
			}
		}
	}
	if string(f.sim.uploads["relay-2"]["relay.toml"]) != generateConfig {
		t.Error("a dry run should use the config as is on further hosts")
	}
	out := f.out.String()
	for _, want := range []string{
		"[relay-1] dry run: would fetch the new family key fleet.secret_family_key and import it on the other 1 relays",
		"[relay-2] note: no passwordless sudo; the dry run runs unprivileged",
		"[relay-2] dry run: the real run imports the family key from relay-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestFleetArchMismatchFailsFast(t *testing.T) {
	f := newFixture(t)
	f.sim.arch["relay-2"] = "aarch64"
	cfg := f.config(t, baseConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2", "relay-3"}})
	if err == nil || err.Error() != "1 of 3 relays failed, 1 skipped" {
		t.Errorf("err = %v", err)
	}
	if outcomes(results) != "relay-1=ok relay-2=failed relay-3=skipped" {
		t.Errorf("outcomes = %s", outcomes(results))
	}
	if msg := results[1].Err.Error(); !strings.Contains(msg, "CPU is aarch64") || !strings.Contains(msg, "install.sh") {
		t.Errorf("mismatch message = %q", msg)
	}
	if got := strings.Join(f.sim.calls, "|"); !strings.Contains(got, "relay-2 probe|relay-2 cleanup") || strings.Contains(got, "relay-2 scp") || strings.Contains(got, "relay-3") {
		t.Errorf("calls = %s", got)
	}
	out := f.out.String()
	if !strings.Contains(out, "relay-3  FleetRelay  skipped  stopped after an earlier failure (--keep-going continues)") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestFleetKeepGoing(t *testing.T) {
	f := newFixture(t)
	f.sim.failApply["relay-1"] = true
	f.sim.arch["relay-3"] = "arm64"
	f.fleet.GOARCH = "arm64"
	f.sim.arch["relay-1"], f.sim.arch["relay-2"] = "aarch64", "aarch64"
	cfg := f.config(t, baseConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2", "relay-3"}, KeepGoing: true})
	if err == nil || err.Error() != "1 of 3 relays failed, 0 skipped" {
		t.Errorf("err = %v", err)
	}
	if outcomes(results) != "relay-1=failed relay-2=ok relay-3=ok" {
		t.Errorf("outcomes = %s", outcomes(results))
	}
	out := f.out.String()
	for _, want := range []string{
		"[relay-1]       FAILED: boom",
		"[relay-1] FAILED: remote apply failed with exit status 1",
		"  HOST     RELAY       RESULT",
		"  relay-1  FleetRelay  failed  remote apply failed with exit status 1",
		"  relay-2  FleetRelay  ok",
		"  relay-3  FleetRelay  ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestFleetFirstFamilyHostFailureSkipsTheRest(t *testing.T) {
	f := newFixture(t)
	f.sim.failApply["relay-1"] = true
	cfg := f.config(t, generateConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2"}, KeepGoing: true})
	if err == nil || outcomes(results) != "relay-1=failed relay-2=skipped" {
		t.Fatalf("err = %v, outcomes %s", err, outcomes(results))
	}
	if !strings.Contains(results[1].Err.Error(), "family key could not be shared from relay-1") {
		t.Errorf("skip reason = %v", results[1].Err)
	}
}

func TestFleetBadFetchedKey(t *testing.T) {
	f := newFixture(t)
	f.sim.badKey = true
	cfg := f.config(t, generateConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2"}})
	if err == nil || outcomes(results) != "relay-1=failed relay-2=skipped" {
		t.Fatalf("err = %v, outcomes %s", err, outcomes(results))
	}
	if msg := results[0].Err.Error(); !strings.Contains(msg, "applied, but fetching the family key failed") || !strings.Contains(msg, "valid family key") {
		t.Errorf("message = %q", msg)
	}
}

func TestFleetSingleGenerateHostIsAsIs(t *testing.T) {
	f := newFixture(t)
	cfg := f.config(t, generateConfig)
	if _, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.sim.calls, "|"), "fetch") {
		t.Error("one host needs no key fetch")
	}
}

func TestFleetImportLocalKey(t *testing.T) {
	f := newFixture(t)
	keyPath := filepath.Join(f.dir, "ops.secret_family_key")
	if err := os.WriteFile(keyPath, testKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "ops.public_family_id"), []byte(testID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := f.config(t, baseConfig+"\n[family]\nmode = \"import\"\nimport_key = \""+keyPath+"\"\n")
	if _, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1", "relay-2"}}); err != nil {
		t.Fatalf("Apply: %v\n%s", err, f.out)
	}
	for _, h := range []string{"relay-1", "relay-2"} {
		up := f.sim.uploads[h]
		if !bytes.Equal(up["ops.secret_family_key"], testKey) {
			t.Errorf("%s: key not uploaded", h)
		}
		s, err := config.Parse(up["relay.toml"])
		if err != nil || s.Family.ImportKey != tmpFor(h)+"/ops.secret_family_key" || s.Family.FamilyID != testID {
			t.Errorf("%s: derived family %+v, %v", h, s.Family, err)
		}
	}

	// A key without a FamilyId is refused before connecting anywhere.
	if err := os.Remove(filepath.Join(f.dir, "ops.public_family_id")); err != nil {
		t.Fatal(err)
	}
	f.sim.calls = nil
	if _, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1"}}); err == nil || !strings.Contains(err.Error(), "no FamilyId") {
		t.Errorf("err = %v", err)
	}
	if len(f.sim.calls) != 0 {
		t.Errorf("connected despite a bad key: %q", f.sim.calls)
	}
}

func TestFleetSudoNeedsPassword(t *testing.T) {
	f := newFixture(t)
	f.sim.user["relay-1"], f.sim.noSudo["relay-1"] = true, true
	cfg := f.config(t, baseConfig)
	results, err := f.apply(t, Options{ConfigPath: cfg, Hosts: []string{"relay-1"}})
	if err == nil || !strings.Contains(results[0].Err.Error(), "sudo asks for a password") {
		t.Errorf("err = %v, results %+v", err, results)
	}
	if strings.Join(f.sim.calls, "|") != "relay-1 probe|relay-1 cleanup" {
		t.Errorf("calls = %q", f.sim.calls)
	}
}

func TestFleetRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	cfg := f.config(t, baseConfig)
	tests := []struct {
		name string
		opt  Options
		want string
	}{
		{"no hosts", Options{ConfigPath: cfg}, "no hosts"},
		{"option injection", Options{ConfigPath: cfg, Hosts: []string{"-oProxyCommand=sh"}}, "not an ssh destination"},
		{"duplicate", Options{ConfigPath: cfg, Hosts: []string{"a", "a"}}, "listed twice"},
		{"no config", Options{Hosts: []string{"a"}}, "needs --config"},
		{"invalid config", Options{ConfigPath: f.config(t, "[relay]\nnickname = \"bad name\"\n"), Hosts: []string{"a"}}, "relay.nickname"},
	}
	for _, tt := range tests {
		if _, err := f.apply(t, tt.opt); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
	f.fleet.GOOS = "darwin"
	if _, err := f.apply(t, Options{ConfigPath: f.config(t, baseConfig), Hosts: []string{"a"}}); err == nil || !strings.Contains(err.Error(), "darwin") {
		t.Errorf("darwin: %v", err)
	}
	if len(f.fake.Commands) != 0 {
		t.Errorf("ran commands: %q", f.fake.CommandLines())
	}
}

func TestFleetConnectionFailure(t *testing.T) {
	f := newFixture(t)
	f.fake.Handler = func(c host.Command) (host.Result, error) {
		return host.Result{ExitCode: 255, Output: "ssh: connect to host relay-1 port 22: Connection refused\n"}, &host.ExitError{ExitCode: 255}
	}
	results, err := f.apply(t, Options{ConfigPath: f.config(t, baseConfig), Hosts: []string{"relay-1"}})
	if err == nil || !strings.Contains(results[0].Err.Error(), "could not connect or authenticate") {
		t.Errorf("err = %v, %+v", err, results)
	}
	if !strings.Contains(f.out.String(), "[relay-1] ssh: connect to host relay-1 port 22: Connection refused") {
		t.Errorf("ssh's own error is not shown:\n%s", f.out)
	}
}

func TestValidHost(t *testing.T) {
	for _, ok := range []string{"relay-1", "root@relay-1.example.org", "my_alias", "203.0.113.5", "admin@2001:db8::1", "[2001:db8::1]", "u.ser@h"} {
		if err := ValidHost(ok); err != nil {
			t.Errorf("ValidHost(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-oProxyCommand=x", "relay 1", "relay\n1", "root@-x", "ssh://root@relay:22", "a;b", "$(x)", "a/b", "@relay", "a@b@c", "relay:22", strings.Repeat("a", 256)} {
		if err := ValidHost(bad); err == nil {
			t.Errorf("ValidHost(%q) accepted", bad)
		}
	}
}

func TestDestinations(t *testing.T) {
	tests := []struct{ in, ssh, scp string }{
		{"relay", "relay", "relay:/t/"},
		{"root@relay", "root@relay", "root@relay:/t/"},
		{"root@2001:db8::1", "root@2001:db8::1", "root@[2001:db8::1]:/t/"},
		{"[2001:db8::1]", "2001:db8::1", "[2001:db8::1]:/t/"},
	}
	for _, tt := range tests {
		if got := sshDest(tt.in); got != tt.ssh {
			t.Errorf("sshDest(%q) = %q", tt.in, got)
		}
		if got := scpTarget(tt.in, "/t/"); got != tt.scp {
			t.Errorf("scpTarget(%q) = %q", tt.in, got)
		}
	}
}

func needSh(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

func TestShellQuoteRoundTrips(t *testing.T) {
	needSh(t)
	for _, s := range []string{"plain", "", "with space", "it's", `"double" $HOME ` + "`id`", "a\nb", "[glob]*?", "back\\slash", "--flag"} {
		out, err := exec.Command("sh", "-c", "printf %s "+ShellQuote(s)).Output()
		if err != nil || string(out) != s {
			t.Errorf("ShellQuote(%q) -> %q, %v", s, out, err)
		}
	}
}

// TestApplyScriptRuns runs the remote apply script with a stub binary and
// checks the arguments and that the directory is removed afterwards.
func TestApplyScriptRuns(t *testing.T) {
	needSh(t)
	tmp := filepath.Join(t.TempDir(), "tor-relay-setup.abc")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nprintf '%s|' \"$@\"\nexit 3\n"
	if err := os.WriteFile(filepath.Join(tmp, "tor-relay-setup"), []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", applyScript(tmp, "", true))
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Errorf("exit = %v, want the binary's status 3", err)
	}
	want := "apply|--config|" + tmp + "/relay.toml|--yes|--plain|--dry-run|"
	if string(out) != want {
		t.Errorf("args = %q, want %q", out, want)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the remote directory was not removed: %v", err)
	}
}

func TestProbeScriptRuns(t *testing.T) {
	needSh(t)
	t.Setenv("TMPDIR", t.TempDir())
	// Run the script locally instead of over ssh.
	res, err := host.NewLocal().Run(context.Background(), host.Command{Name: "sh", Args: []string{"-c", probeScript}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Output, "TRS-ARCH ") || !strings.Contains(res.Output, "TRS-UID ") || !strings.Contains(res.Output, "TRS-TMP "+os.Getenv("TMPDIR")+"/tor-relay-setup.") {
		t.Errorf("probe output:\n%s", res.Output)
	}
}
