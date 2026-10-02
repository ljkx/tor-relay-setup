package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

func TestControlMasterArgs(t *testing.T) {
	fake := host.NewFake()
	f := &Fleet{Host: fake, Out: &strings.Builder{}, Multiplex: true}
	c := f.ssh("root@relay-1", "true", false)
	if len(c.Args) != 11 {
		t.Fatalf("argv = %q", c.Args)
	}
	dir := strings.TrimSuffix(strings.TrimPrefix(c.Args[3], "ControlPath="), "/%C")
	want := []string{
		"-o", "ControlMaster=auto", "-o", "ControlPath=" + dir + "/%C", "-o", "ControlPersist=120s",
		"-o", "ConnectTimeout=10", "--", "root@relay-1",
	}
	if !slices.Equal(c.Args[:10], want) || c.Args[10] != "sh -c true" {
		t.Errorf("argv = %q\nwant %q", c.Args, want)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("control dir %s: %v %v", dir, info, err)
	}
	// Every call shares the directory; IPv6 destinations lose their brackets.
	c2 := f.ssh("[2001:db8::1]", "true", false)
	if c2.Args[3] != c.Args[3] || c2.Args[9] != "2001:db8::1" {
		t.Errorf("second call = %q", c2.Args)
	}
	for _, a := range append(c.Args, c2.Args...) {
		if strings.Contains(a, "StrictHostKeyChecking") || strings.Contains(a, "UserKnownHostsFile") || strings.Contains(a, "BatchMode") {
			t.Errorf("host key checking must never be weakened: %q", a)
		}
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	lines := fake.CommandLines()
	wantExit := []string{
		"ssh -o ControlPath=" + dir + "/%C -O exit -- 2001:db8::1",
		"ssh -o ControlPath=" + dir + "/%C -O exit -- root@relay-1",
	}
	if !slices.Equal(lines, wantExit) {
		t.Errorf("close ran %q\nwant %q", lines, wantExit)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("control dir left behind: %v", err)
	}
	if err := f.Close(); err != nil || len(fake.Commands) != 2 {
		t.Error("a second Close should do nothing")
	}

	// Without multiplexing (tests, or no temp dir): plain ssh.
	plain := (&Fleet{Host: fake}).ssh("relay", "true", false)
	if !slices.Equal(plain.Args[:3], []string{"-o", "ConnectTimeout=10", "--"}) {
		t.Errorf("plain argv = %q", plain.Args)
	}
}

func TestApplyUsesTheSharedConnection(t *testing.T) {
	f := newFixture(t)
	f.fleet.Multiplex = true
	if _, err := f.apply(t, Options{ConfigPath: f.config(t, baseConfig), Hosts: []string{"relay-1"}}); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}
	for _, c := range f.fake.Commands {
		joined := strings.Join(c.Args, " ")
		if !strings.Contains(joined, "-o ControlMaster=auto") || !strings.Contains(joined, "-o ControlPersist=120s -o ConnectTimeout=10 --") {
			t.Errorf("%s does not share the connection: %s", c.Name, joined)
		}
	}
	if err := f.fleet.Close(); err != nil {
		t.Fatal(err)
	}
}

// fleetEntry is one relay of a hand-built inventory (relay.instance is a
// key of the multi-instance relay.toml).
func fleetEntry(t *testing.T, address, instance, nick string) fleet.Entry {
	t.Helper()
	data := []byte(strings.Replace(generateConfig, "FleetRelay", nick, 1))
	s, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return fleet.Entry{Address: address, Instance: instance, Config: data, Setup: s}
}

// gate holds remote applies until the test releases them.
type gate struct {
	mu      sync.Mutex
	waiting map[string][]chan struct{}
	arrived chan string
	overlap []string // servers that ran two applies at once
}

func newGate() *gate {
	return &gate{waiting: map[string][]chan struct{}{}, arrived: make(chan string, 16)}
}

func (g *gate) hold(dest string) {
	ch := make(chan struct{})
	g.mu.Lock()
	if len(g.waiting[dest]) > 0 {
		g.overlap = append(g.overlap, dest)
	}
	g.waiting[dest] = append(g.waiting[dest], ch)
	g.mu.Unlock()
	g.arrived <- dest
	<-ch
}

func (g *gate) release(dest string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	close(g.waiting[dest][0])
	g.waiting[dest] = g.waiting[dest][1:]
}

func TestInventoryApplyFamilyFirstThenBoundedParallel(t *testing.T) {
	f := newFixture(t)
	g := newGate()
	f.fake.Handler = func(c host.Command) (host.Result, error) {
		if c.Name == "ssh" && strings.Contains(c.Args[len(c.Args)-1], "apply --config") {
			if dest := c.Args[len(c.Args)-2]; dest != "relay-1" {
				g.hold(dest)
			}
		}
		return f.sim.handle(c)
	}
	inv := fleet.Inventory{Parallel: 2, Entries: []fleet.Entry{
		fleetEntry(t, "relay-1", "default", "Fleet1"),
		fleetEntry(t, "relay-2", "default", "Fleet2"),
		fleetEntry(t, "relay-3", "default", "Fleet3"),
		fleetEntry(t, "relay-4", "default", "Fleet4"),
		fleetEntry(t, "relay-4", "second", "Fleet5"),
		fleetEntry(t, "relay-5", "default", "Fleet6"),
	}}

	type outcome struct {
		results []HostResult
		err     error
	}
	done := make(chan outcome)
	go func() {
		results, err := f.fleet.Apply(context.Background(), Options{Inventory: &inv})
		done <- outcome{results, err}
	}()

	// Drive the gated applies: two may run at once, never three, and the
	// two relays of relay-4 never overlap.
	var held []string
	got := 0
	for got < 5 || len(held) > 0 {
		if len(held) < 2 && got < 5 {
			select {
			case d := <-g.arrived:
				held, got = append(held, d), got+1
				continue
			case <-time.After(5 * time.Second):
				t.Fatalf("only %v are applying; parallel = 2 should run two servers at once", held)
			}
		}
		select {
		case d := <-g.arrived:
			t.Fatalf("%s started while %v were applying (parallel = 2)", d, held)
		case <-time.After(30 * time.Millisecond):
		}
		g.release(held[0])
		held = held[1:]
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("Apply: %v\n%s", res.err, f.out)
	}
	if outcomes(res.results) != "relay-1=ok relay-2=ok relay-3=ok relay-4=ok relay-4=ok relay-5=ok" {
		t.Errorf("outcomes = %s", outcomes(res.results))
	}

	// The family host was applied and its key fetched before any other
	// host was even probed.
	calls := strings.Join(f.sim.calls, "|")
	if !strings.HasPrefix(calls, "relay-1 probe|relay-1 scp|relay-1 apply|relay-1 fetch|") {
		t.Errorf("calls = %s", calls)
	}
	// Every further relay imports the fetched key under its own nickname.
	for i, e := range inv.Entries[1:] {
		up := f.sim.uploads[e.Address]
		s, err := config.Parse(up["relay.toml"])
		if err != nil {
			t.Fatal(err)
		}
		if s.Family.Mode != "import" || s.Family.FamilyID != testID {
			t.Errorf("%s: family %+v", e.Address, s.Family)
		}
		if e.Address != "relay-4" && s.Relay.Nickname != fmt.Sprintf("Fleet%d", i+2) {
			t.Errorf("%s: nickname %s", e.Address, s.Relay.Nickname)
		}
	}
	out := f.out.String()
	for _, want := range []string{
		"==> [5/6] relay-4/Fleet5",
		"[relay-4/Fleet4] Relay configured.",
		"[relay-1] fetched FamilyId " + testID + "; the other relays join this family",
		"  relay-4  Fleet5 (second)  ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestInventoryApplyStopsWithoutKeepGoing(t *testing.T) {
	f := newFixture(t)
	f.sim.failApply["relay-2"] = true
	inv := fleet.Inventory{Parallel: 1, Entries: []fleet.Entry{
		fleetEntry(t, "relay-1", "default", "Fleet1"),
		fleetEntry(t, "relay-2", "default", "Fleet2"),
		fleetEntry(t, "relay-3", "default", "Fleet3"),
	}}
	results, err := f.fleet.Apply(context.Background(), Options{Inventory: &inv})
	if err == nil || outcomes(results) != "relay-1=ok relay-2=failed relay-3=skipped" {
		t.Fatalf("err %v, outcomes %s", err, outcomes(results))
	}
	// --parallel overrides the inventory and --keep-going continues.
	f2 := newFixture(t)
	f2.sim.failApply["relay-2"] = true
	results, _ = f2.fleet.Apply(context.Background(), Options{Inventory: &inv, KeepGoing: true, Parallel: 3})
	if outcomes(results) != "relay-1=ok relay-2=failed relay-3=ok" {
		t.Errorf("keep going: %s", outcomes(results))
	}
}

// probeJSON is a fleet-probe answer for one relay.
func probeJSON(t *testing.T, active bool) string {
	t.Helper()
	var r status.Report
	r.Relay.Configured, r.Relay.Nickname, r.Relay.ORPort = true, "Fleet", 9001
	r.Service.Unit, r.Service.Active = "tor@default", active
	r.Listener.IPv4 = active
	data, err := json.Marshal(fleet.Probe{Version: "v3.2.0", Relays: []fleet.RelayProbe{{Report: r}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestProbeClassifies(t *testing.T) {
	good := probeJSON(t, true)
	tests := []struct {
		name   string
		out    string
		code   int
		state  fleet.HostState
		detail string
	}{
		{"ok", "sudo: unable to resolve host x\n" + good + "\n", 0, fleet.HostOK, ""},
		{"unreachable", "ssh: connect to host relay-1 port 22: Connection refused\n", 255, fleet.HostUnreachable, "ssh: connect to host relay-1 port 22: Connection refused"},
		{"too old", "unknown command \"fleet-probe\"\n\ntor-relay-setup — set up\n", 2, fleet.HostTooOld, "run self-update"},
		{"not installed", "TRS-NOBINARY\n", 127, fleet.HostMissing, "not installed"},
		{"garbage", "hello\n", 0, fleet.HostFailed, "no probe document"},
		{"crash", "panic: boom\n", 1, fleet.HostFailed, "panic: boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := host.NewFake()
			fake.Handler = func(c host.Command) (host.Result, error) {
				res := host.Result{Output: tt.out, ExitCode: tt.code}
				if tt.code != 0 {
					return res, &host.ExitError{ExitCode: tt.code, Output: tt.out}
				}
				return res, nil
			}
			f := &Fleet{Host: fake, Out: &strings.Builder{}}
			hp := f.Probe(context.Background(), "root@relay-1")
			if hp.State != tt.state || !strings.Contains(hp.Detail, tt.detail) || hp.Address != "root@relay-1" || hp.At.IsZero() {
				t.Errorf("probe = %+v", hp)
			}
			if tt.state == fleet.HostOK && (hp.Probe.Version != "v3.2.0" || !hp.Probe.Relays[0].Report.Service.Active) {
				t.Errorf("document = %+v", hp.Probe)
			}
			c := fake.Commands[0]
			if c.Mutates || !strings.Contains(c.Args[len(c.Args)-1], `exec $s "$b" fleet-probe`) {
				t.Errorf("command = %s", c)
			}
		})
	}
}

func TestProbeAllIsBoundedAndOrdered(t *testing.T) {
	var mu sync.Mutex
	inflight, peak := 0, 0
	fake := host.NewFake()
	good := probeJSON(t, true)
	fake.Handler = func(c host.Command) (host.Result, error) {
		mu.Lock()
		inflight++
		peak = max(peak, inflight)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		return host.Result{Output: good}, nil
	}
	f := &Fleet{Host: fake, Out: &strings.Builder{}}
	addrs := []string{"a", "b", "c", "d", "e", "f", "g"}
	got := f.ProbeAll(context.Background(), addrs, 3)
	for i, hp := range got {
		if hp.Address != addrs[i] || hp.State != fleet.HostOK {
			t.Errorf("probe %d = %+v", i, hp)
		}
	}
	if peak > 3 {
		t.Errorf("%d probes ran at once, limit 3", peak)
	}
}

// TestInstalledScriptRuns runs the remote wrapper locally against a stub.
func TestInstalledScriptRuns(t *testing.T) {
	needSh(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "tor-relay-setup"), []byte("#!/bin/sh\nprintf '%s|' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	env := []string{"PATH=" + bin + ":" + filepath.Dir(shPath) + ":/usr/bin:/bin"}
	out, err := exec.Command("env", append(env, "sh", "-c", installedScript("tor restart --yes --plain", false))...).CombinedOutput()
	if err != nil || !strings.HasSuffix(string(out), "tor|restart|--yes|--plain|") {
		t.Errorf("output %q, %v", out, err)
	}
	// Without the tool on PATH (or in /usr/local/bin) it says so.
	if _, err := os.Stat("/usr/local/bin/tor-relay-setup"); err == nil {
		t.Skip("tor-relay-setup is installed on this machine")
	}
	empty := t.TempDir()
	cmd := exec.Command("env", "PATH="+empty+":"+filepath.Dir(shPath), "sh", "-c", installedScript("fleet-probe", false))
	out, err = cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 || !strings.Contains(string(out), "TRS-NOBINARY") {
		t.Errorf("missing tool: %q, %v", out, err)
	}
}

// rolloutSim answers `tor VERB` and fleet-probe calls for a rollout.
type rolloutSim struct {
	mu        sync.Mutex
	calls     []string
	failVerb  map[string]int    // host → exit code of tor VERB
	output    map[string]string // host → output of a failing tor VERB
	unhealthy map[string]int    // host → number of probes that show tor stopped (-1: forever)
}

func (s *rolloutSim) handle(t *testing.T) func(host.Command) (host.Result, error) {
	return func(c host.Command) (host.Result, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		dest, script := c.Args[len(c.Args)-2], c.Args[len(c.Args)-1]
		if strings.Contains(script, "fleet-probe") {
			s.calls = append(s.calls, dest+" probe")
			healthy := true
			if n := s.unhealthy[dest]; n != 0 {
				healthy = false
				if n > 0 {
					s.unhealthy[dest] = n - 1
				}
			}
			return host.Result{Output: probeJSON(t, healthy)}, nil
		}
		_, args, _ := strings.Cut(script, `exec $s "$b" `)
		s.calls = append(s.calls, dest+" "+strings.TrimSuffix(args, "'"))
		if code := s.failVerb[dest]; code != 0 {
			return host.Result{ExitCode: code, Output: s.output[dest]}, &host.ExitError{ExitCode: code}
		}
		return host.Result{Output: "  systemctl restart tor@default\nTor restarted.\n"}, nil
	}
}

func newRollout(t *testing.T) (*rolloutSim, *Fleet, *strings.Builder, []fleet.Entry) {
	t.Helper()
	sim := &rolloutSim{failVerb: map[string]int{}, output: map[string]string{}, unhealthy: map[string]int{}}
	fake := host.NewFake()
	fake.Handler = sim.handle(t)
	out := &strings.Builder{}
	entries := []fleet.Entry{
		fleetEntry(t, "relay-1", "default", "One"),
		fleetEntry(t, "relay-2", "default", "Two"),
		fleetEntry(t, "relay-3", "default", "Three"),
	}
	return sim, &Fleet{Host: fake, Out: out}, out, entries
}

func TestRolloutOneAtATimeWaitingForHealth(t *testing.T) {
	sim, f, out, entries := newRollout(t)
	sim.unhealthy["relay-2"] = 2 // comes back on the third probe
	results, err := f.Rollout(context.Background(), RolloutOptions{Action: Restart, Entries: entries, Poll: time.Millisecond, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if outcomes(results) != "relay-1=ok relay-2=ok relay-3=ok" {
		t.Errorf("outcomes = %s", outcomes(results))
	}
	want := "relay-1 tor restart --yes --plain|relay-1 probe|" +
		"relay-2 tor restart --yes --plain|relay-2 probe|relay-2 probe|relay-2 probe|" +
		"relay-3 tor restart --yes --plain|relay-3 probe"
	if got := strings.Join(sim.calls, "|"); got != want {
		t.Errorf("calls:\n%s\nwant\n%s", got, want)
	}
	cmd := f.Host.(*host.Fake).Commands[0]
	if !cmd.Mutates || !strings.Contains(cmd.Args[len(cmd.Args)-1], "TRS-NOSUDO") {
		t.Errorf("a real rollout needs root on the host: %s", cmd)
	}
	for _, w := range []string{"==> [2/3] restart relay-2", "[relay-2] Tor restarted.", "[relay-2] running and listening", "  relay-3  Three  ok"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestRolloutStopsOnFailure(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*rolloutSim)
		keepGoing bool
		outcomes  string
		reason    string
	}{
		{"never healthy", func(s *rolloutSim) { s.unhealthy["relay-2"] = -1 }, false,
			"relay-1=ok relay-2=failed relay-3=skipped", "not running and listening after 30ms (tor@default is not active)"},
		{"command fails", func(s *rolloutSim) {
			s.failVerb["relay-2"], s.output["relay-2"] = 1, "error: tor@default did not come back\n"
		}, false,
			"relay-1=ok relay-2=failed relay-3=skipped", "tor restart failed: error: tor@default did not come back"},
		{"too old", func(s *rolloutSim) { s.failVerb["relay-2"], s.output["relay-2"] = 2, "unknown command \"tor\"\n" }, false,
			"relay-1=ok relay-2=failed relay-3=skipped", "too old on this host for `tor restart` — run self-update"},
		{"no sudo", func(s *rolloutSim) { s.failVerb["relay-2"], s.output["relay-2"] = 126, "TRS-NOSUDO\n" }, false,
			"relay-1=ok relay-2=failed relay-3=skipped", "sudo asks for a password"},
		{"unreachable", func(s *rolloutSim) {
			s.failVerb["relay-2"], s.output["relay-2"] = 255, "ssh: Could not resolve hostname relay-2\n"
		}, true,
			"relay-1=ok relay-2=failed relay-3=ok", "ssh could not connect or authenticate (ssh: Could not resolve hostname relay-2)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim, f, out, entries := newRollout(t)
			tt.setup(sim)
			results, err := f.Rollout(context.Background(), RolloutOptions{Action: Restart, Entries: entries, KeepGoing: tt.keepGoing, Poll: time.Millisecond, Timeout: 30 * time.Millisecond})
			if err == nil || outcomes(results) != tt.outcomes {
				t.Fatalf("err %v, outcomes %s\n%s", err, outcomes(results), out)
			}
			if !strings.Contains(results[1].Err.Error(), tt.reason) {
				t.Errorf("reason = %v, want %q", results[1].Err, tt.reason)
			}
			if !tt.keepGoing {
				if !strings.Contains(results[2].Err.Error(), "rollout stopped after an earlier failure") || strings.Contains(strings.Join(sim.calls, "|"), "relay-3") {
					t.Errorf("relay-3 was touched: %v %q", results[2].Err, sim.calls)
				}
			}
		})
	}
}

func TestRolloutDryRunAndVerbs(t *testing.T) {
	sim, f, _, entries := newRollout(t)
	entries[2].Instance = "second"
	if _, err := f.Rollout(context.Background(), RolloutOptions{Action: UpdateTor, Entries: entries, DryRun: true}); err != nil {
		t.Fatal(err)
	}
	want := "relay-1 tor update --yes --plain --dry-run|relay-2 tor update --yes --plain --dry-run|relay-3 tor update --yes --plain --instance second --dry-run"
	if got := strings.Join(sim.calls, "|"); got != want {
		t.Errorf("calls:\n%s\nwant\n%s", got, want)
	}
	for _, c := range f.Host.(*host.Fake).Commands {
		if c.Mutates || strings.Contains(c.Args[len(c.Args)-1], "TRS-NOSUDO") {
			t.Errorf("a dry run should not mutate or require sudo: %s", c)
		}
	}
	if _, err := f.Rollout(context.Background(), RolloutOptions{Action: Reload}); err == nil {
		t.Error("no entries accepted")
	}
	for in, want := range map[string]Action{"restart": Restart, "reload": Reload, "update-tor": UpdateTor} {
		if got, ok := ParseAction(in); !ok || got != want {
			t.Errorf("ParseAction(%q) = %q", in, got)
		}
	}
	if _, ok := ParseAction("status"); ok {
		t.Error("status is no rolling action")
	}
}

func TestFamilyKeyComesFromTheInstanceKeyDirectory(t *testing.T) {
	f := newFixture(t)
	inv := fleet.Inventory{Parallel: 1, Entries: []fleet.Entry{
		fleetEntry(t, "relay-1", "second", "Fleet1"),
		fleetEntry(t, "relay-2", "default", "Fleet2"),
	}}
	if _, err := f.fleet.Apply(context.Background(), Options{Inventory: &inv}); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}
	if !f.fake.Ran("/var/lib/tor-instances/second/keys/fleet.secret_family_key", "/var/lib/tor-instances/second/keys/fleet.public_family_id") {
		t.Errorf("the key was not fetched from the instance directory:\n%s", strings.Join(f.fake.CommandLines(), "\n"))
	}
	for in, want := range map[string]string{"": "/var/lib/tor/keys", "default": "/var/lib/tor/keys", "second": "/var/lib/tor-instances/second/keys"} {
		if got, err := keyDirFor(in); err != nil || got != want {
			t.Errorf("keyDirFor(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"../etc", "a b", "x/y"} {
		if _, err := keyDirFor(bad); err == nil {
			t.Errorf("keyDirFor(%q) accepted", bad)
		}
	}
}
