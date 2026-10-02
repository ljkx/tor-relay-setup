package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// relayFixture is a relay on a Fake host with a stand-in MetricsPort and
// Onionoo.
type relayFixture struct {
	fake    *host.Fake
	onionoo onionoo.Client

	mu      sync.Mutex
	active  bool
	flags   []string
	page    string
	updates bool
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	page, err := os.ReadFile("../metrics/testdata/metricsport-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile("../metrics/testdata/tor-state-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	f := &relayFixture{fake: host.NewFake(), active: true, flags: []string{"Fast", "Guard", "Running", "Stable", "Valid"}, page: string(page)}

	mp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		fmt.Fprint(w, f.page)
	}))
	t.Cleanup(mp.Close)
	oo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		flags, _ := json.Marshal(f.flags)
		fmt.Fprintf(w, `{"relays":[{"nickname":"MyRelay","fingerprint":%q,"running":true,"flags":%s}]}`, testFP, flags)
	}))
	t.Cleanup(oo.Close)
	f.onionoo = onionoo.Client{HTTP: oo.Client(), Base: oo.URL}

	f.fake.Files["/etc/tor/torrc"] = []byte("Nickname MyRelay\nContactInfo ops@example.org\nORPort 9001\nMetricsPort " +
		strings.TrimPrefix(mp.URL, "http://") + "\nAccountingMax 100 GBytes\nAccountingRule sum\n")
	f.fake.Files["/var/lib/tor/fingerprint"] = []byte("MyRelay " + testFP + "\n")
	f.fake.Files["/var/lib/tor/state"] = state
	f.fake.Files["/proc/net/tcp"] = []byte("  sl  local_address rem_address   st\n   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n")
	f.fake.Handler = func(c host.Command) (host.Result, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case c.Name == "tor":
			return host.Result{Output: "Tor version 0.4.9.13.\n"}, nil
		case c.Name == "systemctl" && !f.active:
			return host.Result{ExitCode: 3}, &host.ExitError{Command: c.String(), ExitCode: 3}
		case c.Name == "journalctl":
			return host.Result{Output: "2026-10-02T05:10:00+0000 relay Tor[812]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent.\n"}, nil
		case c.Name == "apt-cache":
			cand := "0.4.9.13-1"
			if f.updates {
				cand = "0.4.9.14-1"
			}
			return host.Result{Output: "tor:\n  Installed: 0.4.9.13-1\n  Candidate: " + cand + "\n"}, nil
		}
		return host.Result{}, nil
	}
	return f
}

func (f *relayFixture) set(edit func(*relayFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(f)
}

func (f *relayFixture) gather(t *testing.T, at time.Time, updates bool) Input {
	t.Helper()
	return Gather(context.Background(), f.fake, GatherOptions{Onionoo: f.onionoo, CheckUpdates: updates, Now: func() time.Time { return at }})
}

func TestGather(t *testing.T) {
	f := newRelayFixture(t)
	f.set(func(f *relayFixture) { f.updates = true })
	in := f.gather(t, testNow, true)
	r := in.Report
	if !r.Relay.Configured || r.Relay.Fingerprint != testFP || !r.Service.Active || !r.Listener.IPv4 || !r.Reachability.IPv4 {
		t.Errorf("report %+v", r)
	}
	if r.Directory == nil || r.DirectoryError != "" || len(r.Directory.Flags) != 5 {
		t.Errorf("directory %+v %q", r.Directory, r.DirectoryError)
	}
	if in.Sample == nil || in.SampleErr != "" || in.Sample.Load.SocketsLimit != 1048544 || in.Sample.At.IsZero() {
		t.Errorf("sample %+v %q", in.Sample, in.SampleErr)
	}
	if a := in.Accounting; a == nil || in.AccountingErr != "" || !a.Enabled || a.Max != 100<<30 || a.Rule != "sum" {
		t.Errorf("accounting %+v %q", a, in.AccountingErr)
	}
	if in.TorInstalled != "0.4.9.13-1" || in.TorCandidate != "0.4.9.14-1" || !in.Now.Equal(testNow) {
		t.Errorf("apt %q %q, now %v", in.TorInstalled, in.TorCandidate, in.Now)
	}
	if !f.fake.Ran("apt-cache policy tor") {
		t.Error("apt-cache was not asked")
	}
	for _, line := range f.fake.CommandLines() {
		if strings.Contains(line, "systemctl") && !strings.Contains(line, "is-active") {
			t.Errorf("gathering must be read-only, ran %q", line)
		}
	}

	// Broken pieces are recorded, not fatal.
	f.fake.Files["/etc/tor/torrc"] = []byte("Nickname MyRelay\nORPort 9001\nMetricsPort 127.0.0.1:1\nAccountingMax lots\n")
	delete(f.fake.Files, "/var/lib/tor/fingerprint")
	ran := len(f.fake.CommandLines())
	in = f.gather(t, testNow, false)
	if in.Sample != nil || in.SampleErr == "" || in.Accounting != nil || !strings.Contains(in.AccountingErr, "AccountingMax") || in.Report.Directory != nil {
		t.Errorf("%+v", in)
	}
	for _, line := range f.fake.CommandLines()[ran:] {
		if strings.Contains(line, "apt-cache") {
			t.Error("apt-cache asked although CheckUpdates is off")
		}
	}
}

func TestGatherInstancePaths(t *testing.T) {
	f := newRelayFixture(t)
	f.fake.Files["/etc/tor/instances/fast2/torrc"] = f.fake.Files["/etc/tor/torrc"]
	delete(f.fake.Files, "/etc/tor/torrc")
	in := Gather(context.Background(), f.fake, GatherOptions{TorrcPath: "/etc/tor/instances/fast2/torrc", Unit: "tor@fast2", Onionoo: f.onionoo})
	if !in.Report.Relay.Configured || in.Report.Service.Unit != "tor@fast2" || !f.fake.Ran("systemctl is-active --quiet tor@fast2") {
		t.Errorf("report %+v\n%s", in.Report.Service, strings.Join(f.fake.CommandLines(), "\n"))
	}
	m := Runner{Instance: "fast2", Config: DefaultConfig()}.message(in, nil)
	if m.Instance != "fast2" || !strings.Contains(m.Text(), "tor instance fast2") {
		t.Errorf("message %+v", m)
	}
}

func TestIdentify(t *testing.T) {
	f := newRelayFixture(t)
	in := Identify(f.fake, "")
	if in.Report.Relay.Nickname != "MyRelay" || in.Report.Relay.Fingerprint != testFP || in.Now.IsZero() {
		t.Errorf("%+v", in.Report.Relay)
	}
	if in := Identify(host.NewFake(), ""); in.Report.Relay.Nickname != "" {
		t.Error("no torrc, no identity")
	}
}

func TestRunnerEndToEnd(t *testing.T) {
	f := newRelayFixture(t)
	hook := newRecorder(t, http.StatusOK)
	cfg := DefaultConfig()
	cfg.Webhook = []WebhookConfig{{URL: hook.URL + "/h"}}
	var out bytes.Buffer
	runner := Runner{Host: f.fake, Config: cfg, Notifiers: cfg.Notifiers(f.fake, hook.Client()), Out: &out}
	const statePath = DefaultStatePath
	at := testNow
	run := func(wantErr bool) {
		t.Helper()
		out.Reset()
		err := runner.Run(context.Background(), f.gather(t, at, false))
		if (err != nil) != wantErr {
			t.Fatalf("run at %v: err %v\n%s", at, err, out.String())
		}
		at = at.Add(5 * time.Minute)
	}
	lastAlerts := func() []Notification {
		t.Helper()
		var m Message
		if err := json.Unmarshal([]byte(hook.body(hook.count()-1)), &m); err != nil {
			t.Fatal(err)
		}
		return m.Alerts
	}
	summary := func(ns []Notification) string {
		var s []string
		for _, n := range ns {
			s = append(s, string(n.Status)+" "+n.ID)
		}
		return strings.Join(s, "; ")
	}

	// 1. Healthy: nothing sent, baseline saved.
	run(false)
	if hook.count() != 0 || !strings.Contains(out.String(), "Nothing to send (0 open problem(s))") {
		t.Fatalf("healthy run sent %d, output %q", hook.count(), out.String())
	}
	st, _ := LoadState(f.fake, statePath)
	if st.Sample == nil || !st.Published || strings.Join(st.Flags, ",") != "Guard,Stable,Fast" || f.fake.Modes[statePath] != 0o600 {
		t.Fatalf("state %+v", st)
	}

	// 2. tor stops: one critical notification.
	f.set(func(f *relayFixture) { f.active = false })
	run(false)
	if hook.count() != 1 || summary(lastAlerts()) != "firing service-inactive" || !strings.Contains(out.String(), "sent 1 alert(s) to webhook[0] (127.0.0.1)") {
		t.Fatalf("sent %d: %v\n%s", hook.count(), lastAlerts(), out.String())
	}
	// 3. Still down five minutes later: quiet.
	run(false)
	if hook.count() != 1 {
		t.Fatalf("repeat notification")
	}

	// 4. tor is back but the relay lost Guard; overload since the last run.
	f.set(func(f *relayFixture) {
		f.active = true
		f.flags = []string{"Fast", "Running", "Stable", "Valid"}
		f.page = strings.Replace(f.page, `tor_relay_load_oom_bytes_total{subsys="cell"} 0`, `tor_relay_load_oom_bytes_total{subsys="cell"} 1048576`, 1)
	})
	run(false)
	if got := summary(lastAlerts()); got != "firing flag-lost-Guard; firing overload-oom; resolved service-inactive" {
		t.Fatalf("got %q", got)
	}

	// 5. Every notifier fails: exit with an error, keep the open problems so
	//    the next run sends them again.
	hook.mu.Lock()
	hook.status = http.StatusBadGateway
	hook.mu.Unlock()
	f.set(func(f *relayFixture) { f.active = false })
	before, _ := LoadState(f.fake, statePath)
	run(true)
	after, _ := LoadState(f.fake, statePath)
	if _, ok := after.Active["service-inactive"]; ok || len(after.Active) != len(before.Active) || !strings.Contains(out.String(), "failed: webhook[0] (127.0.0.1): server answered 502") {
		t.Fatalf("state after failure %+v\n%s", after.Active, out.String())
	}
	hook.mu.Lock()
	hook.status = http.StatusOK
	hook.mu.Unlock()
	run(false)
	if got := summary(lastAlerts()); got != "firing service-inactive" {
		t.Fatalf("retry: %q", got)
	}

	// 6. Dry run: prints, sends nothing, keeps the state.
	f.set(func(f *relayFixture) { f.active = true })
	sent := hook.count()
	stateBefore := string(f.fake.Files[statePath])
	runner.DryRun = true
	run(false)
	if hook.count() != sent || string(f.fake.Files[statePath]) != stateBefore {
		t.Fatal("a dry run sent or saved")
	}
	for _, want := range []string{"Dry run: would send to 1 notifier(s), state not updated.", "[RESOLVED] tor@default is not running", "-> webhook[0] (127.0.0.1)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out.String())
		}
	}

	// A corrupt state file is a warning, not a failure.
	runner.DryRun = false
	f.fake.Files[statePath] = []byte("garbage")
	run(false)
	if !strings.Contains(out.String(), "warning: alert state") {
		t.Errorf("output %q", out.String())
	}
}

func TestRunnerTest(t *testing.T) {
	f := newRelayFixture(t)
	ok, bad := newRecorder(t, http.StatusOK), newRecorder(t, http.StatusUnauthorized)
	cfg := DefaultConfig()
	cfg.Name = "fra-1"
	cfg.Ntfy = []NtfyConfig{{URL: ok.URL + "/t"}, {URL: bad.URL + "/t"}}
	var out bytes.Buffer
	r := Runner{Host: f.fake, Config: cfg, Notifiers: cfg.Notifiers(f.fake, ok.Client()), Out: &out}
	err := r.Test(context.Background(), Identify(f.fake, ""))
	if err == nil || err.Error() != "1 of 2 notifiers failed" {
		t.Fatalf("err %v", err)
	}
	if ok.count() != 1 || ok.req(0).Header.Get("Title") != "fra-1: [TEST] test notification" || !strings.Contains(ok.body(0), "fra-1 (MyRelay, ") {
		t.Errorf("test message: %v\n%s", ok.req(0).Header, ok.body(0))
	}
	if _, saved := f.fake.Files[DefaultStatePath]; saved {
		t.Error("a test must not touch the state")
	}
	out.Reset()
	r.DryRun = true
	if err := r.Test(context.Background(), Identify(f.fake, "")); err != nil || ok.count() != 1 || !strings.Contains(out.String(), "would send a test notification to 2 notifier(s)") {
		t.Errorf("dry test: %v %q", err, out.String())
	}
}
