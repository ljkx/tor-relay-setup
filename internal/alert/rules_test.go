package alert

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

const testFP = "0123456789ABCDEF0123456789ABCDEF01234567"

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// realSample is the trimmed real tor 0.4.9.13 MetricsPort page of the
// metrics package, scraped at at.
func realSample(t *testing.T, at time.Time) *metrics.Sample {
	t.Helper()
	data, err := os.ReadFile("../metrics/testdata/metricsport-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	s, err := metrics.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	s.At = at
	return &s
}

// healthy is a relay with nothing to report.
func healthy(t *testing.T) Input {
	var r status.Report
	r.Tor.Installed, r.Tor.Version, r.Tor.Supported = true, "0.4.9.13", true
	r.Service.Unit, r.Service.Active = "tor@default", true
	r.Relay.Configured, r.Relay.Nickname, r.Relay.Fingerprint = true, "MyRelay", testFP
	r.Relay.ORPort, r.Relay.MetricsPort = 9001, "127.0.0.1:9035"
	r.Listener.IPv4 = true
	r.Reachability.IPv4, r.Reachability.Seen = true, true
	r.Family.KeyDirectory = "/var/lib/tor/keys"
	r.Directory = &onionoo.Relay{Nickname: "MyRelay", Fingerprint: testFP, Running: true,
		Flags: []string{"Fast", "Guard", "HSDir", "Running", "Stable", "Valid"}}
	return Input{Now: testNow, Report: r, Sample: realSample(t, testNow)}
}

func TestEvaluate(t *testing.T) {
	gib := uint64(1 << 30)
	acct := func(used, maxBytes uint64, exhausts time.Time) *metrics.Accounting {
		return &metrics.Accounting{Enabled: true, Rule: "sum", Max: maxBytes, Used: used, ExhaustsAt: exhausts,
			PeriodStart: testNow.Add(-10 * 24 * time.Hour), PeriodEnd: testNow.Add(20 * 24 * time.Hour)}
	}
	prevWithFlags := Observed{Published: true, Flags: []string{"Guard", "Stable", "Fast", "HSDir"}}
	tests := []struct {
		name     string
		edit     func(*Input)
		prev     Observed
		cfg      func(*Config)
		want     map[string]Severity
		unknown  []string
		events   []string
		contains string // in some alert body
	}{
		{name: "healthy", prev: prevWithFlags, want: map[string]Severity{}},
		{
			name: "service down", prev: prevWithFlags,
			edit: func(in *Input) {
				in.Report.Service.Active = false
				in.Report.Listener.IPv4 = false
				in.Sample, in.SampleErr = nil, "connection refused"
			},
			want: map[string]Severity{"service-inactive": Critical}, unknown: []string{prefixOverload},
			contains: "journalctl -u tor@default",
		},
		{
			name: "running but not listening", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Listener.IPv4 = false },
			want: map[string]Severity{"orport-not-listening": Critical},
		},
		{
			name: "self-test failed", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Reachability.IPv4, in.Report.Reachability.Failed = false, true },
			want: map[string]Severity{"orport-unreachable": Critical}, contains: "inbound TCP 9001",
		},
		{
			name: "tor too old", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Tor.Version, in.Report.Tor.Supported = "0.4.7.16", false },
			want: map[string]Severity{"tor-unsupported": Critical},
		},
		{
			name: "tor missing", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Tor = status.Report{}.Tor },
			want: map[string]Severity{"tor-missing": Critical},
		},
		{
			name: "family key missing", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Family.MissingKeys = []string{"AAAA"} },
			want: map[string]Severity{"family-key-missing": Warning}, contains: "FamilyId AAAA",
		},
		{
			name: "not running in Tor Metrics", prev: prevWithFlags,
			edit: func(in *Input) {
				in.Report.Directory.Running = false
				in.Report.Directory.Flags = []string{"Fast", "Guard", "HSDir", "Stable", "Valid"}
			},
			want: map[string]Severity{"directory-not-running": Critical},
		},
		{
			name: "dropped out of the consensus", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Directory = nil },
			want: map[string]Severity{"directory-missing": Critical},
		},
		{
			name: "never published yet is fine", prev: Observed{},
			edit: func(in *Input) { in.Report.Directory = nil },
			want: map[string]Severity{},
		},
		{
			name: "Tor Metrics unreachable keeps directory alerts unknown", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Directory, in.Report.DirectoryError = nil, "onionoo: timeout" },
			want: map[string]Severity{}, unknown: []string{prefixDirectory},
		},
		{
			name: "lost Guard and HSDir", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Directory.Flags = []string{"Fast", "Running", "Stable", "Valid"} },
			want: map[string]Severity{"flag-lost-Guard": Warning, "flag-lost-HSDir": Warning}, events: []string{"flag-lost-Guard", "flag-lost-HSDir"},
			contains: "about 8 days",
		},
		{
			name: "unwatched flag loss is quiet", prev: prevWithFlags,
			cfg:  func(c *Config) { c.WatchFlags = []string{"Stable"} },
			edit: func(in *Input) { in.Report.Directory.Flags = []string{"Running", "Stable"} },
			want: map[string]Severity{},
		},
		{
			name: "Relay Search overload mark", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Directory.OverloadGeneral = testNow.Add(-5 * time.Hour) },
			want: map[string]Severity{"directory-overloaded": Warning},
		},
		{
			name: "old Relay Search overload mark", prev: prevWithFlags,
			edit: func(in *Input) { in.Report.Directory.OverloadGeneral = testNow.Add(-73 * time.Hour) },
			want: map[string]Severity{},
		},
		{
			name: "OOM since the last run",
			prev: func() Observed {
				o := prevWithFlags
				o.Sample = realSample(t, testNow.Add(-5*time.Minute))
				return o
			}(),
			edit: func(in *Input) { in.Sample.Load.OOMBytes.Cell += 64 << 20 },
			want: map[string]Severity{"overload-oom": Warning}, contains: "MaxMemInQueues",
		},
		{
			name: "rate limits are informational",
			prev: func() Observed {
				o := prevWithFlags
				o.Sample = realSample(t, testNow.Add(-5*time.Minute))
				return o
			}(),
			edit: func(in *Input) { in.Sample.Load.RateLimitRead += 30 },
			want: map[string]Severity{"overload-rate_limited": Info},
		},
		{
			name: "overload held from an earlier run",
			prev: func() Observed {
				o := prevWithFlags
				o.Sample = realSample(t, testNow.Add(-5*time.Minute))
				o.Overload = map[string]OverloadMark{
					"tcp_exhaustion": {At: testNow.Add(-2 * time.Hour), Severity: Warning, Summary: "3 connections failed because no local TCP port was free"},
					"oom":            {At: testNow.Add(-7 * time.Hour), Severity: Warning, Summary: "expired"},
				}
				return o
			}(),
			want: map[string]Severity{"overload-tcp_exhaustion": Warning}, contains: "(last seen 2026-10-02 10:00 UTC)",
		},
		{
			name: "sockets near the limit without a baseline", prev: prevWithFlags,
			edit: func(in *Input) { in.Sample.Load.SocketsOpen, in.Sample.Load.SocketsLimit = 64000, 65504 },
			want: map[string]Severity{"overload-sockets_exhausted": Warning}, contains: "LimitNOFILE",
		},
		{
			name: "MetricsPort down while tor runs", prev: prevWithFlags,
			edit: func(in *Input) { in.Sample, in.SampleErr = nil, "MetricsPort returned 403 Forbidden" },
			want: map[string]Severity{"metricsport-down": Info}, unknown: []string{prefixOverload},
		},
		{
			name: "accounting over the threshold", prev: prevWithFlags,
			edit: func(in *Input) { in.Accounting = acct(95*gib, 100*gib, time.Time{}) },
			want: map[string]Severity{"accounting-high": Warning}, contains: "95.0 GiB of 100.0 GiB used (95%",
		},
		{
			name: "accounting projected to run out", prev: prevWithFlags,
			edit: func(in *Input) { in.Accounting = acct(50*gib, 100*gib, testNow.Add(10*24*time.Hour)) },
			want: map[string]Severity{"accounting-runs-out": Warning}, contains: "used up around 2026-10-12",
		},
		{
			name: "accounting exhausted", prev: prevWithFlags,
			edit: func(in *Input) { in.Accounting = acct(100*gib, 100*gib, testNow) },
			want: map[string]Severity{"accounting-exhausted": Critical},
		},
		{
			name: "accounting threshold is configurable", prev: prevWithFlags,
			cfg:  func(c *Config) { c.AccountingThreshold = 50 },
			edit: func(in *Input) { in.Accounting = acct(60*gib, 100*gib, time.Time{}) },
			want: map[string]Severity{"accounting-high": Warning},
		},
		{
			name: "accounting unreadable", prev: prevWithFlags,
			edit: func(in *Input) { in.AccountingErr = "permission denied" },
			want: map[string]Severity{}, unknown: []string{prefixAccounting},
		},
		{
			name: "tor update available", prev: prevWithFlags,
			cfg:  func(c *Config) { c.CheckUpdates = true },
			edit: func(in *Input) { in.TorInstalled, in.TorCandidate = "0.4.9.12-1~deb13+1", "0.4.9.13-1~deb13+1" },
			want: map[string]Severity{"tor-update": Info},
		},
		{
			name: "updates ignored unless enabled", prev: prevWithFlags,
			edit: func(in *Input) { in.TorInstalled, in.TorCandidate = "1", "2" },
			want: map[string]Severity{},
		},
		{
			name: "no relay configured", prev: prevWithFlags,
			edit:    func(in *Input) { in.Report.Relay.Configured = false; in.Report.Service.Active = false },
			want:    map[string]Severity{"relay-not-configured": Critical},
			unknown: []string{prefixDirectory, prefixFlag, prefixOverload, prefixAccounting, idUpdate},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := healthy(t)
			if tt.edit != nil {
				tt.edit(&in)
			}
			cfg := DefaultConfig()
			if tt.cfg != nil {
				tt.cfg(&cfg)
			}
			ev := Evaluate(in, tt.prev, cfg)
			got := map[string]Severity{}
			var events []string
			bodies := ""
			for _, a := range ev.Alerts {
				got[a.ID] = a.Severity
				if a.Event {
					events = append(events, a.ID)
				}
				if a.Title == "" || a.Body == "" {
					t.Errorf("alert %s lacks a title or body", a.ID)
				}
				bodies += a.Body + "\n"
			}
			if len(got) != len(tt.want) {
				t.Errorf("alerts %v, want %v", got, tt.want)
			}
			for id, sev := range tt.want {
				if got[id] != sev {
					t.Errorf("%s: severity %v (present %v), want %v", id, got[id], hasKey(got, id), sev)
				}
			}
			if !slices.Equal(events, tt.events) {
				t.Errorf("events %v, want %v", events, tt.events)
			}
			if !slices.Equal(ev.Unknown, tt.unknown) {
				t.Errorf("unknown %v, want %v", ev.Unknown, tt.unknown)
			}
			if tt.contains != "" && !strings.Contains(bodies, tt.contains) {
				t.Errorf("no body contains %q:\n%s", tt.contains, bodies)
			}
		})
	}
}

func hasKey(m map[string]Severity, k string) bool { _, ok := m[k]; return ok }

func TestEvaluateObservations(t *testing.T) {
	in := healthy(t)
	in.Report.Directory.Flags = []string{"Fast", "Running", "Valid"}
	prev := Observed{Flags: []string{"Guard"}, Sample: realSample(t, testNow.Add(-time.Hour))}
	ev := Evaluate(in, prev, DefaultConfig())
	if !ev.Observed.Published || !slices.Equal(ev.Observed.Flags, []string{"Fast"}) || ev.Observed.Sample != in.Sample {
		t.Errorf("observed %+v", ev.Observed)
	}

	// Without a fresh sample or directory answer the old observations stay.
	in.Sample, in.SampleErr = nil, "refused"
	in.Report.Directory, in.Report.DirectoryError = nil, "timeout"
	prev.Published = true
	prev.Overload = map[string]OverloadMark{"oom": {At: testNow.Add(-time.Hour), Severity: Warning, Summary: "x"}}
	ev = Evaluate(in, prev, DefaultConfig())
	if ev.Observed.Sample != prev.Sample || !slices.Equal(ev.Observed.Flags, prev.Flags) || !ev.Observed.Published || len(ev.Observed.Overload) != 1 {
		t.Errorf("observed %+v", ev.Observed)
	}

	// Overload severity never drops inside the hold period.
	in = healthy(t)
	prev = Observed{Sample: realSample(t, testNow.Add(-5*time.Minute)),
		Overload: map[string]OverloadMark{"onionskins_dropped": {At: testNow.Add(-time.Hour), Severity: Warning, Summary: "big"}}}
	in.Sample.Load.OnionskinsDropped.Ntor += 1 // a single drop alone would be info
	ev = Evaluate(in, prev, DefaultConfig())
	if m := ev.Observed.Overload["onionskins_dropped"]; m.Severity != Warning || !m.At.Equal(testNow) {
		t.Errorf("mark %+v", m)
	}
}

func TestEvaluateKeysAndBridge(t *testing.T) {
	find := func(ev Evaluation, id string) (Alert, bool) {
		for _, a := range ev.Alerts {
			if a.ID == id {
				return a, true
			}
		}
		return Alert{}, false
	}

	in := healthy(t)
	in.Report.Keys = &keys.State{Offline: true, CertExpires: testNow.Add(3 * 24 * time.Hour)}
	a, ok := find(Evaluate(in, Observed{}, Config{}), "signing-key")
	if !ok || a.Severity != Warning || !strings.Contains(a.Body, "expires in 3 days") {
		t.Errorf("expiring: %+v %v", a, ok)
	}
	in.Report.Keys.CertExpires = testNow.Add(-time.Hour)
	if a, ok := find(Evaluate(in, Observed{}, Config{}), "signing-key"); !ok || a.Severity != Critical {
		t.Errorf("expired: %+v %v", a, ok)
	}
	in.Report.Keys.CertExpires = testNow.Add(20 * 24 * time.Hour)
	if _, ok := find(Evaluate(in, Observed{}, Config{}), "signing-key"); ok {
		t.Error("a certificate valid for 20 days needs no alert")
	}

	in = healthy(t)
	in.Report.Bridge = &status.Bridge{Transport: "obfs4", Plugin: "/usr/bin/obfs4proxy", PluginInstalled: true, Port: 443}
	a, ok = find(Evaluate(in, Observed{}, Config{}), "bridge-transport")
	if !ok || a.Severity != Critical || !strings.Contains(a.Body, "not listening on TCP 443") {
		t.Errorf("bridge: %+v %v", a, ok)
	}
	in.Report.Bridge.Listening = true
	if _, ok := find(Evaluate(in, Observed{}, Config{}), "bridge-transport"); ok {
		t.Error("a listening bridge needs no alert")
	}
}
