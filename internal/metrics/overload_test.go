package metrics

import (
	"os"
	"strings"
	"testing"
	"time"
)

// realSample parses testdata/metricsport-0.4.9.13.txt, a page trimmed from
// a real tor 0.4.9.13 MetricsPort.
func realSample(t *testing.T, at time.Time) Sample {
	t.Helper()
	data, err := os.ReadFile("testdata/metricsport-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	s.At = at
	return s
}

func TestParseRealLoadSeries(t *testing.T) {
	s := realSample(t, time.Time{})
	if s.Read != 40328276 || s.Written != 2845970 || s.Connections != 206 {
		t.Errorf("traffic/connections = %d/%d/%d", s.Read, s.Written, s.Connections)
	}
	l := s.Load
	if !l.Seen || l.SocketsOpen != 209 || l.SocketsLimit != 1048544 {
		t.Errorf("sockets: %+v", l)
	}
	if l.OnionskinsDropped != (Onionskins{}) || l.OOMBytes.Total() != 0 || l.TCPExhaustion != 0 || l.RateLimitRead != 0 {
		t.Errorf("a fresh relay has no overload counters: %+v", l)
	}

	// Every load series and label value from the real page is understood.
	page := `tor_relay_traffic_bytes{direction="read"} 1
tor_relay_load_onionskins_total{type="tap",action="processed"} 1
tor_relay_load_onionskins_total{type="tap",action="dropped"} 2
tor_relay_load_onionskins_total{type="fast",action="processed"} 3
tor_relay_load_onionskins_total{type="fast",action="dropped"} 4
tor_relay_load_onionskins_total{type="ntor",action="processed"} 5
tor_relay_load_onionskins_total{type="ntor",action="dropped"} 6
tor_relay_load_onionskins_total{type="ntor_v3",action="processed"} 7
tor_relay_load_onionskins_total{type="ntor_v3",action="dropped"} 8
tor_relay_load_onionskins_total{type="future",action="dropped"} 99
tor_relay_load_onionskins_total{type="ntor",action="queued"} 99
tor_relay_load_oom_bytes_total{subsys="cell"} 10
tor_relay_load_oom_bytes_total{subsys="dns"} 20
tor_relay_load_oom_bytes_total{subsys="geoip"} 30
tor_relay_load_oom_bytes_total{subsys="hsdir"} 40
tor_relay_load_tcp_exhaustion_total 11
tor_relay_load_global_rate_limit_reached_total{side="read"} 12
tor_relay_load_global_rate_limit_reached_total{side="write"} 13
tor_relay_load_socket_total{state="opened"} 14
tor_relay_load_socket_total 15
`
	got, err := Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	want := Load{
		Seen:                true,
		OnionskinsProcessed: Onionskins{TAP: 1, Fast: 3, Ntor: 5, NtorV3: 7},
		OnionskinsDropped:   Onionskins{TAP: 2, Fast: 4, Ntor: 6, NtorV3: 8},
		OOMBytes:            OOMBytes{Cell: 10, DNS: 20, GeoIP: 30, HSDir: 40},
		TCPExhaustion:       11, RateLimitRead: 12, RateLimitWrite: 13, SocketsOpen: 14, SocketsLimit: 15,
	}
	if got.Load != want {
		t.Errorf("got  %+v\nwant %+v", got.Load, want)
	}
	if got.Load.OnionskinsDropped.NtorTotal() != 14 || got.Load.OOMBytes.Total() != 100 {
		t.Error("totals")
	}

	// tor before 0.4.7 has no load series.
	old, _ := Parse(strings.NewReader("tor_relay_traffic_bytes{direction=\"read\"} 1\n"))
	if old.Load.Seen {
		t.Error("no load series should leave Seen false")
	}
}

func TestAssessOverload(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Minute)
	base := func() Sample { return realSample(t, t0) }
	later := func(edit func(*Sample)) Sample {
		s := realSample(t, t1)
		s.Read += 1 << 20
		s.Written += 1 << 20
		edit(&s)
		return s
	}
	type want struct {
		signals   []Signal
		general   bool
		published map[Signal]bool
		summary   string
	}
	tests := []struct {
		name       string
		prev, cur  Sample
		want       want
		baseline   bool
		restarted  bool
		supported  bool
		windowSecs float64
	}{
		{
			name: "quiet window", prev: base(), cur: later(func(*Sample) {}),
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "ntor drops above tor's 1% threshold", prev: base(),
			cur: later(func(s *Sample) {
				s.Load.OnionskinsProcessed.Ntor += 3000
				s.Load.OnionskinsProcessed.NtorV3 += 900
				s.Load.OnionskinsDropped.Ntor += 80
				s.Load.OnionskinsDropped.NtorV3 += 20
			}),
			want:     want{signals: []Signal{SignalOnionskinsDropped}, general: true, published: map[Signal]bool{SignalOnionskinsDropped: true}, summary: "100 of 4000 ntor onionskins dropped (2.5%)"},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "a few drops stay below tor's threshold", prev: base(),
			cur: later(func(s *Sample) {
				s.Load.OnionskinsProcessed.Ntor += 5000
				s.Load.OnionskinsDropped.Ntor += 3
			}),
			want:     want{signals: []Signal{SignalOnionskinsDropped}, published: map[Signal]bool{SignalOnionskinsDropped: false}, summary: "3 of 5003 ntor onionskins dropped (0.1%)"},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "drops with too few requests to count", prev: base(),
			cur: later(func(s *Sample) {
				s.Load.OnionskinsProcessed.NtorV3 += 50
				s.Load.OnionskinsDropped.NtorV3 += 50
			}),
			want:     want{signals: []Signal{SignalOnionskinsDropped}, published: map[Signal]bool{SignalOnionskinsDropped: false}},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "TAP and fast drops are not part of the signal", prev: base(),
			cur: later(func(s *Sample) {
				s.Load.OnionskinsDropped.TAP += 500
				s.Load.OnionskinsDropped.Fast += 500
			}),
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "OOM, TCP exhaustion and rate limits", prev: base(),
			cur: later(func(s *Sample) {
				s.Load.OOMBytes.Cell += 3 << 20
				s.Load.OOMBytes.DNS += 1 << 19
				s.Load.TCPExhaustion += 4
				s.Load.RateLimitRead += 7
				s.Load.RateLimitWrite += 2
			}),
			want: want{
				signals: []Signal{SignalOOM, SignalTCPExhaustion, SignalRateLimited}, general: true,
				published: map[Signal]bool{SignalOOM: true, SignalTCPExhaustion: true, SignalRateLimited: true},
				summary:   "the out-of-memory handler freed 3.5 MiB",
			},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "rate limits alone are not overload-general", prev: base(),
			cur:      later(func(s *Sample) { s.Load.RateLimitWrite += 60 }),
			want:     want{signals: []Signal{SignalRateLimited}, published: map[Signal]bool{SignalRateLimited: true}, summary: "the global bandwidth limit was reached 60 times"},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "sockets near the limit without a baseline", prev: Sample{},
			cur: later(func(s *Sample) {
				s.Load.SocketsOpen, s.Load.SocketsLimit = 60000, 65504
				s.Load.OOMBytes.Cell = 1 << 30 // ignored: no baseline to compare
			}),
			want:      want{signals: []Signal{SignalSocketsExhausted}, published: map[Signal]bool{SignalSocketsExhausted: false}, summary: "60000 of 65504 sockets open (91%)"},
			supported: true,
		},
		{
			name: "socket limit reached", prev: base(),
			cur:      later(func(s *Sample) { s.Load.SocketsOpen, s.Load.SocketsLimit = 65503, 65504 }),
			want:     want{signals: []Signal{SignalSocketsExhausted}, published: map[Signal]bool{SignalSocketsExhausted: true}},
			baseline: true, supported: true, windowSecs: 300,
		},
		{
			name: "tor restarted: counters count from zero", prev: func() Sample {
				s := base()
				s.Load.OOMBytes.Cell = 1 << 30
				s.Load.TCPExhaustion = 9
				return s
			}(),
			cur: later(func(s *Sample) {
				s.Read, s.Written = 100, 100
				s.Load.TCPExhaustion = 2
			}),
			want:     want{signals: []Signal{SignalTCPExhaustion}, general: true, published: map[Signal]bool{SignalTCPExhaustion: true}, summary: "2 connections failed because no local TCP port was free"},
			baseline: true, restarted: true, supported: true, windowSecs: 300,
		},
		{
			name: "samples out of order are no baseline", prev: realSample(t, t1.Add(time.Hour)),
			cur:       later(func(s *Sample) { s.Load.TCPExhaustion = 5 }),
			supported: true,
		},
		{
			name: "tor without load series", prev: base(),
			cur: func() Sample { s := later(func(*Sample) {}); s.Load = Load{}; return s }(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := AssessOverload(tt.prev, tt.cur)
			if o.Baseline != tt.baseline || o.Restarted != tt.restarted || o.Supported != tt.supported {
				t.Errorf("baseline/restarted/supported = %v/%v/%v", o.Baseline, o.Restarted, o.Supported)
			}
			if o.Window().Seconds() != tt.windowSecs {
				t.Errorf("window %v", o.Window())
			}
			var got []Signal
			for _, f := range o.Findings {
				got = append(got, f.Signal)
				if f.Line != f.Signal.Line() || f.Summary == "" || f.Explanation == "" || f.Remedy == "" {
					t.Errorf("incomplete finding %+v", f)
				}
				if p, ok := tt.want.published[f.Signal]; ok && p != f.Published {
					t.Errorf("%s published = %v", f.Signal, f.Published)
				}
			}
			if strings.Join(sigStrings(got), ",") != strings.Join(sigStrings(tt.want.signals), ",") {
				t.Errorf("signals %v, want %v", got, tt.want.signals)
			}
			if o.General() != tt.want.general {
				t.Errorf("General() = %v", o.General())
			}
			if tt.want.summary != "" && len(o.Findings) > 0 && o.Findings[0].Summary != tt.want.summary {
				t.Errorf("summary %q, want %q", o.Findings[0].Summary, tt.want.summary)
			}
			for _, sig := range tt.want.signals {
				if !o.Fired(sig) {
					t.Errorf("Fired(%s) = false", sig)
				}
			}
		})
	}
}

func sigStrings(s []Signal) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = string(v)
	}
	return out
}

func TestSignalLines(t *testing.T) {
	want := map[Signal]string{
		SignalOnionskinsDropped: LineGeneral, SignalOOM: LineGeneral, SignalTCPExhaustion: LineGeneral,
		SignalSocketsExhausted: LineFDExhausted, SignalRateLimited: LineRateLimits,
	}
	if len(Signals) != len(want) {
		t.Fatalf("Signals has %d entries", len(Signals))
	}
	for _, s := range Signals {
		if s.Line() != want[s] {
			t.Errorf("%s.Line() = %s", s, s.Line())
		}
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 3 << 29: "1.5 GiB", 5 << 40: "5.0 TiB"} {
		if got := FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
