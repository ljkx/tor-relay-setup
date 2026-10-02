package status

import (
	"bytes"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

var loadNow = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)

// realLoadSample parses the trimmed real tor 0.4.9.13 MetricsPort page.
func realLoadSample(t *testing.T, at time.Time) metrics.Sample {
	t.Helper()
	data, err := os.ReadFile("../metrics/testdata/metricsport-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	s, err := metrics.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s.At = at
	return s
}

// fullLoadMetrics fills every part of LoadMetrics.
func fullLoadMetrics(t *testing.T) LoadMetrics {
	prev := realLoadSample(t, loadNow.Add(-5*time.Minute))
	cur := realLoadSample(t, loadNow)
	cur.Load.OnionskinsProcessed.Ntor += 5000
	cur.Load.OnionskinsDropped.Ntor += 100
	cur.Load.RateLimitWrite = 3
	o := metrics.AssessOverload(prev, cur)
	cfg, err := metrics.ParseAccountingConfig("100 GBytes", "sum", "month 1 00:00")
	if err != nil {
		t.Fatal(err)
	}
	a := metrics.AssessAccounting(cfg, metrics.AccountingUsage{Read: 30 << 30, Written: 20 << 30, LastWritten: loadNow}, loadNow)
	return LoadMetrics{
		MetricsPort: true, Sample: &cur, Overload: &o, Accounting: &a,
		Directory: &onionoo.Relay{OverloadGeneral: loadNow.Add(-2 * time.Hour)}, Now: loadNow,
	}
}

func TestWriteLoadPrometheus(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteLoadPrometheus(&buf, fullLoadMetrics(t)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# TYPE tor_relay_setup_metricsport_up gauge\ntor_relay_setup_metricsport_up{tor_instance=\"default\"} 1\n",
		"# TYPE tor_relay_setup_overload_onionskins_dropped_total counter\n" +
			`tor_relay_setup_overload_onionskins_dropped_total{tor_instance="default",type="tap"} 0` + "\n" +
			`tor_relay_setup_overload_onionskins_dropped_total{tor_instance="default",type="fast"} 0` + "\n" +
			`tor_relay_setup_overload_onionskins_dropped_total{tor_instance="default",type="ntor"} 100` + "\n",
		`tor_relay_setup_overload_onionskins_processed_total{tor_instance="default",type="ntor"} 5000`,
		`tor_relay_setup_overload_oom_bytes_total{tor_instance="default",subsys="hsdir"} 0`,
		"tor_relay_setup_overload_tcp_exhaustion_total{tor_instance=\"default\"} 0\n",
		`tor_relay_setup_overload_rate_limit_reached_total{tor_instance="default",side="write"} 3`,
		"tor_relay_setup_overload_sockets_open{tor_instance=\"default\"} 209\n",
		"tor_relay_setup_overload_sockets_limit{tor_instance=\"default\"} 1048544\n",
		`tor_relay_setup_overload_signal{tor_instance="default",signal="onionskins_dropped",line="overload-general"} 1`,
		`tor_relay_setup_overload_signal{tor_instance="default",signal="oom",line="overload-general"} 0`,
		`tor_relay_setup_overload_signal{tor_instance="default",signal="sockets_exhausted",line="overload-fd-exhausted"} 0`,
		`tor_relay_setup_overload_signal{tor_instance="default",signal="rate_limited",line="overload-ratelimits"} 1`,
		"tor_relay_setup_overload_general{tor_instance=\"default\"} 1\n",
		"tor_relay_setup_overload_window_seconds{tor_instance=\"default\"} 300\n",
		"tor_relay_setup_directory_overloaded{tor_instance=\"default\"} 1\n",
		"tor_relay_setup_directory_overload_general_timestamp_seconds{tor_instance=\"default\"} 1791669600\n",
		`tor_relay_setup_accounting_max_bytes{tor_instance="default",rule="sum"} 107374182400`,
		`tor_relay_setup_accounting_used_bytes{tor_instance="default",rule="sum"} 53687091200`,
		"tor_relay_setup_accounting_period_start_timestamp_seconds{tor_instance=\"default\"} 1790812800\n",
		"tor_relay_setup_accounting_period_end_timestamp_seconds{tor_instance=\"default\"} 1793491200\n",
		"tor_relay_setup_accounting_hibernating{tor_instance=\"default\"} 0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// 50 GiB in 10 of 31 days: 155 GiB by the end, 100 GiB on 21 October.
	for name, want := range map[string]float64{
		`tor_relay_setup_accounting_projected_bytes{tor_instance="default",rule="sum"}`:   155 << 30,
		`tor_relay_setup_accounting_exhaustion_timestamp_seconds{tor_instance="default"}`: 1792540800,
	} {
		_, rest, ok := strings.Cut(out, "\n"+name+" ")
		v, err := strconv.ParseFloat(strings.SplitN(rest, "\n", 2)[0], 64)
		if !ok || err != nil || math.Abs(v-want) > 2 {
			t.Errorf("%s = %v (%v), want %v", name, v, err, want)
		}
	}
	// Every family has HELP and TYPE, and no line is malformed.
	families := 0
	for line := range strings.Lines(out) {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			families++
		case strings.HasPrefix(line, "# TYPE "):
			if !strings.HasSuffix(line, " gauge\n") && !strings.HasSuffix(line, " counter\n") {
				t.Errorf("bad TYPE %q", line)
			}
		case !strings.HasPrefix(line, "tor_relay_setup_") || strings.Count(line, " ") != 1:
			t.Errorf("bad sample line %q", line)
		}
	}
	if families != strings.Count(out, "# TYPE ") || families < 20 {
		t.Errorf("%d families", families)
	}
}

func TestWriteLoadPrometheusPartial(t *testing.T) {
	tests := []struct {
		name   string
		m      LoadMetrics
		want   []string
		absent []string
	}{
		{name: "nothing", m: LoadMetrics{}, absent: []string{"tor_relay_setup_"}},
		{
			name: "MetricsPort down", m: LoadMetrics{MetricsPort: true},
			want: []string{`tor_relay_setup_metricsport_up{tor_instance="default"} 0`}, absent: []string{"overload_", "accounting_"},
		},
		{
			name: "named instance", m: LoadMetrics{Instance: "fast2", MetricsPort: true},
			want: []string{`tor_relay_setup_metricsport_up{tor_instance="fast2"} 0`}, absent: []string{"default"},
		},
		{
			name: "no baseline yet", m: func() LoadMetrics {
				s := realLoadSample(t, loadNow)
				o := metrics.AssessOverload(metrics.Sample{}, s)
				return LoadMetrics{MetricsPort: true, Sample: &s, Overload: &o}
			}(),
			want: []string{`tor_relay_setup_overload_sockets_open{tor_instance="default"} 209`}, absent: []string{"overload_signal", "overload_general"},
		},
		{
			name: "accounting off, not overloaded", m: LoadMetrics{
				Accounting: &metrics.Accounting{}, Directory: &onionoo.Relay{}, Now: loadNow,
			},
			want: []string{`tor_relay_setup_directory_overloaded{tor_instance="default"} 0`}, absent: []string{"accounting_", "overload_general_timestamp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteLoadPrometheus(&buf, tt.m); err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("lacks %q:\n%s", w, buf.String())
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(buf.String(), a) {
					t.Errorf("has %q:\n%s", a, buf.String())
				}
			}
		})
	}
}
