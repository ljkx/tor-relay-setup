package status

import (
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
)

func TestMergeFamilies(t *testing.T) {
	in := `# HELP a_total A.
# TYPE a_total counter
a_total{tor_instance="default"} 1
# HELP b B.
# TYPE b gauge
b{tor_instance="default"} 2
# HELP a_total A.
# TYPE a_total counter
a_total{tor_instance="relay2"} 3
# HELP b B.
# TYPE b gauge
b{tor_instance="relay2"} 4
`
	want := `# HELP a_total A.
# TYPE a_total counter
a_total{tor_instance="default"} 1
a_total{tor_instance="relay2"} 3
# HELP b B.
# TYPE b gauge
b{tor_instance="default"} 2
b{tor_instance="relay2"} 4
`
	if got := mergeFamilies(in); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestWriteLoadPrometheusAllHasOneHeaderPerFamily(t *testing.T) {
	s := metrics.Sample{At: time.Unix(1_000_000, 0), Read: 1, Load: metrics.Load{Seen: true, TCPExhaustion: 2, SocketsOpen: 10, SocketsLimit: 100}}
	var b strings.Builder
	err := WriteLoadPrometheusAll(&b, []LoadMetrics{
		{Instance: "default", MetricsPort: true, Sample: &s},
		{Instance: "relay2", MetricsPort: true, Sample: &s},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	seen := map[string]bool{}
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "# TYPE ") {
			if seen[line] {
				t.Errorf("repeated header %q in\n%s", line, out)
			}
			seen[line] = true
		}
	}
	if !strings.Contains(out, `tor_instance="relay2"`) || !strings.Contains(out, `tor_instance="default"`) {
		t.Errorf("instances missing:\n%s", out)
	}
}
