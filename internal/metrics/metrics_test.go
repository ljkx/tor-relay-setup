package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// page is trimmed from a real tor 0.4.9 MetricsPort.
const page = `# HELP tor_relay_connections Total number of opened connections
# TYPE tor_relay_connections gauge
tor_relay_connections{type="OR listener",direction="initiated",state="opened",family="ipv4"} 1
tor_relay_connections{type="OR",direction="initiated",state="opened",family="ipv4"} 198
tor_relay_connections{type="OR",direction="received",state="opened",family="ipv6"} 12
tor_relay_connections{type="OR",direction="received",state="closed",family="ipv4"} 40
tor_relay_connections{type="Exit",direction="initiated",state="opened",family="ipv4"} 7
# HELP tor_relay_traffic_bytes Traffic on relay connections
# TYPE tor_relay_traffic_bytes counter
tor_relay_traffic_bytes{direction="read"} 14248253
tor_relay_traffic_bytes{direction="written"} 1285250
tor_relay_load_socket_total 1048544
tor_relay_flag{type="Fast"} 0
`

func TestParse(t *testing.T) {
	s, err := Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	if s.Read != 14248253 || s.Written != 1285250 || s.Connections != 210 {
		t.Fatalf("got %+v", s)
	}
}

func TestParseRejectsOtherPages(t *testing.T) {
	if _, err := Parse(strings.NewReader("node_load1 0.5\n")); err == nil {
		t.Fatal("want an error for a page without tor counters")
	}
	if _, err := Parse(strings.NewReader("<html>not metrics</html>")); err == nil {
		t.Fatal("want an error for HTML")
	}
}

func TestParseLabelsEscapes(t *testing.T) {
	got := parseLabels(`a="x\"y", b="2"`)
	if got["a"] != `x"y` || got["b"] != "2" {
		t.Fatalf("got %v", got)
	}
	if got := parseLabels(`broken`); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if _, _, _, ok := splitSample(`x{a="1" 5`); ok {
		t.Fatal("unterminated labels should not parse")
	}
	if _, _, _, ok := splitSample(`x NaNa`); ok {
		t.Fatal("bad value should not parse")
	}
}

func TestBetween(t *testing.T) {
	t0 := time.Unix(1000, 0)
	a := Sample{At: t0, Read: 1000, Written: 2000}
	b := Sample{At: t0.Add(2 * time.Second), Read: 3000, Written: 6000}
	r, ok := Between(a, b)
	if !ok || r.Read != 1000 || r.Written != 2000 || r.Total() != 3000 {
		t.Fatalf("got %+v %v", r, ok)
	}
	if _, ok := Between(b, a); ok {
		t.Fatal("reversed samples should not give a rate")
	}
	restarted := Sample{At: t0.Add(4 * time.Second), Read: 10, Written: 10}
	if _, ok := Between(b, restarted); ok {
		t.Fatal("counter reset should not give a rate")
	}
}

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:9035":            "http://127.0.0.1:9035/metrics",
		"9035":                      "http://127.0.0.1:9035/metrics",
		"[::1]:9035":                "http://[::1]:9035/metrics",
		"127.0.0.1:9035 SomeFlag=1": "http://127.0.0.1:9035/metrics",
	} {
		got, err := URL(in)
		if err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost"} {
		if _, err := URL(bad); err == nil {
			t.Errorf("URL(%q) should fail", bad)
		}
	}
}

func TestScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	s, err := Scrape(context.Background(), srv.Client(), addr)
	if err != nil || s.Read != 14248253 || s.At.IsZero() {
		t.Fatalf("got %+v, %v", s, err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bad.Close()
	if _, err := Scrape(context.Background(), nil, strings.TrimPrefix(bad.URL, "http://")); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Fatalf("want a 403 error, got %v", err)
	}
	if _, err := Scrape(context.Background(), nil, ""); err == nil {
		t.Fatal("want an error without a MetricsPort")
	}
}
