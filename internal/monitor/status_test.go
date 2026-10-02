package monitor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health", "/-/ready":
			_, _ = w.Write([]byte("ok"))
		case "/api/v1/targets":
			_, _ = w.Write([]byte(`{"data":{"activeTargets":[{"labels":{"job":"prometheus"},"health":"up"},{"labels":{"job":"tor-relay-fleet"},"health":"up","lastError":""}]}}`))
		case "/api/v1/query":
			v := map[string]string{"tor_relay_fleet_relays": "6", "tor_relay_fleet_relays_running": "5", "tor_relay_fleet_hosts": "4", "tor_relay_fleet_hosts_up": "4", "tor_relay_fleet_attention": "1"}[r.URL.Query().Get("query")]
			_, _ = w.Write([]byte(`{"data":{"result":[{"value":[1790000000,"` + v + `"]}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := newFakeServer()
	for _, u := range Units {
		s.active[u] = true
	}
	s.Files[StatePath] = []byte(`{"domain":"grafana.example.org","admin_user":"tor-admin","fleet_path":"/fleet","inventory":"/etc/tor-relay-setup/fleet.toml"}`)
	s.Files[MonitorHome+"/.ssh/id_ed25519.pub"] = []byte(testKey + "\n")
	st := CollectStatus(context.Background(), s, StatusOptions{PrometheusURL: srv.URL, GrafanaURL: srv.URL})
	if !st.Healthy() || st.Fleet["relays_running"] != 5 {
		t.Fatalf("status %+v", st)
	}
	var b bytes.Buffer
	st.Write(&b)
	for _, want := range []string{"https://grafana.example.org/", "Fleet UI     https://grafana.example.org/fleet/", "5/6 relays running", "✓ caddy", "fleet authorize --key '" + testKey} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, b.String())
		}
	}

	s.active["grafana-server"] = false
	if CollectStatus(context.Background(), s, StatusOptions{PrometheusURL: srv.URL, GrafanaURL: srv.URL}).Healthy() {
		t.Error("healthy with grafana stopped")
	}
	empty := CollectStatus(context.Background(), newFakeServer(), StatusOptions{PrometheusURL: "http://127.0.0.1:1", GrafanaURL: "http://127.0.0.1:1"})
	b.Reset()
	empty.Write(&b)
	if empty.Healthy() || !strings.Contains(b.String(), "not installed") {
		t.Errorf("empty status:\n%s", b.String())
	}
}
