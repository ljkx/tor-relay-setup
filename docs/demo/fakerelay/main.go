// Command fakerelay stands in for a busy relay's MetricsPort and for Tor
// Metrics (Onionoo) while the README demos are recorded, so the console's
// live traffic and history cards have something to show. docs/demo/demo-env.sh
// starts it when it is on PATH; it is never part of a release.
//
//	fakerelay [-metrics 127.0.0.1:9035] [-onionoo 127.0.0.1:9036]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"
)

const (
	fingerprint = "7D4698A1B2C3D4E5F60718293A4B5C6D7E8F9012"
	familyID    = "flIHuuYy2vCWg+FgNibpOOHpRQ7rALbVUlS0WMmmuI8"
)

var start = time.Now()

// traffic integrates rate(t) = base + amp·sin(ωt) + amp/3·sin(3ωt+φ), so
// the counters only ever grow and the measured rate wanders smoothly.
func traffic(base, amp, phase float64) uint64 {
	t := time.Since(start).Seconds()
	w := 2 * math.Pi / 40
	v := base*t + amp/w*(1-math.Cos(w*t)) + amp/3/(3*w)*(math.Cos(phase)-math.Cos(3*w*t+phase))
	return uint64(4.2e11 + v)
}

func metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE tor_relay_traffic_bytes counter\n")
	fmt.Fprintf(w, "tor_relay_traffic_bytes{direction=\"read\"} %d\n", traffic(5.6e6, 1.9e6, 0))
	fmt.Fprintf(w, "tor_relay_traffic_bytes{direction=\"written\"} %d\n", traffic(5.4e6, 1.8e6, 0.6))
	fmt.Fprintf(w, "# TYPE tor_relay_connections gauge\n")
	conns := 1480 + int(40*math.Sin(time.Since(start).Seconds()/9))
	fmt.Fprintf(w, "tor_relay_connections{type=\"OR\",direction=\"received\",state=\"opened\",family=\"ipv4\"} %d\n", conns)
	fmt.Fprintf(w, "tor_relay_connections{type=\"OR\",direction=\"initiated\",state=\"opened\",family=\"ipv4\"} %d\n", conns/3)

	// A healthy relay's load counters (same series as tor 0.4.9): busy
	// handshakes, nothing dropped, plenty of sockets left.
	handshakes := 9_400_000 + uint64(time.Since(start).Seconds()*310)
	fmt.Fprintf(w, "# TYPE tor_relay_load_socket_total gauge\n")
	fmt.Fprintf(w, "tor_relay_load_socket_total{state=\"opened\"} %d\n", conns+conns/3+40)
	fmt.Fprintf(w, "tor_relay_load_socket_total 1048544\n")
	fmt.Fprintf(w, "# TYPE tor_relay_load_global_rate_limit_reached_total counter\n")
	fmt.Fprintf(w, "tor_relay_load_global_rate_limit_reached_total{side=\"read\"} 0\n")
	fmt.Fprintf(w, "tor_relay_load_global_rate_limit_reached_total{side=\"write\"} 0\n")
	fmt.Fprintf(w, "# TYPE tor_relay_load_tcp_exhaustion_total counter\n")
	fmt.Fprintf(w, "tor_relay_load_tcp_exhaustion_total 0\n")
	fmt.Fprintf(w, "# TYPE tor_relay_load_oom_bytes_total counter\n")
	fmt.Fprintf(w, "tor_relay_load_oom_bytes_total{subsys=\"cell\"} 0\n")
	fmt.Fprintf(w, "# TYPE tor_relay_load_onionskins_total counter\n")
	fmt.Fprintf(w, "tor_relay_load_onionskins_total{type=\"ntor\",action=\"processed\"} %d\n", handshakes)
	fmt.Fprintf(w, "tor_relay_load_onionskins_total{type=\"ntor\",action=\"dropped\"} 0\n")
	fmt.Fprintf(w, "tor_relay_load_onionskins_total{type=\"ntor_v3\",action=\"processed\"} %d\n", handshakes/4)
	fmt.Fprintf(w, "tor_relay_load_onionskins_total{type=\"ntor_v3\",action=\"dropped\"} 0\n")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func details(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"version": "8.0", "relays": []any{map[string]any{
		"nickname": "ExampleRelay", "fingerprint": fingerprint, "running": true,
		"flags":      []string{"Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"},
		"first_seen": "2026-03-14 08:00:00", "last_seen": time.Now().UTC().Format(time.DateTime),
		"advertised_bandwidth": 13_100_000, "observed_bandwidth": 13_400_000, "consensus_weight": 41_200,
		"platform": "Tor 0.4.9.13 on Linux", "or_addresses": []string{"203.0.113.5:9001", "[2001:db8::5]:9001"},
		"family_ids": []string{familyID}, "guard_probability": 0.00031, "middle_probability": 0.00024,
	}}})
}

// history is a month of daily averages: a ramp-up after a restart, then a
// steady relay with weekend dips.
func history(scale float64) map[string]any {
	const days = 30
	values := make([]int, days)
	for i := range values {
		v := 0.82 + 0.1*math.Sin(float64(i)/2.3)
		if i%7 == 5 || i%7 == 6 {
			v -= 0.12
		}
		if i < 4 {
			v *= float64(i+1) / 5
		}
		values[i] = int(v * 999)
	}
	last := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	return map[string]any{"1_month": map[string]any{
		"first": last.Add(-(days - 1) * 24 * time.Hour).Format(time.DateTime), "last": last.Format(time.DateTime),
		"interval": 86400, "factor": scale / 999, "count": days, "values": values,
	}}
}

func bandwidth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"version": "8.0", "relays": []any{map[string]any{
		"fingerprint": fingerprint, "read_history": history(7.1e6), "write_history": history(6.9e6),
	}}})
}

func summary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"version": "8.0", "relays": []any{
		map[string]any{"n": "ExampleRelay", "f": fingerprint, "r": true, "a": []string{"203.0.113.5"}},
	}})
}

func serve(addr string, mux *http.ServeMux) {
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func main() {
	metricsAddr := flag.String("metrics", "127.0.0.1:9035", "MetricsPort address")
	onionooAddr := flag.String("onionoo", "127.0.0.1:9036", "Onionoo address")
	flag.Parse()

	m := http.NewServeMux()
	m.HandleFunc("/metrics", metrics)
	o := http.NewServeMux()
	o.HandleFunc("/details", details)
	o.HandleFunc("/bandwidth", bandwidth)
	o.HandleFunc("/summary", summary)

	go serve(*metricsAddr, m)
	serve(*onionooAddr, o)
}
