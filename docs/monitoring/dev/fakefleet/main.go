// Command fakefleet serves a synthetic fleet on /metrics in the format of
// docs/monitoring/fleet-metrics.md, behind a bearer token, so the
// Prometheus rules and Grafana dashboards can be checked without relays.
// Counters grow with time; a few relays have problems on purpose (an
// overloaded guard, an inconsistent family, an expiring certificate, an
// unreachable host). It stands in for `tor-relay-setup fleet serve --demo`.
//
//	go run ./docs/monitoring/dev/fakefleet -listen 127.0.0.1:9850 -token-file token
package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type relay struct {
	host, inst, nick, fp, role       string
	version, country, as, asName     string
	transport                        string
	weight                           float64 // consensus weight
	guardP, middleP, exitP           float64
	bw                               float64 // bytes/s written on average
	flags                            []string
	accounting                       bool
	overloaded, inconsistent, expiry bool
	stopped                          bool
}

var hosts = []struct{ name, state, tool string }{
	{"fra1.example.net", "ok", "v3.3.0"},
	{"ams1.example.net", "ok", "v3.3.0"},
	{"nyc1.example.net", "ok", "v3.2.0"},
	{"sin1.example.net", "ok", "v3.3.0"},
	{"hel1.example.net", "unreachable", ""},
	{"waw1.example.net", "no_probe", ""},
}

var relays = []relay{
	{host: "fra1.example.net", inst: "default", nick: "TorFleetFra1", fp: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345671", role: "guard", version: "0.4.9.3", country: "de", as: "AS24940", asName: "Hetzner Online GmbH",
		weight: 41000, guardP: 0.00061, middleP: 0.00022, bw: 28e6, flags: []string{"Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"}},
	{host: "fra1.example.net", inst: "second", nick: "TorFleetFra2", fp: "B1B2C3D4E5F60718293A4B5C6D7E8F9012345672", role: "guard", version: "0.4.9.3", country: "de", as: "AS24940", asName: "Hetzner Online GmbH",
		weight: 38000, guardP: 0.00057, middleP: 0.00020, bw: 25e6, flags: []string{"Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"}, overloaded: true},
	{host: "ams1.example.net", inst: "default", nick: "TorFleetAms1", fp: "C1B2C3D4E5F60718293A4B5C6D7E8F9012345673", role: "exit", version: "0.4.9.3", country: "nl", as: "AS60781", asName: "LeaseWeb Netherlands B.V.",
		weight: 52000, middleP: 0.00010, exitP: 0.0021, bw: 35e6, flags: []string{"Exit", "Fast", "Running", "Stable", "V2Dir", "Valid"}, accounting: true},
	{host: "nyc1.example.net", inst: "default", nick: "TorFleetNyc1", fp: "D1B2C3D4E5F60718293A4B5C6D7E8F9012345674", role: "middle", version: "0.4.8.17", country: "us", as: "AS14061", asName: "DigitalOcean, LLC",
		weight: 12000, middleP: 0.00031, bw: 9e6, flags: []string{"Fast", "Running", "V2Dir", "Valid"}, inconsistent: true, expiry: true},
	{host: "sin1.example.net", inst: "default", nick: "TorFleetSin1", fp: "E1B2C3D4E5F60718293A4B5C6D7E8F9012345675", role: "middle", version: "0.4.9.3", country: "sg", as: "AS16509", asName: "Amazon.com, Inc.",
		weight: 8000, middleP: 0.00019, bw: 6e6, flags: []string{"Fast", "Running", "Stable", "Valid"}, accounting: true},
	{host: "sin1.example.net", inst: "bridge", nick: "TorFleetBridge1", fp: "F1B2C3D4E5F60718293A4B5C6D7E8F9012345676", role: "bridge", version: "0.4.9.3", country: "sg", as: "AS16509", asName: "Amazon.com, Inc.",
		transport: "obfs4", bw: 1.5e6, flags: []string{"Fast", "Running", "Stable", "Valid"}},
}

// start is when the synthetic counters began; fixed, so a backfill and a
// later live run continue the same series.
var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func main() {
	listen := flag.String("listen", "127.0.0.1:9850", "listen address")
	tokenFile := flag.String("token-file", "", "file with the bearer token Prometheus sends (empty: no auth)")
	privacy := flag.Bool("privacy", false, "leave per-relay traffic and connections out, like privacy = true")
	backfill := flag.String("openmetrics", "", "write the last -days of samples as OpenMetrics to this file (for promtool tsdb create-blocks-from openmetrics) and exit")
	days := flag.Int("days", 7, "with -openmetrics: days of history")
	step := flag.Duration("step", time.Minute, "with -openmetrics: sample interval")
	flag.Parse()
	if *backfill != "" {
		if err := writeOpenMetrics(*backfill, *days, *step, *privacy); err != nil {
			log.Fatal(err)
		}
		return
	}
	token := ""
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatal(err)
		}
		token = strings.TrimSpace(string(data))
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, render(time.Now(), *privacy))
	})
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("fakefleet on http://%s/metrics (privacy=%v)", *listen, *privacy)
	log.Fatal(srv.ListenAndServe())
}

// writeOpenMetrics writes timestamped samples from days ago until now
// (minus one step, so live scrapes continue the history).
func writeOpenMetrics(path string, days int, step time.Duration, privacy bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	now := time.Now()
	for t := now.Add(-time.Duration(days) * 24 * time.Hour); t.Before(now.Add(-step)); t = t.Add(step) {
		ts := fmt.Sprintf(" %d\n", t.Unix())
		for _, line := range strings.Split(render(t, privacy), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, err := f.WriteString(line + ts); err != nil {
				_ = f.Close()
				return err
			}
		}
	}
	if _, err := f.WriteString("# EOF\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type writer struct {
	b    strings.Builder
	seen map[string]bool
}

func (w *writer) metric(name, typ, help string) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if w.seen[name] {
		return
	}
	w.seen[name] = true
	fmt.Fprintf(&w.b, "# HELP tor_relay_fleet_%s %s\n# TYPE tor_relay_fleet_%s %s\n", name, help, name, typ)
}

func (w *writer) sample(name string, labels map[string]string, v float64) {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%q", k, labels[k])
	}
	fmt.Fprintf(&w.b, "tor_relay_fleet_%s{%s} %g\n", name, strings.Join(parts, ","), v)
}

func (w *writer) plain(name, typ, help string, v float64) {
	w.metric(name, typ, help)
	fmt.Fprintf(&w.b, "tor_relay_fleet_%s %g\n", name, v)
}

func with(base map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// wave varies a value by ±20% over a day so graphs are not flat.
func wave(now time.Time, phase float64) float64 {
	return 1 + 0.2*math.Sin(2*math.Pi*(float64(now.Unix())/86400+phase))
}

func render(now time.Time, privacy bool) string {
	var w writer
	secs := now.Sub(start).Seconds()
	unix := float64(now.Unix())
	up := map[string]bool{}
	for _, h := range hosts {
		up[h.name] = h.state == "ok"
	}

	var totWeight, totFrac, totG, totM, totE, totAdv, totObs, totRead, totWritten, totConn float64
	running := 0
	visible := 0
	for i, r := range relays {
		if !up[r.host] {
			continue
		}
		visible++
		l := map[string]string{"host": r.host, "tor_instance": r.inst, "nickname": r.nick, "fingerprint": r.fp, "role": r.role}
		ph := float64(i) / 7
		w.metric("relay_info", "gauge", "Relay metadata.")
		w.sample("relay_info", with(l, "version", r.version, "country", r.country, "as", r.as, "as_name", r.asName, "transport", r.transport), 1)
		active := 1.0
		if r.stopped {
			active = 0
		} else {
			running++
		}
		w.metric("relay_service_active", "gauge", "1 when the tor unit is active.")
		w.sample("relay_service_active", l, active)
		w.metric("relay_listener", "gauge", "1 when the ORPort listens.")
		w.metric("relay_reachable", "gauge", "1 when tor's self-test confirmed reachability.")
		for _, fam := range []string{"ipv4", "ipv6"} {
			w.sample("relay_listener", with(l, "family", fam), active)
			w.sample("relay_reachable", with(l, "family", fam), active)
		}
		warnings := 0.0
		if r.inconsistent {
			warnings++
		}
		if r.expiry {
			warnings++
		}
		w.metric("relay_warnings", "gauge", "Number of status warnings.")
		w.sample("relay_warnings", l, warnings)
		published := 1.0
		w.metric("relay_published", "gauge", "1 when Tor Metrics lists the relay.")
		w.sample("relay_published", l, published)
		w.metric("relay_running", "gauge", "1 when Tor Metrics reports it running.")
		w.sample("relay_running", l, active)
		w.metric("relay_flag", "gauge", "1 per flag the relay holds.")
		for _, f := range r.flags {
			w.sample("relay_flag", with(l, "flag", f), 1)
		}
		if r.role != "bridge" {
			frac := r.weight / 95e6
			for _, m := range []struct {
				n string
				v float64
			}{
				{"relay_consensus_weight", r.weight}, {"relay_consensus_weight_fraction", frac},
				{"relay_guard_probability", r.guardP}, {"relay_middle_probability", r.middleP}, {"relay_exit_probability", r.exitP},
			} {
				w.metric(m.n, "gauge", "From Tor Metrics.")
				w.sample(m.n, l, m.v)
			}
			totWeight += r.weight
			totFrac += frac
			totG += r.guardP
			totM += r.middleP
			totE += r.exitP
		}
		adv, obs := r.bw*1.6, r.bw*1.3
		totAdv += adv
		totObs += obs
		w.metric("relay_advertised_bandwidth_bytes", "gauge", "Advertised bandwidth, bytes/s.")
		w.sample("relay_advertised_bandwidth_bytes", l, adv)
		w.metric("relay_observed_bandwidth_bytes", "gauge", "Observed bandwidth, bytes/s.")
		w.sample("relay_observed_bandwidth_bytes", l, obs)
		w.metric("relay_first_seen_timestamp_seconds", "gauge", "First seen by Tor Metrics.")
		w.sample("relay_first_seen_timestamp_seconds", l, unix-float64(400+90*i)*86400)
		w.metric("relay_last_restarted_timestamp_seconds", "gauge", "Last restart.")
		w.sample("relay_last_restarted_timestamp_seconds", l, unix-float64(3+5*i)*86400-float64(i)*3600)

		// The counter is the integral of bw * (1 + 0.2 sin(day)): monotonic,
		// with a daily rhythm in its rate.
		day := 2 * math.Pi * (secs/86400 + ph)
		written := r.bw * (secs + 0.2*86400/(2*math.Pi)*(1-math.Cos(day)))
		read := written * 1.02
		totRead += read
		totWritten += written
		conns := math.Round(3000 * r.bw / 25e6 * wave(now, ph))
		totConn += conns
		if !privacy {
			w.metric("relay_traffic_bytes_total", "counter", "Relay traffic from the MetricsPort.")
			w.sample("relay_traffic_bytes_total", with(l, "direction", "read"), math.Round(read))
			w.sample("relay_traffic_bytes_total", with(l, "direction", "written"), math.Round(written))
			w.metric("relay_or_connections", "gauge", "Open OR connections.")
			w.sample("relay_or_connections", l, conns)
		}
		w.metric("relay_onionskins_total", "counter", "Onionskins by type and action.")
		rate := r.bw / 25e6 * 40
		dropShare := 0.0
		if r.overloaded {
			dropShare = 0.015
		}
		for _, t := range []struct {
			typ   string
			share float64
		}{{"ntor_v3", 0.7}, {"ntor", 0.28}, {"fast", 0.02}} {
			n := rate * t.share * secs
			w.sample("relay_onionskins_total", with(l, "type", t.typ, "action", "processed"), math.Round(n))
			dropped := 0.0
			if t.typ != "fast" {
				dropped = math.Round(n * dropShare)
			}
			w.sample("relay_onionskins_total", with(l, "type", t.typ, "action", "dropped"), dropped)
		}
		w.metric("relay_oom_bytes_total", "counter", "Bytes freed by the OOM handler.")
		for _, s := range []string{"cell", "dns", "geoip", "hsdir"} {
			v := 0.0
			if r.overloaded && s == "cell" {
				v = math.Floor(secs/7200) * 3.5e6
			}
			w.sample("relay_oom_bytes_total", with(l, "subsys", s), v)
		}
		w.metric("relay_tcp_exhaustion_total", "counter", "TCP port exhaustion events.")
		w.sample("relay_tcp_exhaustion_total", l, 0)
		w.metric("relay_rate_limit_reached_total", "counter", "Global rate limit reached.")
		for _, side := range []string{"read", "write"} {
			v := 0.0
			if r.accounting {
				v = math.Floor(secs / 900)
			}
			w.sample("relay_rate_limit_reached_total", with(l, "side", side), v)
		}
		w.metric("relay_sockets_open", "gauge", "Open sockets.")
		w.sample("relay_sockets_open", l, math.Round(conns*1.1+40))
		w.metric("relay_sockets_limit", "gauge", "Socket limit.")
		w.sample("relay_sockets_limit", l, 65535)
		over := 0.0
		if r.overloaded {
			over = 1
			w.metric("relay_overload_general_timestamp_seconds", "gauge", "Onionoo overload_general_timestamp.")
			w.sample("relay_overload_general_timestamp_seconds", l, math.Floor((unix-5*3600)/3600)*3600)
		}
		w.metric("relay_overloaded", "gauge", "1 when Relay Search marks the relay overloaded.")
		w.sample("relay_overloaded", l, over)
		if r.accounting {
			period := 30 * 86400.0
			elapsed := math.Mod(unix, period)
			max := 8e12
			used := r.bw * elapsed * 2
			w.metric("relay_accounting_max_bytes", "gauge", "AccountingMax.")
			w.sample("relay_accounting_max_bytes", l, max)
			w.metric("relay_accounting_used_bytes", "gauge", "Used this period.")
			w.sample("relay_accounting_used_bytes", l, used)
			w.metric("relay_accounting_projected_bytes", "gauge", "Projected by period end.")
			w.sample("relay_accounting_projected_bytes", l, used/elapsed*period)
			w.metric("relay_accounting_period_end_timestamp_seconds", "gauge", "End of the accounting period.")
			w.sample("relay_accounting_period_end_timestamp_seconds", l, unix-elapsed+period)
		}
		expires := unix + float64(20+i)*86400
		if r.expiry {
			expires = unix + 4*86400
		}
		w.metric("relay_signing_cert_expiry_timestamp_seconds", "gauge", "Signing certificate expiry.")
		w.sample("relay_signing_cert_expiry_timestamp_seconds", l, expires)
		w.metric("relay_family_ids", "gauge", "FamilyIds in torrc.")
		w.sample("relay_family_ids", l, 1)
		w.metric("relay_family_keys_missing", "gauge", "FamilyIds without a secret key.")
		w.sample("relay_family_keys_missing", l, 0)
		consistent := 1.0
		if r.inconsistent {
			consistent = 0
		}
		w.metric("relay_family_consistent", "gauge", "1 when the FamilyId set matches the fleet majority.")
		w.sample("relay_family_consistent", l, consistent)
		if r.transport != "" {
			w.metric("relay_bridge_transport_listening", "gauge", "1 when the bridge transport listens.")
			w.sample("relay_bridge_transport_listening", with(l, "transport", r.transport), 1)
		}
	}

	attention := 0.0
	hostsUp, unreachable, noProbe := 0.0, 0.0, 0.0
	for _, h := range hosts {
		hl := map[string]string{"host": h.name}
		w.metric("host_up", "gauge", "1 for the host's current probe state.")
		for _, s := range []string{"ok", "unreachable", "no_probe"} {
			v := 0.0
			if s == h.state {
				v = 1
			}
			w.sample("host_up", with(hl, "state", s), v)
		}
		switch h.state {
		case "ok":
			hostsUp++
			w.metric("host_probe_duration_seconds", "gauge", "Last probe duration.")
			w.sample("host_probe_duration_seconds", hl, 0.8+0.3*wave(now, float64(len(h.name))))
			w.metric("host_last_success_timestamp_seconds", "gauge", "Last successful probe.")
			w.sample("host_last_success_timestamp_seconds", hl, unix-float64(int(unix)%60))
			w.metric("host_tool_info", "gauge", "tor-relay-setup version on the host.")
			w.sample("host_tool_info", with(hl, "version", h.tool), 1)
		case "unreachable":
			unreachable++
			attention++
			w.metric("host_last_success_timestamp_seconds", "gauge", "Last successful probe.")
			w.sample("host_last_success_timestamp_seconds", hl, unix-2*3600)
		default:
			noProbe++
			attention++
		}
	}
	for _, r := range relays {
		if up[r.host] && (r.overloaded || r.inconsistent || r.expiry) {
			attention++
		}
	}
	w.plain("relays", "gauge", "Relays in the inventory.", float64(len(relays)))
	w.plain("relays_running", "gauge", "Relays whose service is active.", float64(running))
	w.plain("hosts", "gauge", "Servers in the inventory.", float64(len(hosts)))
	w.plain("hosts_up", "gauge", "Servers probed successfully.", hostsUp)
	w.plain("hosts_unreachable", "gauge", "Unreachable servers.", unreachable)
	w.plain("hosts_without_probe", "gauge", "Servers without fleet-probe.", noProbe)
	w.plain("attention", "gauge", "Needs attention findings.", attention)
	w.plain("consensus_weight", "gauge", "Summed consensus weight.", totWeight)
	w.plain("consensus_weight_fraction", "gauge", "Summed consensus weight fraction.", totFrac)
	w.plain("guard_probability", "gauge", "Summed guard probability.", totG)
	w.plain("middle_probability", "gauge", "Summed middle probability.", totM)
	w.plain("exit_probability", "gauge", "Summed exit probability.", totE)
	w.plain("advertised_bandwidth_bytes", "gauge", "Summed advertised bandwidth.", totAdv)
	w.plain("observed_bandwidth_bytes", "gauge", "Summed observed bandwidth.", totObs)
	w.metric("traffic_bytes_total", "counter", "Summed relay traffic.")
	w.sample("traffic_bytes_total", map[string]string{"direction": "read"}, math.Round(totRead))
	w.sample("traffic_bytes_total", map[string]string{"direction": "written"}, math.Round(totWritten))
	w.plain("or_connections", "gauge", "Summed OR connections.", totConn)
	w.plain("probe_duration_seconds", "gauge", "Duration of the last probe round.", 2.4)
	w.plain("last_probe_timestamp_seconds", "gauge", "End of the last probe round.", unix-float64(int(unix)%60))
	w.plain("directory_last_update_timestamp_seconds", "gauge", "Last Tor Metrics refresh.", unix-float64(int(unix)%3600))
	_ = visible
	return w.b.String()
}
