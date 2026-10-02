package status

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// metricPrefix starts every exported metric name.
const metricPrefix = "tor_relay_setup_"

// WritePrometheus writes the report in the Prometheus text exposition
// format; see WritePrometheusAll.
func (r Report) WritePrometheus(w io.Writer) error { return WritePrometheusAll(w, []Report{r}) }

// WritePrometheusAll writes reports, one per tor instance, in the Prometheus
// text exposition format for node_exporter's textfile collector: one gauge
// family per metric, with # HELP and # TYPE lines, in a fixed order. Every
// sample carries an instance label ("default" or the instance name), and
// each family lists the instances in the order given.
//
// The Tor Metrics gauges (directory_*, consensus_weight,
// advertised_bandwidth_bytes) are left out for an instance whose state is
// unknown: no fingerprint yet, or the lookup failed. directory_published is
// 0 when Tor Metrics answered but does not list the relay.
func WritePrometheusAll(w io.Writer, reports []Report) error {
	var buf bytes.Buffer
	// gauge writes one family; each report contributes samples(r), which
	// may be none. A family without samples is left out entirely.
	gauge := func(name, help string, samples func(r Report) []sample) {
		var lines []string
		for _, r := range reports {
			inst := [2]string{"instance", instanceLabel(r)}
			for _, s := range samples(r) {
				labels := renderLabels(append([][2]string{inst}, s.labels...))
				lines = append(lines, metricPrefix+name+labels+" "+strconv.FormatInt(s.value, 10))
			}
		}
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&buf, "# HELP %s%s %s\n", metricPrefix, name, escapeHelp(help))
		fmt.Fprintf(&buf, "# TYPE %s%s gauge\n", metricPrefix, name)
		for _, l := range lines {
			buf.WriteString(l + "\n")
		}
	}
	one := func(v func(r Report) int64) func(Report) []sample {
		return func(r Report) []sample { return []sample{{value: v(r)}} }
	}
	flag := func(v func(r Report) bool) func(Report) []sample {
		return one(func(r Report) int64 { return b2i(v(r)) })
	}
	fam := func(v4, v6 func(r Report) bool) func(Report) []sample {
		return func(r Report) []sample {
			return []sample{
				{labels: [][2]string{{"family", "ipv4"}}, value: b2i(v4(r))},
				{labels: [][2]string{{"family", "ipv6"}}, value: b2i(v6(r))},
			}
		}
	}
	// listed returns v only for reports Tor Metrics answered for.
	listed := func(v func(r Report) int64) func(Report) []sample {
		return func(r Report) []sample {
			if r.Directory == nil || r.DirectoryError != "" {
				return nil
			}
			return []sample{{value: v(r)}}
		}
	}

	gauge("up", "1 when tor-relay-setup collected this report.", one(func(Report) int64 { return 1 }))
	gauge("info", "Relay identity and tor version; the value is always 1.", func(r Report) []sample {
		return []sample{{labels: [][2]string{{"version", r.Tor.Version}, {"nickname", r.Relay.Nickname}, {"fingerprint", r.Relay.Fingerprint}}, value: 1}}
	})
	gauge("relay_configured", "1 when the instance's torrc configures an ORPort.", flag(func(r Report) bool { return r.Relay.Configured }))
	gauge("tor_installed", "1 when the tor binary runs.", flag(func(r Report) bool { return r.Tor.Installed }))
	gauge("tor_supported", "1 when the installed tor version is accepted by the network.", flag(func(r Report) bool { return r.Tor.Supported }))
	gauge("service_active", "1 when the tor systemd unit is active.", flag(func(r Report) bool { return r.Service.Active }))
	gauge("listener", "1 when something listens on the ORPort, per address family.",
		fam(func(r Report) bool { return r.Listener.IPv4 }, func(r Report) bool { return r.Listener.IPv6 }))
	gauge("reachable", "1 when Tor's self-test confirmed the ORPort is reachable from outside in the last 24 hours.",
		fam(func(r Report) bool { return r.Reachability.IPv4 }, func(r Report) bool { return r.Reachability.IPv6 }))
	gauge("reachability_failed", "1 when Tor reported that its ORPort self-test failed.", flag(func(r Report) bool { return r.Reachability.Failed }))
	gauge("family_ids", "Number of FamilyId lines in torrc.", one(func(r Report) int64 { return int64(len(r.Family.IDs)) }))
	gauge("family_keys_missing", "Number of configured FamilyIds without an installed secret family key.",
		one(func(r Report) int64 { return int64(len(r.Family.MissingKeys)) }))
	gauge("legacy_myfamily_fingerprints", "Number of fingerprints in legacy MyFamily lines.", one(func(r Report) int64 { return int64(r.Family.LegacyCount) }))
	gauge("warnings", "Number of problems that need attention (status exits 1 when this is not 0).", one(func(r Report) int64 { return int64(len(r.Warnings)) }))

	gauge("directory_published", "1 when Tor Metrics lists the relay.", func(r Report) []sample {
		if r.Relay.Fingerprint == "" || r.DirectoryError != "" {
			return nil
		}
		return []sample{{value: b2i(r.Directory != nil)}}
	})
	gauge("directory_running", "1 when Tor Metrics reports the relay as running.", listed(func(r Report) int64 { return b2i(r.Directory.Running) }))
	gauge("consensus_weight", "Consensus weight reported by Tor Metrics.", listed(func(r Report) int64 { return r.Directory.ConsensusWeight }))
	gauge("advertised_bandwidth_bytes", "Advertised bandwidth in bytes per second, reported by Tor Metrics.",
		listed(func(r Report) int64 { return r.Directory.AdvertisedBandwidth }))

	_, err := w.Write(buf.Bytes())
	return err
}

type sample struct {
	labels [][2]string
	value  int64
}

// instanceLabel is the report's instance; "default" for a hand-built Report.
func instanceLabel(r Report) string {
	if r.Instance == "" {
		return relay.DefaultInstanceName
	}
	return r.Instance
}

// renderLabels formats a label set as {a="1",b="2"}.
func renderLabels(labels [][2]string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l[0] + `="` + escapeLabel(l[1]) + `"`)
	}
	b.WriteByte('}')
	return b.String()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// escapeLabel escapes a label value: backslash, double quote, and line feed.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes HELP text: backslash and line feed.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}
