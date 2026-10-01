package status

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// metricPrefix starts every exported metric name.
const metricPrefix = "tor_relay_setup_"

// WritePrometheus writes the report in the Prometheus text exposition
// format for node_exporter's textfile collector: one gauge family per
// metric, with # HELP and # TYPE lines, in a fixed order.
//
// The Tor Metrics gauges (directory_*, consensus_weight,
// advertised_bandwidth_bytes) are left out when they are unknown: no
// fingerprint yet, or the lookup failed. directory_published is 0 when Tor
// Metrics answered but does not list the relay.
func (r Report) WritePrometheus(w io.Writer) error {
	var buf bytes.Buffer
	gauge := func(name, help string, samples ...sample) {
		fmt.Fprintf(&buf, "# HELP %s%s %s\n", metricPrefix, name, escapeHelp(help))
		fmt.Fprintf(&buf, "# TYPE %s%s gauge\n", metricPrefix, name)
		for _, s := range samples {
			buf.WriteString(metricPrefix + name)
			if len(s.labels) > 0 {
				buf.WriteByte('{')
				for i, l := range s.labels {
					if i > 0 {
						buf.WriteByte(',')
					}
					buf.WriteString(l[0] + `="` + escapeLabel(l[1]) + `"`)
				}
				buf.WriteByte('}')
			}
			buf.WriteString(" " + strconv.FormatInt(s.value, 10) + "\n")
		}
	}
	one := func(v int64) sample { return sample{value: v} }
	fam := func(family string, v bool) sample {
		return sample{labels: [][2]string{{"family", family}}, value: b2i(v)}
	}

	gauge("up", "1 when tor-relay-setup collected this report.", one(1))
	gauge("info", "Relay identity and tor version; the value is always 1.", sample{
		labels: [][2]string{{"version", r.Tor.Version}, {"nickname", r.Relay.Nickname}, {"fingerprint", r.Relay.Fingerprint}},
		value:  1,
	})
	gauge("relay_configured", "1 when /etc/tor/torrc configures an ORPort.", one(b2i(r.Relay.Configured)))
	gauge("tor_installed", "1 when the tor binary runs.", one(b2i(r.Tor.Installed)))
	gauge("tor_supported", "1 when the installed tor version is accepted by the network.", one(b2i(r.Tor.Supported)))
	gauge("service_active", "1 when the tor systemd unit is active.", one(b2i(r.Service.Active)))
	gauge("listener", "1 when something listens on the ORPort, per address family.", fam("ipv4", r.Listener.IPv4), fam("ipv6", r.Listener.IPv6))
	gauge("reachable", "1 when Tor's self-test confirmed the ORPort is reachable from outside in the last 24 hours.", fam("ipv4", r.Reachability.IPv4), fam("ipv6", r.Reachability.IPv6))
	gauge("reachability_failed", "1 when Tor reported that its ORPort self-test failed.", one(b2i(r.Reachability.Failed)))
	gauge("family_ids", "Number of FamilyId lines in torrc.", one(int64(len(r.Family.IDs))))
	gauge("family_keys_missing", "Number of configured FamilyIds without an installed secret family key.", one(int64(len(r.Family.MissingKeys))))
	gauge("legacy_myfamily_fingerprints", "Number of fingerprints in legacy MyFamily lines.", one(int64(r.Family.LegacyCount)))
	gauge("warnings", "Number of problems that need attention (status exits 1 when this is not 0).", one(int64(len(r.Warnings))))

	if r.Relay.Fingerprint != "" && r.DirectoryError == "" {
		gauge("directory_published", "1 when Tor Metrics lists the relay.", one(b2i(r.Directory != nil)))
	}
	if d := r.Directory; d != nil && r.DirectoryError == "" {
		gauge("directory_running", "1 when Tor Metrics reports the relay as running.", one(b2i(d.Running)))
		gauge("consensus_weight", "Consensus weight reported by Tor Metrics.", one(d.ConsensusWeight))
		gauge("advertised_bandwidth_bytes", "Advertised bandwidth in bytes per second, reported by Tor Metrics.", one(d.AdvertisedBandwidth))
	}

	_, err := w.Write(buf.Bytes())
	return err
}

type sample struct {
	labels [][2]string
	value  int64
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
