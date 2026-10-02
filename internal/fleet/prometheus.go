package fleet

import (
	"bytes"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// MetricPrefix starts every fleet metric name. The names, labels and
// meanings are a contract with the Grafana dashboards:
// docs/monitoring/fleet-metrics.md.
const MetricPrefix = "tor_relay_fleet_"

// PrometheusOptions configures WritePrometheus.
type PrometheusOptions struct {
	// Privacy leaves out each relay's traffic counters and OR connections;
	// the fleet totals stay.
	Privacy bool
	// Now judges Relay Search's overload mark; zero means time.Now().
	Now time.Time
}

// Host states of the host_up series.
const (
	upOK          = "ok"
	upUnreachable = "unreachable"
	upNoProbe     = "no_probe"
)

// upState maps a host state onto host_up's three states; "" while pending.
func upState(s HostState) string {
	switch s {
	case HostOK:
		return upOK
	case HostUnreachable, HostFailed:
		return upUnreachable
	case HostTooOld, HostMissing:
		return upNoProbe
	}
	return ""
}

// relayFlags are the flags relay_flag reports, in output order.
var relayFlags = []string{"Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "MiddleOnly", "Running", "Stable", "StaleDesc", "V2Dir", "Valid"}

// exposition collects metric families, then writes each with one # HELP
// and # TYPE line followed by its samples. Families without samples are
// left out.
type exposition struct {
	order    []string
	families map[string]*family
}

type family struct {
	name, typ, help string
	samples         []promSample
}

type promSample struct {
	labels []metrics.Label
	value  float64
}

func (e *exposition) add(name, typ, help string, v float64, labels ...metrics.Label) {
	f := e.families[name]
	if f == nil {
		f = &family{name: MetricPrefix + name, typ: typ, help: help}
		e.families[name] = f
		e.order = append(e.order, name)
	}
	f.samples = append(f.samples, promSample{labels: labels, value: v})
}

func (e *exposition) gauge(name, help string, v float64, labels ...metrics.Label) {
	e.add(name, "gauge", help, v, labels...)
}

func (e *exposition) counter(name, help string, v float64, labels ...metrics.Label) {
	e.add(name, "counter", help, v, labels...)
}

func (e *exposition) writeTo(w io.Writer) error {
	var b bytes.Buffer
	for _, name := range e.order {
		f := e.families[name]
		b.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		b.WriteString("# TYPE " + f.name + " " + f.typ + "\n")
		for _, s := range f.samples {
			b.WriteString(f.name)
			if len(s.labels) > 0 {
				b.WriteByte('{')
				for i, l := range s.labels {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(l.Name + `="` + escapeLabel(l.Value) + `"`)
				}
				b.WriteByte('}')
			}
			b.WriteString(" " + formatValue(s.value) + "\n")
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}

// formatValue prints integers without an exponent and anything else in
// Go's shortest form.
func formatValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unix(t time.Time) float64 { return float64(t.Unix()) }

func label(name, value string) metrics.Label { return metrics.Label{Name: name, Value: value} }

// with appends extra labels to a copy of base.
func with(base []metrics.Label, extra ...metrics.Label) []metrics.Label {
	return append(slices.Clone(base), extra...)
}

// WritePrometheus writes the fleet in the Prometheus text format, exactly
// the series of docs/monitoring/fleet-metrics.md. Per-relay series carry
// host, tor_instance (not "instance", which Prometheus sets to the scrape
// target), nickname, fingerprint (hashed for bridges) and role. Values
// that are not known (no fresh probe, no Tor Metrics entry) are left out
// rather than written as 0.
func (m *Model) WritePrometheus(w io.Writer, opt PrometheusOptions) error {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	e := &exposition{families: map[string]*family{}}
	m.writeTotals(e)
	m.writeHosts(e)
	sets, majority, _ := m.familySets()
	for _, r := range m.relays {
		m.writeRelay(e, r, opt.Privacy, now, sets, majority)
	}
	return e.writeTo(w)
}

func (m *Model) writeTotals(e *exposition) {
	t := m.Totals()
	e.gauge("relays", "Relays in the inventory, plus relays found on its hosts but not listed.", float64(t.Relays))
	e.gauge("relays_running", "Relays whose tor service is active (as of their host's last successful probe).", float64(t.Running))
	e.gauge("hosts", "Servers in the inventory.", float64(t.Hosts))
	e.gauge("hosts_up", "Servers whose last probe answered.", float64(t.HostsUp))
	e.gauge("hosts_unreachable", "Servers that could not be probed over ssh, or whose probe failed.", float64(t.Unreachable))
	e.gauge("hosts_without_probe", "Servers whose tor-relay-setup is missing or too old for fleet-probe.", float64(t.TooOld))
	e.gauge("attention", "Number of \"Needs attention\" findings.", float64(len(m.Attention())))
	if !m.DirOK.IsZero() {
		e.gauge("consensus_weight", "Consensus weight summed over the relays Tor Metrics lists.", float64(t.ConsensusWeight))
		e.gauge("consensus_weight_fraction", "The fleet's share of the network's consensus weight (0-1).", t.WeightFraction)
		e.gauge("guard_probability", "Guard selection probability summed over the fleet.", t.Guard)
		e.gauge("middle_probability", "Middle selection probability summed over the fleet.", t.Middle)
		e.gauge("exit_probability", "Exit selection probability summed over the fleet.", t.Exit)
		e.gauge("advertised_bandwidth_bytes", "Advertised bandwidth summed over the fleet, in bytes per second.", float64(t.Advertised))
		e.gauge("observed_bandwidth_bytes", "Observed bandwidth summed over the fleet, in bytes per second.", float64(t.Observed))
	}
	const trafficHelp = "Traffic of the relays with a MetricsPort, in bytes; it only grows (relay restarts and unreachable hosts do not reset it)."
	e.counter("traffic_bytes_total", trafficHelp, t.TrafficRead, label("direction", "read"))
	e.counter("traffic_bytes_total", trafficHelp, t.TrafficWritten, label("direction", "written"))
	if t.Sampled > 0 {
		e.gauge("or_connections", "Open OR connections summed over the relays whose MetricsPort answered.", float64(t.Connections))
	}
	if !m.RoundEnd.IsZero() {
		e.gauge("probe_duration_seconds", "Duration of the last full probe round.", m.RoundDuration.Seconds())
		e.gauge("last_probe_timestamp_seconds", "End of the last full probe round.", unix(m.RoundEnd))
	}
	if !m.DirOK.IsZero() {
		e.gauge("directory_last_update_timestamp_seconds", "Last successful Tor Metrics (Onionoo) refresh.", unix(m.DirOK))
	}
}

func (m *Model) writeHosts(e *exposition) {
	for _, h := range m.hosts {
		state := upState(h.State)
		if state == "" {
			continue
		}
		host := label("host", HostOf(h.Address))
		for _, s := range []string{upOK, upUnreachable, upNoProbe} {
			e.gauge("host_up", "1 for the host's current probe state (ok, unreachable, no_probe), 0 for the others.", b2f(s == state), host, label("state", s))
		}
		if h.Duration > 0 {
			e.gauge("host_probe_duration_seconds", "Duration of the host's last probe.", h.Duration.Seconds(), host)
		}
		if !h.LastOK.IsZero() {
			e.gauge("host_last_success_timestamp_seconds", "Time of the host's last successful probe.", unix(h.LastOK), host)
		}
		if h.Version != "" {
			e.gauge("host_tool_info", "The tor-relay-setup version on the host; the value is always 1.", 1, host, label("version", h.Version))
		}
	}
}

func (m *Model) writeRelay(e *exposition, r *Relay, privacy bool, now time.Time, sets map[*Relay]string, majority string) {
	base := []metrics.Label{
		label("host", HostOf(r.Address)), label("tor_instance", r.Instance), label("nickname", r.Nickname()),
		label("fingerprint", r.PublicFingerprint()), label("role", m.Role(r)),
	}
	d, bd := m.DirectoryOf(r), m.BridgeDirectoryOf(r)
	var country, as, asName, transport string
	if d != nil {
		country, as, asName = d.Country, d.AS, d.ASName
	}
	if r.Probe != nil && r.Probe.Report.Bridge != nil {
		transport = r.Probe.Report.Bridge.Transport
	}
	e.gauge("relay_info", "Relay identity, tor version and location; the value is always 1.", 1,
		with(base, label("version", r.TorVersion()), label("country", country), label("as", as), label("as_name", asName), label("transport", transport))...)

	if p := m.Fresh(r); p != nil {
		m.writeProbe(e, base, r, p, privacy, sets, majority)
	}

	if published, known := m.Published(r); known {
		e.gauge("relay_published", "1 when Tor Metrics lists the relay.", b2f(published), base...)
	}
	switch {
	case d != nil:
		writeDirectory(e, base, d.Running, d.Flags, d.FirstSeen, d.LastRestarted, d.OverloadGeneral, d.Overloaded(now))
		e.gauge("relay_consensus_weight", "Consensus weight, from Tor Metrics.", float64(d.ConsensusWeight), base...)
		e.gauge("relay_consensus_weight_fraction", "Share of the network's consensus weight (0-1), from Tor Metrics.", d.ConsensusWeightFraction, base...)
		e.gauge("relay_guard_probability", "Guard selection probability, from Tor Metrics.", d.GuardProbability, base...)
		e.gauge("relay_middle_probability", "Middle selection probability, from Tor Metrics.", d.MiddleProbability, base...)
		e.gauge("relay_exit_probability", "Exit selection probability, from Tor Metrics.", d.ExitProbability, base...)
		e.gauge("relay_advertised_bandwidth_bytes", "Advertised bandwidth in bytes per second, from Tor Metrics.", float64(d.AdvertisedBandwidth), base...)
		e.gauge("relay_observed_bandwidth_bytes", "Observed bandwidth in bytes per second, from Tor Metrics.", float64(d.ObservedBandwidth), base...)
	case bd != nil:
		writeDirectory(e, base, bd.Running, bd.Flags, bd.FirstSeen, bd.LastRestarted, bd.OverloadGeneral(), bd.Overloaded(now))
		e.gauge("relay_advertised_bandwidth_bytes", "Advertised bandwidth in bytes per second, from Tor Metrics.", float64(bd.AdvertisedBandwidth), base...)
	}
}

// writeDirectory writes the Tor Metrics series relays and bridges share.
func writeDirectory(e *exposition, base []metrics.Label, running bool, flags []string, firstSeen, lastRestarted string, overload time.Time, overloaded bool) {
	e.gauge("relay_running", "1 when Tor Metrics reports the relay as running.", b2f(running), base...)
	for _, f := range relayFlags {
		if slices.Contains(flags, f) {
			e.gauge("relay_flag", "1 for each flag the relay holds in the consensus, from Tor Metrics.", 1, with(base, label("flag", f))...)
		}
	}
	if t := onionoo.ParseTime(firstSeen); !t.IsZero() {
		e.gauge("relay_first_seen_timestamp_seconds", "When the relay was first seen in a consensus, from Tor Metrics.", unix(t), base...)
	}
	if t := onionoo.ParseTime(lastRestarted); !t.IsZero() {
		e.gauge("relay_last_restarted_timestamp_seconds", "When the relay was last (re)started, from Tor Metrics.", unix(t), base...)
	}
	e.gauge("relay_overloaded", "1 when Relay Search marks the relay as overloaded (overload-general in the last 72 hours).", b2f(overloaded), base...)
	if !overload.IsZero() {
		e.gauge("relay_overload_general_timestamp_seconds", "Hour of the last overload-general event, from Tor Metrics.", unix(overload), base...)
	}
}

// writeProbe writes the series that come from a fresh probe.
func (m *Model) writeProbe(e *exposition, base []metrics.Label, r *Relay, p *RelayProbe, privacy bool, sets map[*Relay]string, majority string) {
	rep := p.Report
	e.gauge("relay_service_active", "1 when the relay's tor unit is active.", b2f(rep.Service.Active), base...)
	if rep.Relay.Configured && rep.Relay.ORPort > 0 {
		const listen, reach = "1 when something listens on the relay's ORPort.", "1 when tor's self-test confirmed the ORPort is reachable (last 24 hours)."
		e.gauge("relay_listener", listen, b2f(rep.Listener.IPv4), with(base, label("family", "ipv4"))...)
		e.gauge("relay_reachable", reach, b2f(rep.Reachability.IPv4), with(base, label("family", "ipv4"))...)
		if rep.Relay.IPv6 {
			e.gauge("relay_listener", listen, b2f(rep.Listener.IPv6), with(base, label("family", "ipv6"))...)
			e.gauge("relay_reachable", reach, b2f(rep.Reachability.IPv6), with(base, label("family", "ipv6"))...)
		}
	}
	e.gauge("relay_warnings", "Number of the relay's own status warnings.", float64(len(rep.Warnings)), base...)

	if s := p.MetricsSample(); s != nil {
		if !privacy {
			const help = "Relay traffic in bytes since tor started, from the MetricsPort."
			e.counter("relay_traffic_bytes_total", help, float64(s.Read), with(base, label("direction", "read"))...)
			e.counter("relay_traffic_bytes_total", help, float64(s.Written), with(base, label("direction", "written"))...)
			e.gauge("relay_or_connections", "Open OR connections, from the MetricsPort.", float64(s.Connections), base...)
		}
		if s.Load.Seen {
			writeLoad(e, base, s.Load)
		}
	}
	if a := p.Accounting; a != nil && a.Enabled {
		e.gauge("relay_accounting_max_bytes", "AccountingMax from torrc, in bytes.", float64(a.Max), base...)
		e.gauge("relay_accounting_used_bytes", "Bytes counted against AccountingMax in the current period (per AccountingRule).", float64(a.Used), base...)
		e.gauge("relay_accounting_projected_bytes", "Bytes expected at the end of the accounting period at the pace so far.", float64(a.Projected), base...)
		e.gauge("relay_accounting_period_end_timestamp_seconds", "End of the current accounting period.", unix(a.PeriodEnd), base...)
	}
	if k := rep.Keys; k != nil && !k.CertExpires.IsZero() {
		e.gauge("relay_signing_cert_expiry_timestamp_seconds", "Expiry of the relay's ed25519 signing certificate.", unix(k.CertExpires), base...)
	}
	if rep.Relay.Configured && !r.IsBridge() {
		e.gauge("relay_family_ids", "Number of FamilyIds the relay is configured with.", float64(len(rep.Family.IDs)), base...)
		e.gauge("relay_family_keys_missing", "Number of FamilyIds without an installed family key.", float64(len(rep.Family.MissingKeys)), base...)
		if key, ok := sets[r]; ok {
			e.gauge("relay_family_consistent", "1 when the relay's FamilyId set matches the fleet majority.", b2f(key == majority), base...)
		}
	}
	if b := rep.Bridge; b != nil {
		e.gauge("relay_bridge_transport_listening", "1 when the bridge's pluggable transport listens.", b2f(b.Listening), with(base, label("transport", b.Transport))...)
	}
}

// writeLoad writes tor's load counters (tor_relay_load_* on the MetricsPort).
func writeLoad(e *exposition, base []metrics.Label, l metrics.Load) {
	const onionHelp = "Onionskins (circuit handshakes) processed or dropped since tor started, from the MetricsPort."
	for _, a := range []struct {
		action string
		o      metrics.Onionskins
	}{{"processed", l.OnionskinsProcessed}, {"dropped", l.OnionskinsDropped}} {
		for _, t := range []struct {
			typ string
			n   uint64
		}{{"tap", a.o.TAP}, {"fast", a.o.Fast}, {"ntor", a.o.Ntor}, {"ntor_v3", a.o.NtorV3}} {
			e.counter("relay_onionskins_total", onionHelp, float64(t.n), with(base, label("type", t.typ), label("action", a.action))...)
		}
	}
	for _, s := range []struct {
		subsys string
		n      uint64
	}{{"cell", l.OOMBytes.Cell}, {"dns", l.OOMBytes.DNS}, {"geoip", l.OOMBytes.GeoIP}, {"hsdir", l.OOMBytes.HSDir}} {
		e.counter("relay_oom_bytes_total", "Bytes the out-of-memory handler freed since tor started, by subsystem.", float64(s.n), with(base, label("subsys", s.subsys))...)
	}
	e.counter("relay_tcp_exhaustion_total", "Connections that failed since tor started because no local TCP port was free.", float64(l.TCPExhaustion), base...)
	const rlHelp = "Times the global BandwidthRate/BandwidthBurst bucket ran empty since tor started."
	e.counter("relay_rate_limit_reached_total", rlHelp, float64(l.RateLimitRead), with(base, label("side", "read"))...)
	e.counter("relay_rate_limit_reached_total", rlHelp, float64(l.RateLimitWrite), with(base, label("side", "write"))...)
	e.gauge("relay_sockets_open", "Sockets tor has open.", float64(l.SocketsOpen), base...)
	if l.SocketsLimit > 0 {
		e.gauge("relay_sockets_limit", "Most sockets tor allows itself.", float64(l.SocketsLimit), base...)
	}
}
