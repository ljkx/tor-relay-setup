package status

import (
	"io"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/metrics"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// DefaultTorInstance is the tor_instance label of Debian's default tor
// unit (tor@default).
const DefaultTorInstance = "default"

// LoadMetrics is the input of WriteLoadPrometheus. Every part is optional;
// nil parts are left out of the output.
type LoadMetrics struct {
	// Instance names the tor instance ("default" or the Debian instance
	// name); every series carries it as the tor_instance label. Empty means
	// DefaultTorInstance.
	Instance string
	// MetricsPort is true when torrc configures a MetricsPort; it enables
	// tor_relay_setup_metricsport_up.
	MetricsPort bool
	// Sample is the current MetricsPort scrape, nil when it failed.
	Sample *metrics.Sample
	// Overload compares Sample with the previous run's sample (see
	// metrics.AssessOverload); left out when it had no baseline.
	Overload *metrics.Overload
	// Accounting is the AccountingMax assessment (metrics.AssessAccounting);
	// left out unless accounting is enabled.
	Accounting *metrics.Accounting
	// Directory is the Tor Metrics entry, for Relay Search's overload mark.
	Directory *onionoo.Relay
	// Now is the time the Relay Search overload mark is judged at; zero
	// means time.Now().
	Now time.Time
}

// WriteLoadPrometheus writes the overload and accounting gauges in the
// same text format and prefix as Report.WritePrometheus, so the two can be
// concatenated into one node_exporter textfile:
//
//	r.WritePrometheus(w)
//	status.WriteLoadPrometheus(w, status.LoadMetrics{...})
//
// The tor_relay_setup_overload_*_total series mirror tor's MetricsPort
// counters, so Prometheus can take increase() without scraping the
// MetricsPort itself. Several instances can be written one after another
// only if the caller merges their families (one # HELP/# TYPE per name).
func WriteLoadPrometheus(w io.Writer, m LoadMetrics) error {
	inst := m.Instance
	if inst == "" {
		inst = DefaultTorInstance
	}
	x := labelled{e: &metrics.Exposition{}, inst: metrics.Label{Name: "tor_instance", Value: inst}}
	if m.MetricsPort {
		x.gauge("metricsport_up", "1 when tor's MetricsPort answered this run.", b2u(m.Sample != nil))
	}
	if s := m.Sample; s != nil && s.Load.Seen {
		writeLoadCounters(x, s.Load)
	}
	if o := m.Overload; o != nil && o.Supported && o.Baseline {
		x.family("overload_signal", "gauge", "1 when the overload signal fired since the previous run; line is the descriptor line it feeds.")
		for _, sig := range metrics.Signals {
			x.sample("overload_signal", b2u(o.Fired(sig)), metrics.Label{Name: "signal", Value: string(sig)}, metrics.Label{Name: "line", Value: sig.Line()})
		}
		x.gauge("overload_general", "1 when tor would publish overload-general for the window since the previous run (Relay Search marks the relay overloaded).", b2u(o.General()))
		x.family("overload_window_seconds", "gauge", "Length of the window the overload signals cover.")
		x.e.Float(metricPrefix+"overload_window_seconds", o.Window().Seconds(), x.inst)
	}
	if d := m.Directory; d != nil {
		now := m.Now
		if now.IsZero() {
			now = time.Now()
		}
		x.gauge("directory_overloaded", "1 when Tor Metrics lists an overload-general event in the last 72 hours (Relay Search shows the relay as overloaded).", b2u(d.Overloaded(now)))
		if !d.OverloadGeneral.IsZero() {
			x.gauge("directory_overload_general_timestamp_seconds", "Hour of the last overload-general event reported by Tor Metrics.", unixSeconds(d.OverloadGeneral))
		}
	}
	if a := m.Accounting; a != nil && a.Enabled {
		writeAccounting(x, *a)
	}
	_, err := x.e.WriteTo(w)
	return err
}

// labelled writes tor_relay_setup_ series that all carry the tor_instance
// label first.
type labelled struct {
	e    *metrics.Exposition
	inst metrics.Label
}

func (x labelled) family(name, typ, help string) { x.e.Family(metricPrefix+name, typ, help) }

func (x labelled) sample(name string, v uint64, labels ...metrics.Label) {
	x.e.Uint(metricPrefix+name, v, append([]metrics.Label{x.inst}, labels...)...)
}

func (x labelled) gauge(name, help string, v uint64, labels ...metrics.Label) {
	x.family(name, "gauge", help)
	x.sample(name, v, labels...)
}

func writeLoadCounters(x labelled, l metrics.Load) {
	onionskins := func(name, help string, o metrics.Onionskins) {
		x.family(name, "counter", help)
		for _, v := range []struct {
			typ string
			n   uint64
		}{{"tap", o.TAP}, {"fast", o.Fast}, {"ntor", o.Ntor}, {"ntor_v3", o.NtorV3}} {
			x.sample(name, v.n, metrics.Label{Name: "type", Value: v.typ})
		}
	}
	onionskins("overload_onionskins_processed_total", "Onionskins tor processed since it started (tor_relay_load_onionskins_total{action=\"processed\"}).", l.OnionskinsProcessed)
	onionskins("overload_onionskins_dropped_total", "Onionskins tor dropped since it started because its CPU workers were busy (tor_relay_load_onionskins_total{action=\"dropped\"}).", l.OnionskinsDropped)

	x.family("overload_oom_bytes_total", "counter", "Bytes the out-of-memory handler freed since tor started, by subsystem (tor_relay_load_oom_bytes_total).")
	for _, v := range []struct {
		subsys string
		n      uint64
	}{{"cell", l.OOMBytes.Cell}, {"dns", l.OOMBytes.DNS}, {"geoip", l.OOMBytes.GeoIP}, {"hsdir", l.OOMBytes.HSDir}} {
		x.sample("overload_oom_bytes_total", v.n, metrics.Label{Name: "subsys", Value: v.subsys})
	}

	x.family("overload_tcp_exhaustion_total", "counter", "Connections that failed since tor started because no local TCP port was free (tor_relay_load_tcp_exhaustion_total).")
	x.sample("overload_tcp_exhaustion_total", l.TCPExhaustion)

	x.family("overload_rate_limit_reached_total", "counter", "Times the global BandwidthRate bucket ran empty since tor started (tor_relay_load_global_rate_limit_reached_total).")
	x.sample("overload_rate_limit_reached_total", l.RateLimitRead, metrics.Label{Name: "side", Value: "read"})
	x.sample("overload_rate_limit_reached_total", l.RateLimitWrite, metrics.Label{Name: "side", Value: "write"})

	x.gauge("overload_sockets_open", "Sockets tor has open (tor_relay_load_socket_total{state=\"opened\"}).", l.SocketsOpen)
	x.gauge("overload_sockets_limit", "Most sockets tor allows itself, derived from its file-descriptor limit (tor_relay_load_socket_total).", l.SocketsLimit)
}

func writeAccounting(x labelled, a metrics.Accounting) {
	rule := metrics.Label{Name: "rule", Value: a.Rule}
	x.gauge("accounting_max_bytes", "AccountingMax from torrc, in bytes.", a.Max, rule)
	x.gauge("accounting_used_bytes", "Bytes counted against AccountingMax in the current period (per AccountingRule), from tor's state file.", a.Used, rule)
	x.gauge("accounting_projected_bytes", "Bytes expected at the end of the period at the average pace so far.", a.Projected, rule)
	x.gauge("accounting_period_start_timestamp_seconds", "Start of the current accounting period.", unixSeconds(a.PeriodStart))
	x.gauge("accounting_period_end_timestamp_seconds", "End of the current accounting period.", unixSeconds(a.PeriodEnd))
	var exhausts uint64
	if a.RunsOut() {
		exhausts = unixSeconds(a.ExhaustsAt)
	}
	x.gauge("accounting_exhaustion_timestamp_seconds", "When AccountingMax is reached at the current pace, if before the period ends; 0 otherwise.", exhausts)
	x.gauge("accounting_hibernating", "1 when AccountingMax is used up and tor hibernates until the period ends.", b2u(a.Exhausted()))
}

// unixSeconds is t as a Unix timestamp, 0 before 1970.
func unixSeconds(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
