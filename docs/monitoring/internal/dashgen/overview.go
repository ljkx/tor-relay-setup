package dashgen

import "strings"

// Metric name prefix of the fleet contract (docs/monitoring/fleet-metrics.md).
const pfx = "tor_relay_fleet_"

// relayM is a per-relay series filtered by the overview's host and role
// variables, with extra label matchers.
func relayM(name string, extra ...string) string {
	sel := append([]string{`host=~"$host"`, `role=~"$role"`}, extra...)
	return pfx + "relay_" + name + "{" + strings.Join(sel, ", ") + "}"
}

// hostM is a per-host series filtered by the host variable.
func hostM(name string, extra ...string) string {
	sel := append([]string{`host=~"$host"`}, extra...)
	return pfx + "host_" + name + "{" + strings.Join(sel, ", ") + "}"
}

const privacyNote = " Per-relay traffic and connection series are left out when fleet serve runs with privacy = true; the fleet totals stay."

var (
	roleMappings = []any{valueMap(
		[3]string{"guard", "Guard", Purple},
		[3]string{"exit", "Exit", Orange},
		[3]string{"middle", "Middle", Blue},
		[3]string{"bridge", "Bridge", Green},
	)}
	checkMappings = []any{valueMap([3]string{"1", "✓", Green}, [3]string{"0", "✗", Red}), nullMap("–", Grey)}
	runMappings   = []any{valueMap([3]string{"1", "running", Green}, [3]string{"0", "stopped", Red})}
	// Durations: red below a day, orange below a week.
	expirySteps   = []Step{{Color: Red}, {Color: Orange, Value: 86400}, {Color: Green, Value: 7 * 86400}}
	attentionStep = []Step{{Color: Green}, {Color: Orange, Value: 1}, {Color: Red, Value: 5}}
	warnSteps     = []Step{{Color: Green}, {Color: Orange, Value: 1}, {Color: Red, Value: 3}}
	pct3          = Field{Unit: "percentunit", Decimals: ip(3), ColorMode: "fixed", FixedColor: Purple}
	directionOver = []any{
		override(byName("read"), prop("displayName", "in (read)"), fixedColor(PurpleLight), prop("custom.transform", "negative-Y")),
		override(byName("written"), prop("displayName", "out (written)"), fixedColor(Purple)),
	}
	directionColors = []any{
		override(byName("read"), prop("displayName", "in (read)"), fixedColor(PurpleLight)),
		override(byName("written"), prop("displayName", "out (written)"), fixedColor(Purple)),
	}
)

// expiryField colours a time-left value by range mappings (red below a
// day, orange below a week, green after), so that a missing value shows
// in neutral grey rather than in the colour of the lowest threshold.
func expiryField(noValue string) Field {
	return Field{
		Unit: "dtdurations", NoValue: noValue, Thresholds: []Step{{Color: Grey}},
		Mappings: []any{
			rangeMap(-1e12, 86400, Red, 0),
			rangeMap(86400, 7*86400, Orange, 1),
			rangeMap(7*86400, 1e12, Green, 2),
		},
	}
}

// rangeMap colours values in [from, to) without changing their text.
func rangeMap(from, to float64, color string, index int) M {
	return M{"type": "range", "options": M{"from": from, "to": to, "result": M{"color": color, "index": index}}}
}

// Overview is the "Tor fleet — overview" dashboard.
func Overview() M {
	var l Layout

	// Header: the whole fleet at a glance (fleet totals, not filtered).
	l.Add(
		Stat("Relays running", "Relays whose tor service is active, and all relays in the inventory (plus relays found on the hosts but not listed). Whole fleet.", 4,
			Field{ColorMode: "fixed", FixedColor: Purple, Decimals: ip(0)},
			Q{Expr: pfx + "relays_running", Legend: "running"}, Q{Expr: pfx + "relays", Legend: "total"}),
		Stat("Hosts up", "Servers whose last SSH probe succeeded, and all servers in the inventory. Whole fleet.", 4,
			Field{ColorMode: "fixed", FixedColor: Purple, Decimals: ip(0)},
			Q{Expr: pfx + "hosts_up", Legend: "up"}, Q{Expr: pfx + "hosts", Legend: "total"}),
		Stat("Needs attention", "Findings in fleet serve's \"Needs attention\" list: stopped relays, unreachable hosts, lost flags, overload, accounting, keys. Open the fleet web UI for the details.", 4,
			Field{Decimals: ip(0), Thresholds: attentionStep}, Q{Expr: pfx + "attention", Legend: "findings"}),
		Stat("Throughput now", "Traffic of all relays with a MetricsPort over the last 5 minutes: in = read, out = written. Relays forward what they read, so both are similar.", 4,
			Field{Unit: "Bps", ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: `sum(rate(` + pfx + `traffic_bytes_total{direction="read"}[5m]))`, Legend: "in"},
			Q{Expr: `sum(rate(` + pfx + `traffic_bytes_total{direction="written"}[5m]))`, Legend: "out"}),
		Stat("Relayed, last 30 days", "Bytes all relays wrote in the last 30 days (Prometheus keeps 400 days). Starts counting when monitoring starts.", 4,
			Field{Unit: "decbytes", ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: `sum(increase(` + pfx + `traffic_bytes_total{direction="written"}[30d]))`, Legend: "written", Instant: true}),
		Stat("Oldest probe", "Time since the least recent successful SSH probe of any host. fleet serve probes every host each probe interval (30 s by default); orange after 5 minutes, red after 15.", 4,
			Field{Unit: "dtdurations", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 300}, {Color: Red, Value: 900}}},
			Q{Expr: `time() - min(` + pfx + `host_last_success_timestamp_seconds)`, Legend: "age"}),

		Stat("Consensus weight share", "The fleet's share of the total consensus weight of the Tor network, summed over relays Tor Metrics lists. Roughly the share of the network's traffic the fleet is offered.", 4,
			pct3, Q{Expr: pfx + "consensus_weight_fraction", Legend: "share"}),
		Stat("Guard probability", "Probability that a client picks one of the fleet's relays as its entry guard (summed, from Tor Metrics).", 4,
			pct3, Q{Expr: pfx + "guard_probability", Legend: "guard"}),
		Stat("Middle probability", "Probability that a circuit uses one of the fleet's relays in the middle position (summed, from Tor Metrics).", 4,
			pct3, Q{Expr: pfx + "middle_probability", Legend: "middle"}),
		Stat("Exit probability", "Probability that a circuit exits through one of the fleet's relays (summed, from Tor Metrics). 0 for a fleet without exits.", 4,
			pct3, Q{Expr: pfx + "exit_probability", Legend: "exit"}),
		Stat("Advertised bandwidth", "Sum of the bandwidth the relays advertise in their descriptors (the minimum of their rate limits and observed capacity), from Tor Metrics.", 4,
			Field{Unit: "Bps", ColorMode: "fixed", FixedColor: Purple}, Q{Expr: pfx + "advertised_bandwidth_bytes", Legend: "advertised"}),
		Stat("OR connections", "Open connections to other relays and clients, summed over relays with a MetricsPort.", 4,
			Field{Decimals: ip(0), ColorMode: "fixed", FixedColor: Purple}, Q{Expr: pfx + "or_connections", Legend: "connections"}),
	)

	l.Row("Traffic", false)
	l.Add(
		withLegendTable(Series("Fleet throughput", "Bytes per second read (below the axis) and written (above) by all relays with a MetricsPort. Always present, also in privacy mode.", 12,
			Field{Unit: "Bps"}, false,
			Q{Expr: `sum by (direction) (rate(` + pfx + `traffic_bytes_total[$__rate_interval]))`, Legend: "{{direction}}"}), "mean", "max", "lastNotNull"),
		withLegendTable(Series("Throughput per relay", "Bytes per second written by each relay, stacked. Filtered by host and role."+privacyNote, 12,
			Field{Unit: "Bps", NoValue: "No data yet, or hidden by privacy mode"}, true,
			Q{Expr: `sum by (nickname) (rate(` + relayM("traffic_bytes_total", `direction="written"`) + `[$__rate_interval]))`, Legend: "{{nickname}}"}), "mean", "max", "lastNotNull"),
		Bars("Traffic per day", "Bytes read and written by the whole fleet per day.", 12,
			Field{Unit: "decbytes", NoValue: "Daily totals appear after the first full day (UTC)"}, "1d", false,
			Q{Expr: `sum by (direction) (increase(` + pfx + `traffic_bytes_total[1d]))`, Legend: "{{direction}}"}),
		withLegendTable(Series("Bandwidth: advertised, observed, used", "Advertised and observed bandwidth from the relays' descriptors (Tor Metrics, hourly) next to what the fleet actually writes. A large gap between advertised and used is spare capacity.", 12,
			Field{Unit: "Bps"}, false,
			Q{Expr: pfx + "advertised_bandwidth_bytes", Legend: "advertised"},
			Q{Expr: pfx + "observed_bandwidth_bytes", Legend: "observed"},
			Q{Expr: `sum(rate(` + pfx + `traffic_bytes_total{direction="written"}[$__rate_interval]))`, Legend: "used (written)"}), "mean", "max"),
	)
	setOverrides(&l, "Fleet throughput", directionOver)
	setOverrides(&l, "Traffic per day", directionColors)
	setOverrides(&l, "Bandwidth: advertised, observed, used", []any{
		override(byName("advertised"), fixedColor(PurpleLight), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}})),
		override(byName("observed"), fixedColor(Blue)),
		override(byName("used (written)"), fixedColor(Purple)),
	})

	l.Row("Relays", false)
	l.Add(relayTable())

	l.Row("Attention", false)
	l.Add(
		Table("Firing alerts", "Prometheus alert rules that fire right now (prometheus-fleet-rules.yml). Grafana lists all rules under Alerting → Alert rules.", 12, 8,
			Field{NoValue: "No alert fires"},
			M{
				"excludeByName": M{"Time": true, "__name__": true, "alertstate": true, "Value": true, "job": true, "instance": true, "fingerprint": true, "tor_instance": true, "role": true, "direction": true, "family": true},
				"indexByName":   M{"severity": 0, "alertname": 1, "nickname": 2, "host": 3, "flag": 4},
				"renameByName":  M{"severity": "Severity", "alertname": "Alert", "nickname": "Relay", "host": "Host", "flag": "Flag", "transport": "Transport", "version": "Version", "state": "State"},
			}, "Severity",
			Q{Expr: `ALERTS{alertstate="firing"}`}),
		Timeline("Host probe state", "Result of fleet serve's SSH probe per host: OK, no probe (tor-relay-setup missing or too old on the host) or unreachable.", 12, 8,
			Field{Mappings: []any{valueMap([3]string{"1", "OK", Green}, [3]string{"2", "No probe", Orange}, [3]string{"3", "Unreachable", Red})}, Thresholds: []Step{{Color: Grey}}},
			Q{Expr: `max by (host) ((` + hostM("up", `state="ok"`) + ` == 1) * 1 or (` + hostM("up", `state="no_probe"`) + ` == 1) * 2 or (` + hostM("up", `state="unreachable"`) + ` == 1) * 3)`, Legend: "{{host}}"}),
	)
	setOptions(&l, "Firing alerts", "Severity")
	setOverrides(&l, "Firing alerts", []any{
		override(byName("Severity"), prop("mappings", []any{valueMap([3]string{"critical", "critical", Red}, [3]string{"warning", "warning", Orange}, [3]string{"info", "info", Blue})}), cellColor(true), prop("custom.width", 90)),
	})

	l.Row("Network position", false)
	l.Add(
		withLegendTable(Series("Consensus weight share per relay", "Each relay's share of the network's consensus weight, stacked: the top line is the fleet's share. Filtered by host and role.", 12,
			Field{Unit: "percentunit", Decimals: ip(3)}, true,
			Q{Expr: relayM("consensus_weight_fraction"), Legend: "{{nickname}}"}), "mean", "lastNotNull"),
		withLegendTable(Series("Path selection probability", "How likely clients are to pick a fleet relay as guard, middle or exit (summed over the fleet, from Tor Metrics).", 12,
			Field{Unit: "percentunit", Decimals: ip(3)}, false,
			Q{Expr: pfx + "guard_probability", Legend: "guard"},
			Q{Expr: pfx + "middle_probability", Legend: "middle"},
			Q{Expr: pfx + "exit_probability", Legend: "exit"}), "mean", "lastNotNull"),
		withLegendTable(Series("Consensus weight by role", "The fleet's consensus weight (the bandwidth the directory authorities measured, scaled), stacked by role; the dashed line is the fleet total from fleet serve.", 24,
			Field{Decimals: ip(0), Min: fp(0)}, true,
			Q{Expr: `sum by (role) (` + relayM("consensus_weight") + `)`, Legend: "{{role}}"},
			Q{Expr: pfx + "consensus_weight", Legend: "fleet total"}), "mean", "lastNotNull"),
	)
	setOverrides(&l, "Consensus weight by role", []any{
		override(byName("guard"), fixedColor(Purple)), override(byName("exit"), fixedColor(Orange)),
		override(byName("middle"), fixedColor(Blue)), override(byName("bridge"), fixedColor(Green)),
		override(byName("fleet total"), fixedColor(PurpleLight), prop("custom.stacking", M{"mode": "none", "group": "B"}),
			prop("custom.fillOpacity", 0), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}})),
	})
	setOverrides(&l, "Path selection probability", []any{
		override(byName("guard"), fixedColor(Purple)), override(byName("middle"), fixedColor(Blue)), override(byName("exit"), fixedColor(Orange)),
	})

	l.Row("Geography and diversity", true)
	l.Add(
		Panel{
			Type: "geomap", Title: "Relays by country", W: 12, H: 12,
			Desc:    "Where the relays are, by the country Tor Metrics reports for their address. The circle size is the number of relays. The base map is loaded from CARTO by your browser.",
			Targets: []Q{{Expr: `count by (country) (` + unknownLabel(relayM("info"), "country") + `)`, Instant: true, Table: true}},
			Field:   Field{ColorMode: "fixed", FixedColor: Purple, Decimals: ip(0)},
			Transformations: []any{
				M{"id": "formatString", "options": M{"stringField": "country", "outputFormat": "Upper Case"}},
			},
			Options: geomapOptions(),
		},
		BarGauge("Relays per country", "Number of relays per country (ISO code from Tor Metrics). Diversity across countries and jurisdictions makes the network harder to observe.", 12, 12,
			Field{ColorMode: "continuous-purples", Decimals: ip(0), Min: fp(0)},
			Q{Expr: `sort_desc(count by (country) (` + unknownLabel(relayM("info"), "country") + `))`, Legend: "{{country}}", Instant: true}),
		Pie("Roles", "Relays by role: guard (Guard flag), exit (Exit flag), middle, or bridge.", 6, 8, Field{Decimals: ip(0)},
			Q{Expr: `count by (role) (` + relayM("info") + `)`, Legend: "{{role}}", Instant: true}),
		Pie("tor versions", "Relays by tor version. Several versions at once usually means some relays missed an upgrade.", 6, 8, Field{Decimals: ip(0)},
			Q{Expr: `count by (version) (` + unknownLabel(relayM("info"), "version") + `)`, Legend: "{{version}}", Instant: true}),
		BarGauge("Relays per network (AS)", "Number of relays per autonomous system. Many relays in one AS concentrate the fleet at one provider.", 12, 8,
			Field{ColorMode: "continuous-purples", Decimals: ip(0), Min: fp(0)},
			Q{Expr: `sort_desc(count by (as, as_name) (` + unknownLabel(relayM("info"), "as_name") + `))`, Legend: "{{as}} {{as_name}}", Instant: true}),
		BarGauge("Consensus weight share per network (AS)", "The fleet's consensus weight share by autonomous system.", 12, 8,
			Field{Unit: "percentunit", Decimals: ip(3), ColorMode: "continuous-purples", Min: fp(0)},
			Q{Expr: `sort_desc(sum by (as, as_name) (` + relayM("consensus_weight_fraction") + ` * on (host, tor_instance) group_left (as, as_name) max by (host, tor_instance, as, as_name) (` + unknownLabel(pfx+"relay_info", "as_name") + `)))`, Legend: "{{as}} {{as_name}}", Instant: true}),
		BarGauge("Consensus weight share per country", "The fleet's consensus weight share by country.", 12, 8,
			Field{Unit: "percentunit", Decimals: ip(3), ColorMode: "continuous-purples", Min: fp(0)},
			Q{Expr: `sort_desc(sum by (country) (` + relayM("consensus_weight_fraction") + ` * on (host, tor_instance) group_left (country) max by (host, tor_instance, country) (` + unknownLabel(pfx+"relay_info", "country") + `)))`, Legend: "{{country}}", Instant: true}),
	)
	setOverrides(&l, "Roles", []any{
		override(byName("guard"), fixedColor(Purple)), override(byName("exit"), fixedColor(Orange)),
		override(byName("middle"), fixedColor(Blue)), override(byName("bridge"), fixedColor(Green)),
	})

	l.Row("Overload and health", true)
	l.Add(
		Stat("Overloaded relays", "Relays Relay Search marks as overloaded: tor published overload-general in the last 72 hours (OOM, dropped ntor handshakes, or TCP port exhaustion).", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 1}}},
			Q{Expr: `sum(` + relayM("overloaded") + `) or vector(0)`, Legend: "overloaded"}),
		Stat("Relays with warnings", "Relays whose status report lists at least one problem.", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 1}}},
			Q{Expr: `count(` + relayM("warnings") + ` > 0) or vector(0)`, Legend: "relays"}),
		Stat("Dropped ntor handshakes, 24 h", "ntor and ntor_v3 onionskins the relays dropped in the last 24 hours because their CPU workers were busy.", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 1}}},
			Q{Expr: `sum(increase(` + relayM("onionskins_total", `type=~"ntor|ntor_v3"`, `action="dropped"`) + `[24h])) or vector(0)`, Legend: "dropped"}),
		Stat("Freed by the OOM handler, 24 h", "Bytes tor's out-of-memory handler freed in the last 24 hours (MaxMemInQueues reached).", 6,
			Field{Unit: "decbytes", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 1}}},
			Q{Expr: `sum(increase(` + relayM("oom_bytes_total") + `[24h])) or vector(0)`, Legend: "freed"}),
		withThresholdLine(withLegendTable(Series("ntor handshake drop ratio", "Share of ntor/ntor_v3 onionskins each relay dropped. From 1% over 6 hours tor reports overload-general (dashed line): give it more CPU or lower RelayBandwidthRate.", 12,
			Field{Unit: "percentunit", Decimals: ip(2), Min: fp(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 0.01}}}, false,
			Q{Expr: `sum by (nickname) (rate(` + relayM("onionskins_total", `type=~"ntor|ntor_v3"`, `action="dropped"`) + `[$__rate_interval])) / sum by (nickname) (rate(` + relayM("onionskins_total", `type=~"ntor|ntor_v3"`) + `[$__rate_interval]))`, Legend: "{{nickname}}"}), "mean", "max")),
		BarGauge("Socket usage", "Open sockets as a share of tor's socket limit per relay. At the limit tor publishes overload-fd-exhausted; raise LimitNOFILE.", 12, 8,
			Field{Unit: "percentunit", Decimals: ip(1), Min: fp(0), Max: fp(1), Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 0.8}, {Color: Red, Value: 0.9}}},
			Q{Expr: relayM("sockets_open") + ` / ` + relayM("sockets_limit"), Legend: "{{nickname}}", Instant: true}),
		Series("Freed by the OOM handler per hour", "Bytes freed by tor's out-of-memory handler per hour and relay. Shown as a rate per hour.", 8, Field{Unit: "decbytes"}, true,
			Q{Expr: `sum by (nickname) (rate(` + relayM("oom_bytes_total") + `[$__rate_interval]) * 3600)`, Legend: "{{nickname}}"}),
		Series("TCP port exhaustion per hour", "Connections per hour that failed because no local TCP port was free. Widen net.ipv4.ip_local_port_range. Shown as a rate per hour.", 8, Field{Decimals: ip(1)}, true,
			Q{Expr: `sum by (nickname) (rate(` + relayM("tcp_exhaustion_total") + `[$__rate_interval]) * 3600)`, Legend: "{{nickname}}"}),
		Series("Global rate limit reached per hour", "How often per hour the global BandwidthRate bucket ran empty (read/write). Expected with a deliberate limit. Shown as a rate per hour.", 8, Field{Decimals: ip(1)}, true,
			Q{Expr: `sum by (nickname, side) (rate(` + relayM("rate_limit_reached_total") + `[$__rate_interval]) * 3600)`, Legend: "{{nickname}} {{side}}"}),
		withLegendTable(Series("OR connections per relay", "Open connections to other relays and clients per relay."+privacyNote, 12,
			Field{Decimals: ip(0), NoValue: "No data yet, or hidden by privacy mode"}, false,
			Q{Expr: relayM("or_connections"), Legend: "{{nickname}}"}), "mean", "lastNotNull"),
		Series("Status warnings per relay", "Number of problems each relay's status report lists (tor-relay-setup status on the host shows them).", 12,
			Field{Decimals: ip(0), Min: fp(0)}, false,
			Q{Expr: relayM("warnings"), Legend: "{{nickname}}"}),
	)

	l.Row("Accounting", true)
	l.Add(
		BarGauge("AccountingMax used", "Share of the accounting budget each relay used this period. tor hibernates at 100% until the period ends.", 12, 8,
			Field{Unit: "percentunit", Decimals: ip(1), Min: fp(0), Max: fp(1), NoValue: "No relay uses AccountingMax", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 0.8}, {Color: Red, Value: 0.95}}},
			Q{Expr: relayM("accounting_used_bytes") + ` / ` + relayM("accounting_max_bytes"), Legend: "{{nickname}}", Instant: true}),
		BarGauge("Projected by the end of the period", "Budget each relay will have used when the period ends, at its pace so far. Above 100% it hibernates early: lower RelayBandwidthRate.", 12, 8,
			Field{Unit: "percentunit", Decimals: ip(0), Min: fp(0), Max: fp(1.2), NoValue: "No relay uses AccountingMax", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 0.9}, {Color: Red, Value: 1}}},
			Q{Expr: relayM("accounting_projected_bytes") + ` / ` + relayM("accounting_max_bytes"), Legend: "{{nickname}}", Instant: true}),
		withLegendTable(Series("Accounting budget", "Bytes counted against AccountingMax this period (solid) and the limit (dashed), per relay.", 16,
			Field{Unit: "decbytes", Min: fp(0), NoValue: "No relay uses AccountingMax"}, false,
			Q{Expr: relayM("accounting_used_bytes"), Legend: "{{nickname}} used"},
			Q{Expr: relayM("accounting_max_bytes"), Legend: "{{nickname}} limit"}), "lastNotNull"),
		BarGauge("Period ends in", "Time until each relay's accounting period ends and the budget resets.", 8, 8,
			Field{Unit: "dtdurations", Min: fp(0), ColorMode: "fixed", FixedColor: Purple, NoValue: "No relay uses AccountingMax"},
			Q{Expr: relayM("accounting_period_end_timestamp_seconds") + ` - time()`, Legend: "{{nickname}}", Instant: true}),
	)
	setOverrides(&l, "Accounting budget", []any{
		override(byRegexp(".* limit$"), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}}), prop("custom.fillOpacity", 0)),
	})

	l.Row("Family and keys", true)
	l.Add(
		Stat("Not in the fleet's family", "Relays whose FamilyId set differs from the fleet majority, so clients might put two fleet relays in one circuit.", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 1}}},
			Q{Expr: `count(` + relayM("family_consistent") + ` == 0) or vector(0)`, Legend: "relays"}),
		Stat("Missing family keys", "FamilyIds in torrc without their secret family key on the relay.", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 1}}},
			Q{Expr: `sum(` + relayM("family_keys_missing") + `) or vector(0)`, Legend: "keys"}),
		Stat("Next signing certificate expiry", "The ed25519 signing certificate that expires first (relays with an offline master key need a renewal before that).", 6,
			expiryField("unknown"),
			Q{Expr: `min(` + relayM("signing_cert_expiry_timestamp_seconds") + `) - time()`, Legend: "expires in"}),
		Stat("Relays known to Tor Metrics", "Relays Tor Metrics lists (published) out of all relays.", 6,
			Field{Decimals: ip(0), ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: `sum(` + relayM("published") + `)`, Legend: "listed"}),
		Table("Family", "Each relay's FamilyIds, missing secret keys and whether its family matches the fleet majority.", 12, 9,
			Field{},
			M{
				"excludeByName": M{"Time": true, "job": true, "instance": true, "fingerprint": true, "tor_instance": true, "role": true},
				"indexByName":   M{"nickname": 0, "host": 1, "Value #A": 2, "Value #B": 3, "Value #C": 4},
				"renameByName":  M{"nickname": "Relay", "host": "Host", "Value #A": "FamilyIds", "Value #B": "Missing keys", "Value #C": "Consistent"},
			}, "Relay",
			Q{Expr: relayM("family_ids")}, Q{Expr: relayM("family_keys_missing")}, Q{Expr: relayM("family_consistent")}),
		BarGauge("Signing certificate valid for", "Time until each relay's ed25519 signing certificate expires; red below a day, orange below a week. tor renews it itself unless the master key is offline.", 12, 9,
			expiryField("No expiry known"),
			Q{Expr: relayM("signing_cert_expiry_timestamp_seconds") + ` - time()`, Legend: "{{nickname}}", Instant: true}),
	)
	setOverrides(&l, "Family", []any{
		override(byName("Consistent"), prop("mappings", checkMappings), cellColor(false)),
		override(byName("Missing keys"), prop("thresholds", thresholds(Step{Color: Green}, Step{Color: Red, Value: 1})), cellColor(false)),
	})

	l.Row("Hosts and probes", true)
	l.Add(
		Table("Hosts", "Every server fleet serve probes: probe state, tor-relay-setup version, time since the last successful probe, probe duration, and relays found.", 24, 8,
			Field{},
			M{
				"excludeByName": M{"Time": true, "Value #A": true, "Value #B": true, "job": true, "instance": true},
				"indexByName":   M{"host": 0, "state": 1, "version": 2, "Value #C": 3, "Value #D": 4, "Value #E": 5},
				"renameByName":  M{"host": "Host", "state": "Probe", "version": "tor-relay-setup", "Value #C": "Last success", "Value #D": "Probe duration", "Value #E": "Relays"},
			}, "Host",
			Q{Expr: `max by (host, state) (` + hostM("up") + ` == 1)`},
			Q{Expr: `max by (host, version) (` + hostM("tool_info") + `)`},
			Q{Expr: `time() - max by (host) (` + hostM("last_success_timestamp_seconds") + `)`},
			Q{Expr: `max by (host) (` + hostM("probe_duration_seconds") + `)`},
			Q{Expr: `count by (host) (` + pfx + `relay_info{host=~"$host"})`}),
		withLegendTable(Series("Probe duration per host", "How long the SSH probe of each host took. Rising times point at a slow network or a loaded host.", 12,
			Field{Unit: "s"}, false,
			Q{Expr: hostM("probe_duration_seconds"), Legend: "{{host}}"}), "mean", "max"),
		Series("Probe round and scrape", "Duration of fleet serve's last full probe round, and of Prometheus's scrape of fleet serve.", 12,
			Field{Unit: "s"}, false,
			Q{Expr: pfx + "probe_duration_seconds", Legend: "probe round"},
			Q{Expr: `scrape_duration_seconds{job="tor-relay-fleet"}`, Legend: "scrape"}),
		StatState("fleet serve scrape", "Whether Prometheus can scrape fleet serve on 127.0.0.1:9850 with its bearer token.", 4,
			[]any{valueMap([3]string{"1", "up", Green}, [3]string{"0", "down", Red})},
			Q{Expr: `up{job="tor-relay-fleet"}`, Legend: "scrape"}),
		Stat("Last probe round", "Time since fleet serve finished its last full probe round; orange after 5 minutes, red after 15.", 4,
			Field{Unit: "dtdurations", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 300}, {Color: Red, Value: 900}}},
			Q{Expr: `time() - ` + pfx + `last_probe_timestamp_seconds`, Legend: "age"}),
		Stat("Probe round duration", "How long fleet serve's last full probe round over all hosts took.", 4,
			Field{Unit: "s", Decimals: ip(1), ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: pfx + "probe_duration_seconds", Legend: "duration"}),
		Stat("Tor Metrics data age", "Time since fleet serve last refreshed relay data from Tor Metrics (Onionoo publishes hourly).", 4,
			Field{Unit: "dtdurations", Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 7200}, {Color: Red, Value: 10800}}},
			Q{Expr: `time() - ` + pfx + `directory_last_update_timestamp_seconds`, Legend: "age"}),
		Stat("Hosts unreachable", "Hosts whose last SSH probe failed to connect.", 4,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 1}}},
			Q{Expr: pfx + "hosts_unreachable", Legend: "hosts"}),
		Stat("Hosts without probe", "Hosts where tor-relay-setup fleet-probe is missing or too old.", 4,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 1}}},
			Q{Expr: pfx + "hosts_without_probe", Legend: "hosts"}),
	)
	setOverrides(&l, "Hosts", []any{
		override(byName("Probe"), prop("mappings", []any{valueMap([3]string{"ok", "OK", Green}, [3]string{"unreachable", "unreachable", Red}, [3]string{"no_probe", "no probe", Orange})}), cellColor(false)),
		override(byName("Last success"), prop("unit", "dtdurations"), prop("thresholds", thresholds(Step{Color: Green}, Step{Color: Orange, Value: 300}, Step{Color: Red, Value: 900})), cellColor(false)),
		override(byName("Probe duration"), prop("unit", "s"), prop("decimals", 1)),
	})

	return Dashboard(
		"tor-fleet-overview", "Tor fleet — overview",
		"All relays of the fleet aggregated: health, traffic, network position, geography, overload, accounting and keys. Data: tor-relay-setup fleet serve via Prometheus.",
		[]string{"tor", "tor-relay-setup"},
		[]any{
			DatasourceVar(),
			QueryVar("host", "Host", "label_values("+pfx+"relay_info, host)", true),
			QueryVar("role", "Role", "label_values("+pfx+"relay_info, role)", true),
		},
		l.Panels(),
		[]any{M{"title": "Relay detail", "type": "dashboards", "tags": []string{"tor-relay-setup"}, "asDropdown": true, "includeVars": false, "keepTime": true, "icon": "external link", "targetBlank": false, "tooltip": "", "url": ""}},
		"now-24h",
	)
}

func geomapOptions() M {
	return M{
		"view":     M{"id": "zero", "lat": 25, "lon": 10, "zoom": 1.2, "allLayers": true},
		"controls": M{"showZoom": true, "mouseWheelZoom": false, "showAttribution": true, "showScale": false, "showMeasure": false, "showDebug": false},
		"basemap":  M{"type": "default", "name": "Base map", "config": M{}},
		"layers": []any{M{
			"type": "markers", "name": "Relays", "tooltip": true,
			"location": M{"mode": "lookup", "lookup": "country", "gazetteer": "public/gazetteer/countries.json"},
			"config": M{
				"showLegend": false,
				"style": M{
					"size":        M{"field": "Value", "fixed": 8, "min": 8, "max": 30},
					"color":       M{"fixed": Purple},
					"opacity":     0.75,
					"symbol":      M{"mode": "fixed", "fixed": "img/icons/marker/circle.svg"},
					"text":        M{"mode": "field", "field": "Value", "fixed": ""},
					"textConfig":  M{"fontSize": 11, "offsetX": 0, "offsetY": 0, "textAlign": "center", "textBaseline": "middle"},
					"symbolAlign": M{"horizontal": "center", "vertical": "center"},
					"rotation":    M{"fixed": 0, "mode": "mod", "min": -360, "max": 360},
				},
			},
		}},
		"tooltip": M{"mode": "details"},
	}
}

// relayTable is the per-relay table with a link to the detail dashboard.
func relayTable() Panel {
	link := "/d/tor-fleet-relay/tor-fleet-relay-detail?var-host=${__data.fields.host}&var-relay=${__data.fields.nickname}&${datasource:queryparam}&${__url_time_range}"
	p := Table("Relays", "One row per relay. Click a nickname for its detail dashboard. Throughput is bytes written per second over 5 minutes (empty in privacy mode); uptime counts from tor's last restart as Tor Metrics saw it; Stable/Fast/HSDir are consensus flags.", 24, 12,
		Field{},
		M{
			"excludeByName": M{"Time": true, "job": true, "instance": true, "fingerprint": true, "tor_instance": true, "transport": true, "Value #A": true},
			"indexByName": M{
				"nickname": 0, "host": 1, "role": 2, "Value #B": 3, "Value #H": 4, "Value #C": 5, "Value #D": 6, "Value #E": 7,
				"Value #F": 8, "Value #G": 9, "Value #I": 10, "Value #J": 11, "Value #K": 12, "country": 13, "as": 14, "as_name": 15, "version": 16,
			},
			"renameByName": M{
				"nickname": "Nickname", "host": "Host", "role": "Role", "country": "Country", "as": "AS", "as_name": "Network", "version": "tor",
				"Value #B": "Service", "Value #C": "Weight", "Value #D": "Share", "Value #E": "Throughput", "Value #F": "Uptime",
				"Value #G": "Certificate", "Value #H": "Warnings", "Value #I": "Stable", "Value #J": "Fast", "Value #K": "HSDir",
			},
		}, "Nickname",
		Q{Expr: relayM("info")},
		Q{Expr: relayM("service_active")},
		Q{Expr: relayM("consensus_weight")},
		Q{Expr: relayM("consensus_weight_fraction")},
		Q{Expr: `sum without (direction) (rate(` + relayM("traffic_bytes_total", `direction="written"`) + `[5m]))`},
		Q{Expr: `time() - ` + relayM("last_restarted_timestamp_seconds")},
		Q{Expr: relayM("signing_cert_expiry_timestamp_seconds") + ` - time()`},
		Q{Expr: relayM("warnings")},
		Q{Expr: `max without (flag) (` + relayM("flag", `flag="Stable"`) + `)`},
		Q{Expr: `max without (flag) (` + relayM("flag", `flag="Fast"`) + `)`},
		Q{Expr: `max without (flag) (` + relayM("flag", `flag="HSDir"`) + `)`},
	)
	p.Overrides = []any{
		override(byName("Nickname"), prop("links", []any{M{"title": "Relay detail", "url": link}}), prop("custom.width", 150)),
		override(byName("Role"), prop("mappings", roleMappings), cellColor(false), prop("custom.width", 80)),
		override(byName("Country"), prop("custom.width", 70)),
		override(byName("Host"), prop("custom.width", 160)),
		override(byName("Network"), prop("custom.width", 150)),
		override(byName("tor"), prop("custom.width", 80)),
		override(byName("AS"), prop("custom.width", 85)),
		override(byName("Service"), prop("mappings", runMappings), cellColor(false), prop("custom.width", 80)),
		override(byRegexp("^(Stable|Fast|HSDir)$"), prop("mappings", checkMappings), cellColor(false), prop("custom.align", "center"), prop("custom.width", 58)),
		override(byName("Weight"), prop("decimals", 0)),
		override(byName("Share"), prop("unit", "percentunit"), prop("decimals", 3),
			prop("custom.cellOptions", M{"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}), prop("color", M{"mode": "fixed", "fixedColor": Purple})),
		override(byName("Throughput"), prop("unit", "Bps"), prop("decimals", 1)),
		override(byName("Uptime"), prop("unit", "dtdurations"), prop("decimals", 0),
			prop("thresholds", thresholds(Step{Color: Orange}, Step{Color: "text", Value: 86400})), cellColor(false)),
		override(byName("Certificate"), prop("unit", "dtdurations"), prop("decimals", 0), prop("thresholds", thresholds(expirySteps...)), cellColor(false)),
		override(byName("Warnings"), prop("decimals", 0), prop("thresholds", thresholds(warnSteps...)), cellColor(true), prop("custom.width", 90)),
	}
	return p
}

// setOverrides sets the overrides of the panel with this title.
func setOverrides(l *Layout, title string, ov []any) {
	if p := l.find(title); p != nil {
		p["fieldConfig"].(M)["overrides"] = ov
	}
}

// setOptions sets a table's sort column.
func setOptions(l *Layout, title, sortBy string) {
	if p := l.find(title); p != nil {
		p["options"].(M)["sortBy"] = []any{M{"displayName": sortBy, "desc": false}}
	}
}

func (l *Layout) find(title string) M {
	var walk func([]any) M
	walk = func(ps []any) M {
		for _, x := range ps {
			p := x.(M)
			if p["title"] == title && p["type"] != "row" {
				return p
			}
			if sub, ok := p["panels"].([]any); ok {
				if r := walk(sub); r != nil {
					return r
				}
			}
		}
		return nil
	}
	return walk(l.panels)
}

// unknownLabel names an empty label "unknown" (bridges have no country or
// AS in Tor Metrics), so legends never fall back to "Value".
func unknownLabel(sel, label string) string {
	return `label_replace(` + sel + `, "` + label + `", "unknown", "` + label + `", "")`
}
