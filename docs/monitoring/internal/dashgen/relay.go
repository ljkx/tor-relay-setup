package dashgen

import "strings"

// oneM is a series of the selected relay, with extra label matchers.
func oneM(name string, extra ...string) string {
	sel := append([]string{`host="$host"`, `nickname="$relay"`}, extra...)
	return pfx + "relay_" + name + "{" + strings.Join(sel, ", ") + "}"
}

// Relay is the "Tor fleet — relay detail" dashboard.
func Relay() M {
	var l Layout
	l.Add(
		StatState("Service", "Whether the relay's tor systemd unit is active, from the last SSH probe.", 4,
			[]any{valueMap([3]string{"1", "Running", Green}, [3]string{"0", "Stopped", Red}), nullMap("unknown", Grey)},
			Q{Expr: oneM("service_active"), Legend: "service"}),
		StatState("ORPort", "Whether something listens on the ORPort, per address family.", 4,
			[]any{valueMap([3]string{"1", "listening", Green}, [3]string{"0", "closed", Red})},
			Q{Expr: oneM("listener"), Legend: "{{family}}"}),
		StatState("Reachable", "Whether tor's self-test confirmed the ORPort is reachable from outside, per address family.", 4,
			[]any{valueMap([3]string{"1", "reachable", Green}, [3]string{"0", "not confirmed", Red})},
			Q{Expr: oneM("reachable"), Legend: "{{family}}"}),
		StatState("Consensus", "Whether Tor Metrics lists the relay, and whether the directory authorities consider it running.", 4,
			[]any{valueMap([3]string{"2", "Running", Green}, [3]string{"1", "Listed, not running", Red}, [3]string{"0", "Not listed", Orange})},
			Q{Expr: `(` + oneM("published") + ` == 0) or (` + oneM("running") + ` + 1)`, Legend: "consensus"}),
		StatNamed("Role and version", "The relay's role (from its flags) and tor version.", 4,
			Field{ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: oneM("info"), Legend: "{{role}} · tor {{version}}"}),
		StatNamed("Location", "Country and autonomous system of the relay's address, from Tor Metrics.", 4,
			Field{ColorMode: "fixed", FixedColor: PurpleDark},
			Q{Expr: oneM("info"), Legend: "{{country}} · {{as}} {{as_name}}"}),

		StatNamed("Flags", "Consensus flags the relay holds now.", 8,
			Field{ColorMode: "fixed", FixedColor: Purple, NoValue: "no flags"},
			Q{Expr: oneM("flag"), Legend: "{{flag}}"}),
		Stat("Uptime", "Time since tor last restarted, as reported in the relay's descriptor (Tor Metrics). Guard and Stable need long uptimes.", 4,
			Field{Unit: "dtdurations", Thresholds: []Step{{Color: Orange}, {Color: Purple, Value: 86400}}},
			Q{Expr: `time() - ` + oneM("last_restarted_timestamp_seconds"), Legend: "uptime"}),
		Stat("First seen", "When Tor Metrics first saw this relay.", 4,
			Field{Unit: "dateTimeFromNow", ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: oneM("first_seen_timestamp_seconds") + ` * 1000`, Legend: "first seen"}),
		Stat("Signing certificate", "Time until the ed25519 signing certificate expires. With an offline master key renew it with tor-relay-setup keys renew before it runs out.", 4,
			expiryField("unknown"),
			Q{Expr: oneM("signing_cert_expiry_timestamp_seconds") + ` - time()`, Legend: "expires in"}),
		Stat("Warnings", "Problems the relay's status report lists; run tor-relay-setup status on the host for the text.", 4,
			Field{Decimals: ip(0), Thresholds: warnSteps},
			Q{Expr: oneM("warnings"), Legend: "warnings"}),

		Stat("Consensus weight", "The relay's consensus weight: the bandwidth the directory authorities measured, scaled.", 4,
			Field{Decimals: ip(0), ColorMode: "fixed", FixedColor: Purple}, Q{Expr: oneM("consensus_weight"), Legend: "weight"}),
		Stat("Weight share", "The relay's share of the network's total consensus weight.", 4,
			pct3, Q{Expr: oneM("consensus_weight_fraction"), Legend: "share"}),
		Stat("Guard probability", "Probability that a client picks this relay as its guard.", 4,
			pct3, Q{Expr: oneM("guard_probability"), Legend: "guard"}),
		Stat("Middle probability", "Probability that a circuit uses this relay in the middle.", 4,
			pct3, Q{Expr: oneM("middle_probability"), Legend: "middle"}),
		Stat("Exit probability", "Probability that a circuit exits through this relay.", 4,
			pct3, Q{Expr: oneM("exit_probability"), Legend: "exit"}),
		Stat("Throughput now", "Bytes per second read (in) and written (out) over the last 5 minutes."+privacyNote, 4,
			Field{Unit: "Bps", ColorMode: "fixed", FixedColor: Purple, NoValue: "hidden"},
			Q{Expr: `sum(rate(` + oneM("traffic_bytes_total", `direction="read"`) + `[5m]))`, Legend: "in"},
			Q{Expr: `sum(rate(` + oneM("traffic_bytes_total", `direction="written"`) + `[5m]))`, Legend: "out"}),
	)
	setOverrides(&l, "Flags", []any{
		override(byRegexp("^(BadExit|StaleDesc)$"), fixedColor(Red)),
		override(byName("MiddleOnly"), fixedColor(Orange)),
		override(byRegexp("^(Guard|Exit)$"), fixedColor(PurpleDark)),
	})
	setStatOption(&l, "Flags", "orientation", "vertical")

	l.Row("Traffic", false)
	l.Add(
		withLegendTable(Series("Throughput", "Bytes per second read (below the axis) and written (above)."+privacyNote, 12,
			Field{Unit: "Bps", NoValue: "No data yet, or hidden by privacy mode"}, false,
			Q{Expr: `sum by (direction) (rate(` + oneM("traffic_bytes_total") + `[$__rate_interval]))`, Legend: "{{direction}}"}), "mean", "max", "lastNotNull"),
		withLegendTable(Series("Bandwidth: advertised, observed, used", "Advertised and observed bandwidth from the relay's descriptor (Tor Metrics, hourly) next to what it writes.", 12,
			Field{Unit: "Bps"}, false,
			Q{Expr: oneM("advertised_bandwidth_bytes"), Legend: "advertised"},
			Q{Expr: oneM("observed_bandwidth_bytes"), Legend: "observed"},
			Q{Expr: `sum(rate(` + oneM("traffic_bytes_total", `direction="written"`) + `[$__rate_interval]))`, Legend: "used (written)"}), "mean", "max"),
		Bars("Traffic per day", "Bytes read and written per day."+privacyNote, 12,
			Field{Unit: "decbytes", NoValue: "Daily totals appear after the first full day, unless privacy mode hides them"}, "1d", false,
			Q{Expr: `sum by (direction) (increase(` + oneM("traffic_bytes_total") + `[1d]))`, Legend: "{{direction}}"}),
		withLegendTable(Series("OR connections", "Open connections to other relays and clients."+privacyNote, 12,
			Field{Decimals: ip(0), NoValue: "No data yet, or hidden by privacy mode"}, false,
			Q{Expr: oneM("or_connections"), Legend: "connections"}), "mean", "max", "lastNotNull"),
	)
	setOverrides(&l, "Throughput", directionOver)
	setOverrides(&l, "Traffic per day", directionColors)
	setOverrides(&l, "Bandwidth: advertised, observed, used", []any{
		override(byName("advertised"), fixedColor(PurpleLight), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}})),
		override(byName("observed"), fixedColor(Blue)),
		override(byName("used (written)"), fixedColor(Purple)),
	})
	setOverrides(&l, "OR connections", []any{override(byName("connections"), fixedColor(Purple))})

	l.Row("Network position", false)
	l.Add(
		withLegendTable(Series("Consensus weight over time", "Consensus weight (left axis) and its share of the network (right axis), from Tor Metrics.", 12,
			Field{Decimals: ip(0)}, false,
			Q{Expr: oneM("consensus_weight"), Legend: "weight"},
			Q{Expr: oneM("consensus_weight_fraction"), Legend: "share"}), "mean", "lastNotNull"),
		withLegendTable(Series("Path selection probability", "How likely clients are to pick this relay as guard, middle or exit.", 12,
			Field{Unit: "percentunit", Decimals: ip(3)}, false,
			Q{Expr: oneM("guard_probability"), Legend: "guard"},
			Q{Expr: oneM("middle_probability"), Legend: "middle"},
			Q{Expr: oneM("exit_probability"), Legend: "exit"}), "mean", "lastNotNull"),
		Timeline("Flags over time", "Which consensus flags the relay held, hour by hour (Tor Metrics). Gaps mean the flag was not held.", 24, 7,
			Field{Mappings: []any{valueMap([3]string{"1", "held", Purple})}, ColorMode: "fixed", FixedColor: Purple},
			Q{Expr: oneM("flag"), Legend: "{{flag}}"}),
	)
	setOverrides(&l, "Consensus weight over time", []any{
		override(byName("weight"), fixedColor(Purple)),
		override(byName("share"), fixedColor(Blue), prop("unit", "percentunit"), prop("decimals", 3), prop("custom.axisPlacement", "right")),
	})
	setOverrides(&l, "Path selection probability", []any{
		override(byName("guard"), fixedColor(Purple)), override(byName("middle"), fixedColor(Blue)), override(byName("exit"), fixedColor(Orange)),
	})

	l.Row("Health", false)
	good := []any{valueMap([3]string{"1", "yes", Green}, [3]string{"0", "no", Red})}
	l.Add(
		Timeline("Health over time", "Service, ORPort, reachability, consensus and family state from every probe. Red is a problem; for \"overloaded\" red means yes.", 24, 8,
			Field{Mappings: good, Thresholds: []Step{{Color: Grey}}},
			Q{Expr: oneM("service_active"), Legend: "service active"},
			Q{Expr: `max(` + oneM("listener") + `)`, Legend: "ORPort listening"},
			Q{Expr: oneM("reachable", `family="ipv4"`), Legend: "reachable (IPv4)"},
			Q{Expr: oneM("published"), Legend: "listed by Tor Metrics"},
			Q{Expr: oneM("running"), Legend: "running in consensus"},
			Q{Expr: oneM("family_consistent"), Legend: "family consistent"},
			Q{Expr: oneM("overloaded"), Legend: "overloaded"}),
		Series("Status warnings", "Number of problems the relay's status report lists.", 12,
			Field{Decimals: ip(0), Min: fp(0)}, false,
			Q{Expr: oneM("warnings"), Legend: "warnings"}),
		Series("Sockets", "Open sockets and tor's socket limit. At the limit tor publishes overload-fd-exhausted.", 12,
			Field{Decimals: ip(0), Min: fp(0)}, false,
			Q{Expr: oneM("sockets_open"), Legend: "open"},
			Q{Expr: oneM("sockets_limit"), Legend: "limit"}),
	)
	setOverrides(&l, "Health over time", []any{
		override(byName("overloaded"), prop("mappings", []any{valueMap([3]string{"1", "yes", Red}, [3]string{"0", "no", Green})})),
	})
	setOverrides(&l, "Status warnings", []any{override(byName("warnings"), fixedColor(Orange))})
	setOverrides(&l, "Sockets", []any{
		override(byName("open"), fixedColor(Purple)),
		override(byName("limit"), fixedColor(Red), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}}), prop("custom.fillOpacity", 0)),
	})

	l.Row("Load and overload", true)
	l.Add(
		withLegendTable(Series("Onionskins processed", "Circuit handshakes processed per second, by type (ntor_v3 is current, ntor older clients, fast and tap legacy).", 12,
			Field{Unit: "ops"}, true,
			Q{Expr: `sum by (type) (rate(` + oneM("onionskins_total", `action="processed"`) + `[$__rate_interval]))`, Legend: "{{type}}"}), "mean", "max"),
		withLegendTable(Series("Onionskins dropped", "Circuit handshakes dropped per second because tor's CPU workers were busy, by type.", 12,
			Field{Unit: "ops"}, true,
			Q{Expr: `sum by (type) (rate(` + oneM("onionskins_total", `action="dropped"`) + `[$__rate_interval]))`, Legend: "{{type}}"}), "mean", "max"),
		withThresholdLine(Series("ntor handshake drop ratio", "Share of ntor/ntor_v3 handshakes dropped. From 1% over 6 hours tor reports overload-general (dashed line).", 12,
			Field{Unit: "percentunit", Decimals: ip(2), Min: fp(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 0.01}}}, false,
			Q{Expr: `sum(rate(` + oneM("onionskins_total", `type=~"ntor|ntor_v3"`, `action="dropped"`) + `[$__rate_interval])) / sum(rate(` + oneM("onionskins_total", `type=~"ntor|ntor_v3"`) + `[$__rate_interval]))`, Legend: "drop ratio"})),
		Series("Freed by the OOM handler per hour", "Bytes tor's out-of-memory handler freed per hour, by subsystem (cell, dns, geoip, hsdir). Shown as a rate per hour.", 12, Field{Unit: "decbytes"}, true,
			Q{Expr: `sum by (subsys) (rate(` + oneM("oom_bytes_total") + `[$__rate_interval]) * 3600)`, Legend: "{{subsys}}"}),
		Series("TCP port exhaustion per hour", "Connections per hour that failed for lack of a local TCP port. Shown as a rate per hour.", 8, Field{Decimals: ip(1)}, false,
			Q{Expr: `rate(` + oneM("tcp_exhaustion_total") + `[$__rate_interval]) * 3600`, Legend: "events"}),
		Series("Global rate limit reached per hour", "How often per hour the global BandwidthRate bucket ran empty, by side. Shown as a rate per hour.", 8, Field{Decimals: ip(1)}, true,
			Q{Expr: `sum by (side) (rate(` + oneM("rate_limit_reached_total") + `[$__rate_interval]) * 3600)`, Legend: "{{side}}"}),
		Stat("Last overload-general", "When tor last reported overload-general, from Tor Metrics. Relay Search shows the relay as overloaded for 72 hours after it.", 8,
			Field{Unit: "dateTimeFromNow", ColorMode: "fixed", FixedColor: Orange, NoValue: "never"},
			Q{Expr: oneM("overload_general_timestamp_seconds") + ` * 1000`, Legend: "last"}),
	)
	setOverrides(&l, "ntor handshake drop ratio", []any{override(byName("drop ratio"), fixedColor(Purple))})
	setOverrides(&l, "TCP port exhaustion per hour", []any{override(byName("events"), fixedColor(Orange))})

	l.Row("Accounting", true)
	l.Add(
		withLegendTable(Series("Accounting budget", "Bytes counted against AccountingMax this period, the projection for its end at the current pace, and the limit.", 16,
			Field{Unit: "decbytes", Min: fp(0), NoValue: "AccountingMax is not set"}, false,
			Q{Expr: oneM("accounting_used_bytes"), Legend: "used"},
			Q{Expr: oneM("accounting_projected_bytes"), Legend: "projected"},
			Q{Expr: oneM("accounting_max_bytes"), Legend: "limit"}), "lastNotNull"),
		Panel{
			Type: "gauge", Title: "Budget used", W: 8, H: 8,
			Desc:    "Share of AccountingMax used this period; tor hibernates at 100%.",
			Targets: []Q{{Expr: oneM("accounting_used_bytes") + ` / ` + oneM("accounting_max_bytes"), Legend: "used"}},
			Field: Field{Unit: "percentunit", Decimals: ip(1), Min: fp(0), Max: fp(1), NoValue: "not set",
				Thresholds: []Step{{Color: Green}, {Color: Orange, Value: 0.8}, {Color: Red, Value: 0.95}}},
			Options: M{"reduceOptions": reduce("lastNotNull"), "orientation": "auto", "showThresholdLabels": false, "showThresholdMarkers": true, "sizing": "auto", "minVizHeight": 75, "minVizWidth": 75},
		},
		Stat("Period ends in", "Time until the accounting period ends and the budget resets.", 8,
			Field{Unit: "dtdurations", ColorMode: "fixed", FixedColor: Purple, NoValue: "not set"},
			Q{Expr: oneM("accounting_period_end_timestamp_seconds") + ` - time()`, Legend: "ends in"}),
	)
	setOverrides(&l, "Accounting budget", []any{
		override(byName("used"), fixedColor(Purple)),
		override(byName("projected"), fixedColor(Orange), prop("custom.lineStyle", M{"fill": "dot", "dash": []int{2, 6}}), prop("custom.fillOpacity", 0)),
		override(byName("limit"), fixedColor(Red), prop("custom.lineStyle", M{"fill": "dash", "dash": []int{10, 10}}), prop("custom.fillOpacity", 0)),
	})

	l.Row("Keys, family and transports", true)
	l.Add(
		Stat("FamilyIds", "Number of FamilyIds in the relay's torrc.", 6,
			Field{Decimals: ip(0), ColorMode: "fixed", FixedColor: Purple}, Q{Expr: oneM("family_ids"), Legend: "ids"}),
		Stat("Missing family keys", "FamilyIds without their secret key on the relay.", 6,
			Field{Decimals: ip(0), Thresholds: []Step{{Color: Green}, {Color: Red, Value: 1}}}, Q{Expr: oneM("family_keys_missing"), Legend: "missing"}),
		StatState("Family", "Whether the relay's FamilyId set matches the fleet majority.", 6,
			[]any{valueMap([3]string{"1", "consistent", Green}, [3]string{"0", "differs", Red})},
			Q{Expr: oneM("family_consistent"), Legend: "family"}),
		StatState("Bridge transport", "Bridges only: whether the pluggable transport listens.", 6,
			[]any{valueMap([3]string{"1", "listening", Green}, [3]string{"0", "down", Red}), nullMap("not a bridge", Grey)},
			Q{Expr: oneM("bridge_transport_listening"), Legend: "{{transport}}"}),
		Series("Signing certificate validity", "Time left until the ed25519 signing certificate expires. tor renews it itself unless the master key is offline; the drops are renewals.", 24,
			expiryField("unknown"), false,
			Q{Expr: oneM("signing_cert_expiry_timestamp_seconds") + ` - time()`, Legend: "valid for"}),
	)
	setOverrides(&l, "Signing certificate validity", []any{override(byName("valid for"), fixedColor(Purple))})

	d := Dashboard(
		"tor-fleet-relay", "Tor fleet — relay detail",
		"One relay of the fleet over time: health, traffic, consensus, flags, load, accounting and keys. Pick the host and relay at the top, or click a nickname on the overview.",
		[]string{"tor", "tor-relay-setup"},
		[]any{
			DatasourceVar(),
			QueryVar("host", "Host", "label_values("+pfx+"relay_info, host)", false),
			QueryVar("relay", "Relay", "label_values("+pfx+`relay_info{host="$host"}, nickname)`, false),
		},
		l.Panels(),
		[]any{M{"title": "Fleet overview", "type": "link", "url": "/d/tor-fleet-overview/tor-fleet-overview", "icon": "dashboard", "includeVars": false, "keepTime": true, "asDropdown": false, "targetBlank": false, "tags": []string{}, "tooltip": "All relays"}},
		"now-7d",
	)
	d["annotations"] = M{"list": []any{
		builtinAnnotations(),
		M{
			"name": "tor restarts", "enable": true, "hide": false, "iconColor": Orange, "datasource": ds,
			"expr":        `changes(` + oneM("last_restarted_timestamp_seconds") + `[10m]) > 0`,
			"step":        "5m",
			"titleFormat": "tor restarted", "textFormat": "{{nickname}} on {{host}}",
			"useValueForTime": false,
		},
	}}
	return d
}

func setStatOption(l *Layout, title, key string, v any) {
	if p := l.find(title); p != nil {
		p["options"].(M)[key] = v
	}
}
