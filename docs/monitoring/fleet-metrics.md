# Fleet metrics contract

`tor-relay-setup fleet serve` exposes these series on `/metrics`, and
`fleet status --format prometheus` prints the same set once. The Grafana
dashboards in `docs/monitoring/` are built against exactly these names; change
both together.

All names start with `tor_relay_fleet_`. Gauges unless marked *counter*.

## Fleet totals (no labels)

| Name | Meaning |
| --- | --- |
| `relays` | relays in the inventory (plus relays found on hosts but not listed) |
| `relays_running` | relays whose service is active |
| `hosts`, `hosts_up`, `hosts_unreachable`, `hosts_without_probe` | servers in the inventory and their probe state |
| `attention` | number of "Needs attention" findings |
| `consensus_weight`, `consensus_weight_fraction` | summed over relays Tor Metrics lists |
| `guard_probability`, `middle_probability`, `exit_probability` | summed |
| `advertised_bandwidth_bytes`, `observed_bandwidth_bytes` | summed, bytes/s |
| `traffic_bytes_total{direction="read"\|"written"}` | *counter*, summed over relays with a MetricsPort (always present, also in privacy mode); it never goes backwards: after the first probe round it grows by each relay's increase, so relay restarts and unreachable hosts do not look like counter resets |
| `or_connections` | summed open OR connections |
| `probe_duration_seconds` | duration of the last full probe round |
| `last_probe_timestamp_seconds` | end of the last probe round |
| `directory_last_update_timestamp_seconds` | last successful Tor Metrics (Onionoo) refresh |

## Per host — labels `host`

| Name | Meaning |
| --- | --- |
| `host_up{host,state}` | 1 for the host's current state: `ok`, `unreachable`, `no_probe` (tool missing or too old); the other two states are 0 |
| `host_probe_duration_seconds{host}` | last probe's duration |
| `host_last_success_timestamp_seconds{host}` | last successful probe |
| `host_tool_info{host,version}` | 1; the tor-relay-setup version on the host |

## Per relay — labels `host`, `tor_instance`, `nickname`, `fingerprint`, `role`

`role` is `guard` (has the Guard flag), `exit` (Exit flag), `bridge`, or
`middle`. A relay with both flags is an `exit`; until Tor Metrics lists a
relay, its configuration decides (`exit` or `middle`). For bridges
`fingerprint` is the **hashed** fingerprint.

| Name | Extra labels | Meaning |
| --- | --- | --- |
| `relay_info` | `version`, `country`, `as`, `as_name`, `transport` | 1. `country` is the lower-case ISO code from Onionoo; `transport` is `obfs4`/`webtunnel` for bridges, empty otherwise |
| `relay_service_active` | | 1 when the tor unit is active |
| `relay_listener` | `family` (`ipv4`/`ipv6`) | 1 when the ORPort listens |
| `relay_reachable` | `family` | 1 when the ORPort is reachable (tor's self-test, or for IPv4 running in the consensus: tor self-tests only at startup), 0 when the self-test failed, absent when unknown |
| `relay_warnings` | | number of status warnings |
| `relay_published` | | 1 when Tor Metrics lists the relay |
| `relay_running` | | 1 when Tor Metrics reports it running |
| `relay_flag` | `flag` | 1 per flag the relay holds (Authority, BadExit, Exit, Fast, Guard, HSDir, MiddleOnly, Running, Stable, StaleDesc, V2Dir, Valid) |
| `relay_consensus_weight`, `relay_consensus_weight_fraction` | | from Tor Metrics |
| `relay_guard_probability`, `relay_middle_probability`, `relay_exit_probability` | | from Tor Metrics |
| `relay_advertised_bandwidth_bytes`, `relay_observed_bandwidth_bytes` | | bytes/s, from Tor Metrics |
| `relay_first_seen_timestamp_seconds`, `relay_last_restarted_timestamp_seconds` | | from Tor Metrics |
| `relay_traffic_bytes_total` | `direction` | *counter*, MetricsPort (omitted in privacy mode) |
| `relay_or_connections` | | open OR connections (omitted in privacy mode) |
| `relay_onionskins_total` | `type`, `action` (`processed`/`dropped`) | *counter* |
| `relay_oom_bytes_total` | `subsys` | *counter* |
| `relay_tcp_exhaustion_total` | | *counter* |
| `relay_rate_limit_reached_total` | `side` | *counter* |
| `relay_sockets_open`, `relay_sockets_limit` | | |
| `relay_overloaded` | | 1 when Relay Search marks the relay overloaded |
| `relay_overload_general_timestamp_seconds` | | Onionoo's overload_general_timestamp, when set |
| `relay_accounting_max_bytes`, `relay_accounting_used_bytes`, `relay_accounting_projected_bytes`, `relay_accounting_period_end_timestamp_seconds` | | only with AccountingMax |
| `relay_signing_cert_expiry_timestamp_seconds` | | ed25519 signing certificate expiry, when known |
| `relay_master_key_offline` | | 1 when tor cannot renew the signing certificate itself (offline master key); tor renews the others a day before expiry |
| `relay_family_ids`, `relay_family_keys_missing` | | |
| `relay_family_consistent` | | 1 when the relay's FamilyId set matches the fleet majority |
| `relay_bridge_transport_listening` | `transport` | bridges only |

Bridge lines are never exported. Series whose value is unknown are left out
rather than written as 0.
