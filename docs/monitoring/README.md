# Monitoring a relay

There are three supported ways to watch relays set up with tor-relay-setup. Use one or several:

| | What you get | What you need |
| --- | --- | --- |
| [a. Textfile collector](#a-node_exporter-textfile-collector) | Health, Tor Metrics, overload and accounting gauges from `tor-relay-setup status --format prometheus` | node_exporter on the relay, a Prometheus |
| [b. Tor's MetricsPort](#b-scraping-tors-metricsport-safely) | Tor's own counters: traffic, connections, circuits, overload, DoS defences | a Prometheus that can reach the MetricsPort privately |
| [c. Alerts](#c-alerts-with-tor-relay-setup-alert) | Push, chat or mail messages when something breaks, without any monitoring stack | `tor-relay-setup alert` and a systemd timer |

Files in this directory:

- [`prometheus-rules.yml`](prometheus-rules.yml): Prometheus alerting rules for paths a and b
- [`grafana-dashboard.json`](grafana-dashboard.json): Grafana dashboard (import it and pick your Prometheus data source)
- [`alerts.toml`](alerts.toml): example configuration for `tor-relay-setup alert`

## a. node_exporter textfile collector

`tor-relay-setup status --format prometheus` prints Prometheus text format with the `tor_relay_setup_` prefix. node_exporter's textfile collector publishes it next to the host metrics. Each run reads torrc, systemd, the journal, tor's key directory and state file, and asks Tor Metrics about the relay. When torrc has a MetricsPort it also reads tor's load counters, and with AccountingMax it reads the accounting budget.

Install node_exporter (Debian and Ubuntu read textfiles from `/var/lib/prometheus/node-exporter`):

```bash
sudo apt install prometheus-node-exporter
```

Then add a oneshot service and timer. `status` needs root, because tor's data directory is private to debian-tor. It writes to a temporary file first, so node_exporter never reads half a file:

```ini
# /etc/systemd/system/tor-relay-setup-textfile.service
[Unit]
Description=tor-relay-setup metrics for the node_exporter textfile collector
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'umask 022; f=/var/lib/prometheus/node-exporter/tor_relay.prom; /usr/local/bin/tor-relay-setup status --format prometheus > "$f.tmp" && mv "$f.tmp" "$f"'
TimeoutStartSec=2min
Nice=10
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

```ini
# /etc/systemd/system/tor-relay-setup-textfile.timer
[Unit]
Description=Refresh tor-relay-setup metrics every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tor-relay-setup-textfile.timer
cat /var/lib/prometheus/node-exporter/tor_relay.prom
```

`status --format prometheus` always exits 0. Problems show up in the gauges (`tor_relay_setup_warnings` counts them), so the file is always replaced. Tor Metrics data changes about once an hour, and 5 minutes is enough for everything else. If you installed the binary from the .deb package, its path is `/usr/bin/tor-relay-setup`.

node_exporter listens on port 9100 on every address. Do not expose it to the internet. Scrape it over WireGuard, an SSH tunnel (see below), or from Prometheus on the same host, and block 9100 in the firewall otherwise. Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: node
    static_configs:
      # Name the host with Prometheus's instance label, and use the same name in the
      # MetricsPort job below. tor-relay-setup labels its own series tor_instance
      # ("default", or the Debian tor instance name) to tell relays on one host apart.
      - targets: ["10.8.0.11:9100"]  # the relay's WireGuard address
        labels:
          instance: relay-fra-1
```

### What the textfile contains

Health gauges, all prefixed `tor_relay_setup_`:

- `up` and `info{version,nickname,fingerprint}`: always 1.
- `relay_configured`, `tor_installed`, `tor_supported` and `service_active`: 0 or 1.
- `listener{family}` and `reachable{family}`: 0 or 1 per address family. `reachability_failed` is 1 when tor's self-test failed.
- `family_ids`, `family_keys_missing` and `legacy_myfamily_fingerprints`: counts.
- `warnings`: the number of problems `status` lists.
- From Tor Metrics, once it knows the relay: `directory_published`, `directory_running`, `consensus_weight` and `advertised_bandwidth_bytes`.

Overload and accounting series (each also carries `tor_instance`):

| Metric | Type | Meaning |
| --- | --- | --- |
| `tor_relay_setup_metricsport_up` | gauge | 1 when tor's MetricsPort answered (only when torrc has a MetricsPort) |
| `tor_relay_setup_overload_onionskins_processed_total{type}` | counter | onionskins tor processed, by handshake type (tap, fast, ntor, ntor_v3) |
| `tor_relay_setup_overload_onionskins_dropped_total{type}` | counter | onionskins tor dropped because its CPU workers were busy |
| `tor_relay_setup_overload_oom_bytes_total{subsys}` | counter | bytes the out-of-memory handler freed (cell, dns, geoip, hsdir) |
| `tor_relay_setup_overload_tcp_exhaustion_total` | counter | connections that failed because no local TCP port was free |
| `tor_relay_setup_overload_rate_limit_reached_total{side}` | counter | times the global BandwidthRate bucket ran empty (read, write) |
| `tor_relay_setup_overload_sockets_open`, `…_sockets_limit` | gauge | open sockets and tor's socket limit |
| `tor_relay_setup_overload_signal{signal,line}` | gauge | 1 when the signal fired since the previous run; `line` is the descriptor line it feeds |
| `tor_relay_setup_overload_general` | gauge | 1 when tor would publish `overload-general` for that window |
| `tor_relay_setup_directory_overloaded` | gauge | 1 while Relay Search shows the relay as overloaded (72 h after the last event) |
| `tor_relay_setup_directory_overload_general_timestamp_seconds` | gauge | hour of the last `overload-general` event, from Tor Metrics |
| `tor_relay_setup_accounting_max_bytes{rule}`, `…_used_bytes{rule}` | gauge | AccountingMax and the bytes counted against it this period |
| `tor_relay_setup_accounting_projected_bytes{rule}` | gauge | bytes expected by the end of the period at the pace so far |
| `tor_relay_setup_accounting_period_start_timestamp_seconds`, `…_period_end_…` | gauge | the current accounting period |
| `tor_relay_setup_accounting_exhaustion_timestamp_seconds` | gauge | when AccountingMax runs out at the current pace, if before the period ends; else 0 |
| `tor_relay_setup_accounting_hibernating` | gauge | 1 when AccountingMax is used up and tor hibernates |

The counters mirror tor's MetricsPort, so `increase()` works on them without scraping the MetricsPort.

## b. Scraping tor's MetricsPort safely

Tor's MetricsPort serves detailed per-relay statistics. The Tor Project warns that exposing it publicly is dangerous for Tor's users, so never open it to the internet. tor-relay-setup binds it to loopback only, with a policy that admits only loopback:

```text
MetricsPort 127.0.0.1:9035
MetricsPortPolicy accept 127.0.0.1
```

Pick one way to reach it.

**Prometheus on the relay itself.** Scrape the loopback address:

```yaml
scrape_configs:
  - job_name: tor-metricsport
    static_configs:
      - targets: ["127.0.0.1:9035"]
        labels:
          instance: relay-fra-1
          tor_instance: default  # one target per tor instance, each with its MetricsPort
```

**An SSH tunnel from the Prometheus host.** Keep the MetricsPort on loopback, and run a tunnel as an unprivileged user with a dedicated key. On the relay, restrict that key in `authorized_keys` with `restrict,port-forwarding,permitopen="127.0.0.1:9035"`. On the Prometheus host:

```ini
# /etc/systemd/system/tor-metrics-tunnel@.service  (instance = relay host name)
[Unit]
Description=SSH tunnel to the tor MetricsPort on %i
After=network-online.target
Wants=network-online.target

[Service]
User=prometheus
ExecStart=/usr/bin/ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -i /var/lib/prometheus/.ssh/tor-metrics -L 127.0.0.1:19035:127.0.0.1:9035 tunnel@%i
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```yaml
scrape_configs:
  - job_name: tor-metricsport
    static_configs:
      - targets: ["127.0.0.1:19035"]  # one local port per relay
        labels:
          instance: relay-fra-1
          tor_instance: default
```

**WireGuard.** Bind the MetricsPort to the relay's WireGuard address and admit only the Prometheus host:

```text
MetricsPort 10.8.0.11:9035
MetricsPortPolicy accept 10.8.0.1
```

Allow TCP 9035 only on the WireGuard interface (`sudo ufw allow in on wg0 to any port 9035 proto tcp`). The relay's public addresses must not accept it. Note that `tor-relay-setup apply` with `metrics_port = true` writes the loopback block again. Re-apply your edit afterwards, or keep `metrics_port = false` and maintain the lines yourself.

Useful MetricsPort series (names verified against tor 0.4.9.13):

| Series | Meaning |
| --- | --- |
| `tor_relay_traffic_bytes{direction="read"\|"written"}` | relay traffic; graph `rate(...[5m])` |
| `tor_relay_connections{type="OR",direction,state="opened",family}` | open connections to other relays and clients |
| `tor_relay_circuits_total{state="opened"}` | open circuits (a gauge, despite the name) |
| `tor_relay_load_onionskins_total{type,action="processed"\|"dropped"}` | circuit handshakes; ntor/ntor_v3 drops drive `overload-general` |
| `tor_relay_load_oom_bytes_total{subsys}` | bytes freed by the OOM handler (MaxMemInQueues reached) |
| `tor_relay_load_tcp_exhaustion_total` | out of local TCP ports |
| `tor_relay_load_global_rate_limit_reached_total{side}` | global BandwidthRate bucket empty |
| `tor_relay_load_socket_total{state="opened"}` and unlabelled `tor_relay_load_socket_total` | open sockets and tor's limit |
| `tor_relay_flag{type}` | the relay's flags in the consensus tor last downloaded |
| `tor_relay_dos_total{type}` | DoS defence actions |

Tor 0.4.9 exposes no accounting series on the MetricsPort. tor-relay-setup reads the accounting counters from tor's state file instead (`/var/lib/tor/state`, rewritten about once a minute).

## c. Alerts with `tor-relay-setup alert`

The alert command needs no monitoring stack. A systemd timer runs `tor-relay-setup alert run` every 5 minutes. It notifies you when a problem appears, reminds you every 24 hours while it lasts, and tells you when it resolves. A timer that runs every few minutes therefore never spams you.

```bash
sudo install -m 0600 docs/monitoring/alerts.toml /etc/tor-relay-setup/alerts.toml
sudoedit /etc/tor-relay-setup/alerts.toml        # set your ntfy topic, webhook, mail address …
sudo tor-relay-setup alert test                   # one test message to every notifier
sudo tor-relay-setup alert run --dry-run          # what would be sent now; changes nothing
sudo tor-relay-setup alert install                # timer every 5 min (--every 15m to change)
systemctl list-timers tor-relay-setup-alert.timer
journalctl -u tor-relay-setup-alert               # every run's output
sudo tor-relay-setup alert uninstall              # stop and remove the timer
```

`alert install --dry-run` prints both unit files and the systemctl commands without changing anything. Exit codes: 0 success, 1 the relay could not be checked or a notifier failed, 2 usage error.

### What is checked

| Alert | Severity | When |
| --- | --- | --- |
| `service-inactive` | critical | the tor unit is not active |
| `orport-not-listening` | critical | tor runs but nothing listens on the ORPort |
| `orport-unreachable` | critical | tor's self-test could not confirm the ORPort is reachable from outside |
| `tor-missing`, `tor-unsupported` | critical | tor does not run, or is older than the network accepts |
| `family-key-missing` | warning | a FamilyId in torrc has no secret family key installed |
| `directory-not-running` | critical | Tor Metrics does not see the relay running |
| `directory-missing` | critical | Tor Metrics listed the relay before but no longer does (it dropped out of the consensus) |
| `flag-lost-<Flag>` | warning, once | the relay lost a watched flag (Guard, Stable, Fast, HSDir) since the last run |
| `directory-overloaded` | warning | Relay Search shows the relay as overloaded (72 h after tor's last `overload-general`) |
| `overload-<signal>` | warning or info | tor's load counters show overload since the last run (needs a MetricsPort; see below) |
| `accounting-high` | warning | at least `accounting_threshold` % (default 90) of AccountingMax is used |
| `accounting-runs-out` | warning | AccountingMax runs out before the period ends at the pace so far |
| `accounting-exhausted` | critical | AccountingMax is used up and tor hibernates |
| `metricsport-down` | info | tor runs but its MetricsPort does not answer |
| `tor-update` | info | apt has a newer tor package (`check_updates = true`) |

Alerts below `min_severity` (default `warning`) are tracked but not sent. When Tor Metrics or the MetricsPort cannot be reached, alerts that depend on them stay as they were. A network hiccup never sends a "resolved" message.

The state lives in `/var/lib/tor-relay-setup/alert-state.json` (mode 0600). It holds the open problems, the last MetricsPort sample (the baseline for the overload deltas), the flags the relay held, and recent overload events. Deleting it only costs one run without a baseline.

### Notifiers

Configure any number of each in `/etc/tor-relay-setup/alerts.toml` (see [alerts.toml](alerts.toml)). Every notifier gets every message. Unknown keys are rejected. The file may hold tokens, so keep it mode 0600; the command warns otherwise. Errors and logs show a notifier's kind and host name, never a URL path, token or command argument.

- **ntfy** (`[[ntfy]] url, token, tags`): POSTs the text to the topic. `Title` is the summary, `Priority` is 5 for critical, 4 for warning and 3 otherwise, and `Tags` carries an emoji tag plus `tor` and your tags. `token` is sent as `Authorization: Bearer`.
- **webhook** (`[[webhook]] url, format, headers`): POSTs JSON with a 10 s timeout. The default `format = "json"` sends:

  ```json
  {
    "relay": "MyRelay", "nickname": "MyRelay", "fingerprint": "0123…4567", "host": "relay-fra-1",
    "time": "2026-10-02T12:00:00Z",
    "alerts": [
      {"id": "service-inactive", "severity": "critical", "title": "tor@default is not running",
       "body": "The tor service is not active …", "status": "firing", "since": "2026-10-02T12:00:00Z"}
    ]
  }
  ```

  `status` is `firing`, `reminder`, `resolved` or `test`. `format = "slack"` sends `{"text": "…"}`, which Slack, Mattermost, Rocket.Chat, Discord (its `/slack` webhook URL) and Matrix hookshot accept.
- **email** (`[[email]] to, from, sendmail`): pipes a plain-text mail to `sendmail -t -i` of the local mail transfer agent (postfix, exim, msmtp-mta, …).
- **command** (`[[command]] argv, timeout`): runs a program (absolute path) with the same JSON as the webhook on standard input. The default timeout is 30 s.

### Overload signals

Relay Search marks a relay as overloaded from the `overload-general` line in its server descriptor. Tor also publishes `overload-ratelimits` and `overload-fd-exhausted` in its extra-info descriptor. The tables below follow tor 0.4.9 (`src/feature/stats/rephist.c`, `src/core/mainloop/connection.c`), the [directory specification](https://spec.torproject.org/dir-spec/server-descriptor-format.html), [proposal 328](https://spec.torproject.org/proposals/328-relay-overload-report.html) and the [Tor support page on overloaded relays](https://support.torproject.org/relays/performance/overloaded/).

| Signal | Descriptor line (kept) | Tor publishes it when | tor-relay-setup alerts when | Tor's remedy |
| --- | --- | --- | --- | --- |
| `onionskins_dropped` | overload-general (72 h) | at least 1% of ntor/ntor_v3 handshakes were dropped over a 6 h period with at least 1000 requests | any ntor drop since the last run: warning at tor's threshold, info below it | more CPU: let tor use every core, stop other CPU load, or lower RelayBandwidthRate |
| `oom` | overload-general (72 h) | the OOM handler ran because queues reached MaxMemInQueues | any bytes freed (warning) | more RAM (2 GB minimum, 4 GB advised); raise MaxMemInQueues only if RAM is free |
| `tcp_exhaustion` | overload-general (72 h) | a connection failed for lack of local ports | any event (warning) | `sysctl -w net.ipv4.ip_local_port_range="15000 64000"`, persisted in `/etc/sysctl.d/` |
| `sockets_exhausted` | overload-fd-exhausted (72 h) | opening a socket failed because tor ran out of file descriptors | at least 90% of tor's socket limit is open (warning) | higher `LimitNOFILE` for the tor unit (`systemctl edit tor@default`) |
| `rate_limited` | overload-ratelimits (24 h) | the global BandwidthRate/BandwidthBurst bucket ran empty (RelayBandwidthRate has its own bucket and does not count) | any event (info) | expected with a deliberate limit; raise it if the line has headroom |

An overload alert stays open for `overload_hold` (default 6 h) after its signal last fired. During that time its severity only goes up, so a flapping signal does not send a message every run. The first run after installing has no baseline sample, so only the socket gauge is checked then.

### Accounting

With `AccountingMax` in torrc, tor stops relaying ("hibernates") once the budget for the period is used up. The counters come from tor's state file. The limit, `AccountingRule` (max, sum, in or out) and `AccountingStart` (day, week or month; local time) come from torrc. The projection assumes the average pace since the period began continues. Tor itself stops accepting new connections a little before the limit (at 95% used, or with less than 500 MB left).

### The systemd units

`alert install` writes `/etc/systemd/system/tor-relay-setup-alert.service` (a root oneshot) and `.timer`. Each hardening line in the service carries a comment explaining it. The job keeps write access to `/var` (its own state, and an MTA's mail spool for sendmail) and full root capabilities, because tor's key directory belongs to debian-tor and a sendmail may switch users. It loses write access to `/usr`, `/boot` and `/etc`, physical devices, kernel and cgroup tunables, new namespaces, and every socket family except unix, IPv4 and IPv6.

## Prometheus rules and Grafana

Load [`prometheus-rules.yml`](prometheus-rules.yml) in Prometheus:

```yaml
rule_files:
  - /etc/prometheus/rules/tor-relay-setup.yml
```

The `tor-relay-setup` group covers the relay being down or unreachable, dropping out of the consensus, a missing family key, an unsupported tor, a consensus weight drop of more than half, stale textfile data, Relay Search overload, and accounting. The `tor-metricsport` group covers overload from tor's own counters and needs the `tor-metricsport` job. Check the file with `promtool check rules prometheus-rules.yml`.

Import [`grafana-dashboard.json`](grafana-dashboard.json) in Grafana (Dashboards → New → Import) and choose your Prometheus data source. The `nickname`, `instance` (host) and `tor_instance` variables filter every panel. Give MetricsPort targets a `tor_instance` label, as in the scrape configs above, so the MetricsPort panels follow the `tor_instance` filter too. The traffic, connection, socket and per-hour overload panels need the MetricsPort job; everything else comes from the textfile.
