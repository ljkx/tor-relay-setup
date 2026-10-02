# Monitoring relays

There are four supported ways to watch relays set up with tor-relay-setup. Use one or several:

| | What you get | What you need |
| --- | --- | --- |
| [Fleet dashboard](#fleet-dashboard-on-a-management-server) (recommended for several relays) | One Grafana for all relays behind HTTPS (or, in [local mode](#local-mode-on-a-relay-through-an-ssh-tunnel), on a non-exit relay through an SSH tunnel): health, traffic, consensus weight, flags, geography, overload, accounting, keys, alerts | A small Debian or Ubuntu server (or one of your non-exit relays) and `tor-relay-setup monitor install` |
| [a. Textfile collector](#a-node_exporter-textfile-collector) | Health, Tor Metrics, overload and accounting gauges from `tor-relay-setup status --format prometheus` | node_exporter on the relay, a Prometheus |
| [b. Tor's MetricsPort](#b-scraping-tors-metricsport-safely) | Tor's own counters: traffic, connections, circuits, overload, DoS defences | a Prometheus that can reach the MetricsPort privately |
| [c. Alerts](#c-alerts-with-tor-relay-setup-alert) | Push, chat or mail messages when something breaks, without any monitoring stack | `tor-relay-setup alert` and a systemd timer |

Files in this directory:

- [`fleet-metrics.md`](fleet-metrics.md): the metrics `tor-relay-setup fleet serve` exports (the contract the fleet dashboards and rules are built on)
- [`grafana/`](grafana): the fleet dashboards, *Tor fleet — overview* and *Tor fleet — relay detail* (generated; see [Development](#development))
- [`prometheus-fleet-rules.yml`](prometheus-fleet-rules.yml): Prometheus alerting rules for the fleet metrics
- [`prometheus-rules.yml`](prometheus-rules.yml): Prometheus alerting rules for paths a and b
- [`grafana-dashboard.json`](grafana-dashboard.json): single-relay Grafana dashboard for paths a and b (import it and pick your Prometheus data source)
- [`alerts.toml`](alerts.toml): example configuration for `tor-relay-setup alert`
- [`dev/`](dev): the local test stack, a synthetic fleet exporter and the panel checker

## Fleet dashboard on a management server

```text
                 HTTPS 443 (Let's Encrypt)
  operator ───────────────► Caddy ──► Grafana 127.0.0.1:3000 ──► Prometheus 127.0.0.1:9090
  browser                     │                                     │ scrape every 30 s,
                              └─► /fleet/ ─► fleet serve ◄──────────┘ bearer token
                                             127.0.0.1:9850
                                                  │ ssh as tor-relay-probe, every 30 s
                                                  ▼ (forced command, read-only)
            relay 1 … relay N:  sudo -n tor-relay-setup fleet-probe
```

Everything runs on one management server, which should not be a relay itself (if you don't want a separate server or any new public service, see [local mode](#local-mode-on-a-relay-through-an-ssh-tunnel)). Relays expose nothing new: no exporter, no open port, no MetricsPort over the network. `tor-relay-setup fleet serve` logs in to every relay over SSH with its own key and runs one read-only command there, `tor-relay-setup fleet-probe`. It combines the answers with Tor Metrics data and publishes the [fleet metrics](fleet-metrics.md) on loopback. Prometheus keeps the history, and Grafana shows it. Caddy is the only service reachable from the internet. It terminates HTTPS with an automatic Let's Encrypt certificate and serves Grafana at `/` and the fleet web UI at `/fleet/`.

<!-- Screenshot placeholder: docs/monitoring/screenshots/fleet-overview.png (Tor fleet — overview, top) -->
<!-- Screenshot placeholder: docs/monitoring/screenshots/fleet-overview-details.png (expanded detail rows) -->
<!-- Screenshot placeholder: docs/monitoring/screenshots/fleet-relay.png (Tor fleet — relay detail) -->

### Install

Supported management servers: Debian 12 (bookworm) and 13 (trixie), Ubuntu 22.04 (jammy), 24.04 (noble) and 26.04 (resolute), amd64 or arm64, with 1 GiB of RAM and a few GB of disk. You also need a DNS name (an A and/or AAAA record) that points at the server.

1. Install tor-relay-setup on the management server (`install.sh`, into `/usr/local/bin`). Copy your fleet inventory there as `/etc/tor-relay-setup/fleet.toml`, together with the `relay.toml` it names. Make both readable for the `tor-relay-monitor` user. Write the inventory addresses without `user@` (see step 4).
2. Review, then install:

   ```bash
   sudo tor-relay-setup monitor install --domain grafana.example.org --email ops@example.org --dry-run
   sudo tor-relay-setup monitor install --domain grafana.example.org --email ops@example.org
   ```

   The review lists every change, and `--dry-run` shows every command and file. `--yes` skips the question. Running it again is safe: it changes only what differs, keeps the password, token and your `serve.toml` users, and restarts only services whose configuration changed. At the end it prints the Grafana URL, the administrator login, where the password is, and the password itself (only when it was just generated).
3. On **every relay**, authorize the monitoring key that `monitor install` printed. Use the management server's public address for `--from`:

   ```bash
   sudo tor-relay-setup fleet authorize --key 'ssh-ed25519 AAAA… tor-relay-monitor@mgmt' --from 203.0.113.5
   ```

   It prints the relay's SSH host key as a `known_hosts` line.
4. On the management server, add each relay's host key line to `/var/lib/tor-relay-monitor/.ssh/known_hosts`. Use the name or address exactly as the inventory writes it. Host keys are never accepted blindly (`StrictHostKeyChecking yes`). Then check one relay end to end:

   ```bash
   sudo -u tor-relay-monitor ssh relay1.example.org | head -c 300   # prints the probe's JSON
   sudo systemctl start tor-relay-setup-fleet                        # if it waited for the inventory
   sudo tor-relay-setup monitor status
   ```

5. Open `https://grafana.example.org/` and sign in as `tor-admin`. The *Tor fleet — overview* dashboard is the home page. Add logins for the fleet web UI with `sudo tor-relay-setup fleet serve passwd NAME`.

`sudo tor-relay-setup monitor status` shows the four services, whether Prometheus scrapes fleet serve, the fleet totals, and the key and command for new relays. It exits 1 when something is wrong. `sudo tor-relay-setup monitor uninstall` stops and disables the stack and keeps all data. `--purge` also removes the packages it installed, Grafana's database, the metrics history, the monitoring user and key, `serve.toml`, the password file and the apt sources it added. Firewall rules stay either way.

| Flag | Meaning |
| --- | --- |
| `--domain NAME` | DNS name of Grafana; Caddy gets the certificate for it |
| `--local` | [local mode](#local-mode-on-a-relay-through-an-ssh-tunnel): no Caddy, no open port, Grafana through an SSH tunnel; not combined with `--domain`, `--email` or `--fleet-path` |
| `--email ADDR` | ACME account address for certificate expiry notices (optional) |
| `--inventory FILE` | inventory fleet serve probes (default `/etc/tor-relay-setup/fleet.toml`) |
| `--fleet-path PATH` | publish the fleet web UI at `https://NAME/PATH/` (default `/fleet`); `off` keeps it on loopback |
| `--admin-user NAME` | Grafana administrator login (default `tor-admin`; `admin` is refused) |
| `--rotate-token` | new metrics token for fleet serve and Prometheus |

### Local mode (on a relay, through an SSH tunnel)

```text
  operator laptop                                   relay (non-exit)
  browser ─► localhost:3000 ══ SSH tunnel (port 22) ══► Grafana 127.0.0.1:3000 ─► Prometheus 127.0.0.1:9090
                                                        fleet serve 127.0.0.1:9850 ─ssh─► other relays
```

`monitor install --local` sets up the same stack without any public service. Use it when you don't want to rent a separate management server and don't want to open anything new: Grafana, Prometheus and fleet serve listen on 127.0.0.1 only, Caddy is not installed (no Caddy repository on Ubuntu 22.04 either), and the firewall is not touched, so no port is opened and none is added to an existing firewall. You reach Grafana through an SSH tunnel, using the SSH access you already have.

```bash
sudo tor-relay-setup monitor install --local --dry-run
sudo tor-relay-setup monitor install --local
```

Then, on your own computer, open the tunnel and leave it running:

```bash
ssh -N -L 3000:127.0.0.1:3000 USER@RELAY            # add -p PORT for another SSH port
ssh -N -L 3000:127.0.0.1:3000 -L 9850:127.0.0.1:9850 USER@RELAY   # with the fleet web UI too
```

and open `http://localhost:3000` (and `http://localhost:9850/` for the fleet UI). `monitor install` and `monitor status` print this command with your login (`SUDO_USER`) and the relay's public address filled in when they can tell (the address you are connected to, the torrc `Address`, or a public interface address), otherwise with placeholders. In **Termius**, open the host, then *Port Forwarding → New → Local*: local port `3000`, destination host `127.0.0.1`, destination port `3000`. Start the rule, then open `http://localhost:3000` in your browser. On Windows, `ssh` (OpenSSH) works the same in PowerShell; in PuTTY, use *Connection → SSH → Tunnels*, source port `3000`, destination `127.0.0.1:3000`.

What differs from public mode:

| | Local mode |
| --- | --- |
| Caddy, Let's Encrypt | not installed; `--domain`, `--email` and `--fleet-path` (other than `off`) are refused with `--local` |
| Firewall | unchanged: no TCP 80/443, and no firewall is installed or enabled (on a running relay, a firewall that allows only SSH would cut off the ORPort) |
| grafana.ini | `domain = localhost`, `enforce_domain = false` (through the tunnel the browser sends `Host: localhost:3000`), `root_url = http://localhost:3000/`, `cookie_secure = false` and `strict_transport_security = false` (the browser talks plain HTTP to its end of the tunnel; SSH encrypts the rest). Everything else is hardened exactly as in public mode, including `cookie_samesite = strict`, no anonymous access, no sign-up and no basic auth |
| serve.toml | `listen = "127.0.0.1:9850"`, `base_path = ""` (the root), `trusted_proxies = []`: no proxy, so no forwarded header is believed |
| Preflight | no DNS check; refuses to install on an **exit** relay; notes that Grafana and Prometheus share a non-exit relay, and warns when the RAM looks short for the relays plus the stack |

**Why not on an exit.** Exits attract abuse complaints, port scans and denial-of-service attacks, and their addresses are on public exit lists. Monitoring should keep working when a relay is under attack and should not add to what an exit has to defend, so `--local` refuses when any relay on the server is an exit (`ExitRelay 1`, or an `ExitPolicy` that accepts anything, or `ReducedExitPolicy 1`). Use a non-exit relay, or a separate server with `--domain`.

**Security reasoning.** Nothing new is reachable from the internet: the only way in is SSH, which the relay already exposes and which you already protect (keys only, ideally). The tunnel encrypts and authenticates the connection, so plain HTTP between your browser and its end of the tunnel is fine, and Grafana's login form is a second barrier behind SSH. The price is that Grafana and Prometheus share the relay's memory and CPU (about 300 to 500 MiB together), and that whoever can log in to the relay over SSH can reach Grafana's login page.

**Switching modes.** The mode is stored in `/var/lib/tor-relay-setup/monitor.json`, so running `monitor install` again without `--local` or `--domain` keeps local mode. `--domain NAME` switches to public mode (Caddy, TCP 80/443, HTTPS). `--local` on a public install switches to local mode. It stops and disables Caddy, moves the Caddyfile it wrote to a `.bak.*` copy, and removes the ufw or nftables rules for TCP 80 and 443 that carry its comments, unless another service still listens on the port. A Caddyfile it did not write is left alone, and so are firewalld rules, which do not record who added them; the run names what you should close yourself. `monitor status` shows the tunnel command and checks fleet serve, Prometheus and Grafana (no Caddy). `monitor uninstall` works the same in both modes, and in local mode it does not touch Caddy.

### What monitor install sets up

| Component | Source | Configuration |
| --- | --- | --- |
| Prometheus | the distribution (bookworm 2.42, trixie 2.53, jammy 2.31, noble 2.45, resolute 2.53) | `/etc/default/prometheus`: loopback only, 400 days or 20 GB of history. It is written **before** the package is installed, so Prometheus never listens publicly, not even on its first start. `/etc/prometheus/prometheus.yml` scrapes fleet serve every 30 s with `authorization: credentials_file: /etc/prometheus/tor-relay-fleet.token` (0640 root:prometheus) and loads `/etc/prometheus/rules/tor-relay-fleet.yml`. promtool checks both before they replace the old files. Installed with `--no-install-recommends`, so no node_exporter appears on port 9100. |
| Grafana OSS | `https://apt.grafana.com stable main`, deb822 source `/etc/apt/sources.list.d/grafana.sources` with `Signed-By: /usr/share/keyrings/grafana-archive-keyring.gpg` | `/etc/grafana/grafana.ini` (below), data source `tor-prometheus`, folder *Tor relays*, both dashboards (read-only, from `/etc/grafana/dashboards/tor-relay-setup`) |
| Caddy | the distribution; on Ubuntu 22.04, which has no caddy package, Caddy's repository (`https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main`, `Signed-By: /usr/share/keyrings/caddy-stable-archive-keyring.gpg`) | `/etc/caddy/Caddyfile`: automatic HTTPS, HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, no `Server` header, HTTP/1.1 and HTTP/2 only (no UDP), `/fleet/metrics*` answered with 404. `caddy validate` checks it first. |
| fleet serve | this tool | `/etc/tor-relay-setup/serve.toml` (0600 tor-relay-monitor) and `tor-relay-setup-fleet.service`, running as `tor-relay-monitor` |
| Firewall | ufw (installed when no firewall manager exists), firewalld or nftables, as for relays | allow the existing SSH ports, TCP 80 and TCP 443; nothing else |

The apt signing keys are pinned by fingerprint and verified in Go before they are installed, the same way as the Tor Project key. The download must contain exactly one key with that fingerprint, and only that key is written to the keyring:

- Grafana: `B53AE77BADB630A683046005963FA27710458545` ("Grafana Labs <engineering@grafana.com>", rsa3072, created 2023-08-24, **expires 2027-08-22**). It is the key at `https://apt.grafana.com/gpg.key`, and it signs `dists/stable/InRelease`. `gpg-full.key` also holds the revoked 2017 key and the expired 2023-01 key, so it is not used. When Grafana Labs extends the expiry, run `monitor install` again to refresh the keyring.
- Caddy (Ubuntu 22.04 only): `65760C51EDEA2017CEA2CA15155B6D79CA56EA34` ("Caddy Web Server <contact@caddyserver.com>"). It signs with the subkey `2F5C3BE9886ACD2913299EFBABA1F9B8875A6661`.

`monitor install` refuses to continue when another apt source already points at the same repository, because apt rejects one repository with two different `Signed-By` keys. Remove the old `grafana.list` or `caddy-stable.list` first.

**grafana.ini** listens on 127.0.0.1:3000 with `root_url = https://DOMAIN/` and `enforce_domain`. Anonymous access, sign-up, org creation, HTTP basic auth on the API, snapshots, public dashboards, the plugin catalog and plugin auto-install, Gravatar, usage reporting, update checks, feedback links and the news feed are off. Cookies are `Secure` and `SameSite=Strict`. HSTS, the content security policy and `X-Content-Type-Options` are on, embedding is off, and the data source proxy may reach only the local Prometheus. The login hints are neutral. Grafana's `secret_key` is generated once and kept across runs. The administrator is renamed (`tor-admin`), and its 32-character password is generated once and stored in `/etc/tor-relay-setup/grafana-admin` (0600 root). `grafana cli … reset-admin-password --password-from-stdin` sets it as the `grafana` user, before Grafana's first start, so the server never runs with `admin`/`admin` and the password never appears on a command line.

**Alerting.** Prometheus evaluates [`prometheus-fleet-rules.yml`](prometheus-fleet-rules.yml): fleet serve down, stale probes or Tor Metrics data, unreachable hosts, hosts without fleet-probe, stopped relays, closed or unreachable ORPorts, relays not running in or dropped out of the consensus, lost Guard/Stable/Fast/HSDir flags, halved consensus weight, status warnings, tor and tool version drift, bridge transports down, Relay Search overload, dropped ntor handshakes, OOM, TCP port exhaustion, sockets near the limit, AccountingMax running out, signing certificates expiring within 7 days or 1 day, missing family keys, and relays outside the fleet's family. Grafana lists them under *Alerting → Alert rules*, and the overview's *Firing alerts* table shows what fires now. No Alertmanager and no Grafana contact point are installed. Sending notifications needs your own secrets (an ntfy topic, SMTP or a chat webhook), and the relays already notify on their own with `tor-relay-setup alert` without depending on the management server. To get fleet-level notifications too, add `prometheus-alertmanager` and point Prometheus at it, or create a Grafana contact point and alert rules on these series in the UI.

**Retention.** Prometheus keeps 400 days, so this year can be compared with the last one (yearly accounting, seasonal traffic, consensus weight trends), but never more than 20 GB. A fleet of 20 relays produces a few thousand series and needs well under 5 GB for 400 days at a 30 s interval, so the size limit only matters for large fleets or small disks.

### The fleet serve service

`tor-relay-setup-fleet.service` runs `tor-relay-setup fleet serve --config /etc/tor-relay-setup/serve.toml` as the system user `tor-relay-monitor`, whose home `/var/lib/tor-relay-monitor` holds the SSH key `.ssh/id_ed25519`, `.ssh/config` and `.ssh/known_hosts`. The SSH config logs in as `tor-relay-probe` with only that key, in batch mode, with strict host key checking and every forwarding disabled. Each line of the unit is commented. The service has no capabilities and cannot gain any (`NoNewPrivileges`, empty `CapabilityBoundingSet`). It sees the file system read-only except its cache directory (`ProtectSystem=strict`, `CacheDirectory=`). It gets private `/tmp` and devices, cannot see `/home` or other processes, cannot change kernel settings, clock or host name, and may use only unix, IPv4 and IPv6 sockets and the `@system-service` system calls. It keeps network access, because relays can be anywhere. `systemd-analyze security` rates it 1.5 ("OK").

monitor install keeps these `serve.toml` keys in sync: `listen = "127.0.0.1:9850"`, `base_path`, `inventory`, `metrics_auth = true`, `metrics_token_sha256` and `trusted_proxies = ["127.0.0.1", "::1"]`. Your `[[users]]`, `privacy`, `probe_interval` (30 s at first) and everything else are left as you set them.

### Relay side: the forced-command key

The SSH key is the security boundary between the monitoring server and the relays. `tor-relay-setup fleet authorize` sets it up so that whoever holds the key can run exactly one read-only command, and nothing else:

- A dedicated system user, `tor-relay-probe`. It has no password (`*`, so password logins are impossible; unlike `!`, `*` does not lock the account, which sshd would refuse even for keys when `UsePAM no`). Its shell is `/bin/sh`, because sshd runs forced commands through the user's shell. Its home `/var/lib/tor-relay-probe`, `~/.ssh` and `authorized_keys` belong to **root**, so the user cannot change them.
- `authorized_keys`: `restrict,command="sudo -n /usr/local/bin/tor-relay-setup fleet-probe",from="MONITOR_IP" ssh-ed25519 …`. `restrict` turns off port, agent and X11 forwarding, PTYs and `~/.ssh/rc`. `command=` replaces whatever the client asks to run, so `ssh relay 'rm -rf /'` still runs only the probe. `from=` (repeatable `--from`, IP addresses or CIDR ranges, never host names) limits where the key works. Only `ssh-ed25519` keys are accepted, and comments are sanitized.
- `/etc/sudoers.d/tor-relay-setup-probe` (0440, checked with `visudo -c` before it is installed): `tor-relay-probe ALL=(root) NOPASSWD: /usr/local/bin/tor-relay-setup fleet-probe`. A sudoers command with arguments matches only exactly those arguments, so no other subcommand or flag is allowed. `env_reset` drops the caller's environment, and `!requiretty` lets it run without a terminal.
- Before writing anything, authorize checks that the tor-relay-setup binary and every directory above it belong to root and are writable only by root. Otherwise anyone who could replace the binary could run anything as root through this rule. It also warns when sshd's `AllowUsers`/`AllowGroups`, `PubkeyAuthentication` or `AuthorizedKeysFile` would keep the key out.
- `fleet-probe` only reads: torrc, systemd state, the journal, key and family-key presence, tor's state file and the local MetricsPort. It prints one JSON document. Bridge lines and private keys are never part of it.

If the management server is compromised, the attacker can learn what the probe reports, but cannot change a relay. `sudo tor-relay-setup fleet authorize --remove` takes the access away again (sudoers rule, home and user). The manual equivalent of authorize is the `authorized_keys` line above plus the sudoers line, with the user created as described.

### Security notes

- **Exposed:** TCP 443 and 80 (80 only redirects to HTTPS and answers ACME challenges), plus your SSH port. Grafana, Prometheus and fleet serve listen on 127.0.0.1 only. The firewall allows nothing else, and Prometheus listens on loopback from its very first start.
- **Authentication:** Grafana needs its login form; there is no anonymous access, sign-up or basic auth. The fleet web UI has its own users (argon2id hashes in `serve.toml`, set with `fleet serve passwd`). `/metrics` needs the bearer token, and Caddy does not even forward `/fleet/metrics`.
- **Admin password:** keep a copy of `/etc/tor-relay-setup/grafana-admin` in your password manager. To replace it, delete the file and run `monitor install` again: it generates, sets and prints a new one. A password you change in Grafana's UI stays until you do that.
- **Metrics token rotation:** `sudo tor-relay-setup monitor install --domain NAME --rotate-token` writes a new token to Prometheus's credentials file and its SHA-256 to `serve.toml`, and restarts both. (`tor-relay-setup fleet serve token` changes only `serve.toml`; Prometheus would then need the new token in `/etc/prometheus/tor-relay-fleet.token` by hand.)
- **Privacy:** Tor's manual warns that the MetricsPort's statistics must not be exposed publicly, and fine-grained per-relay traffic and connection counts are exactly that kind of data. Keep the dashboards private: public dashboards and snapshots are disabled on purpose, so don't share panel links outside your team. Tor Metrics publishes relay bandwidth only aggregated and delayed, and the dashboards should not publish more than that. With `privacy = true` in `serve.toml`, fleet serve leaves per-relay traffic and OR connection series out of `/metrics` (fleet totals stay), and the per-relay traffic panels show "No data yet, or hidden by privacy mode". The geomap's base map tiles are loaded by your browser from CARTO (`*.cartocdn.com`, allowed by Grafana's content security policy). Remove that panel if your browser should make no third-party requests.
- **Updates:** Grafana and Caddy (jammy) come from their apt repositories, and Prometheus and Caddy from the distribution, so `unattended-upgrades` or `apt upgrade` updates them. The dashboards and rules are updated by running a newer `monitor install`.

### Development

The dashboards are generated from Go (`internal/dashgen`), so roughly 100 panels share one colour scheme (Tor purple `#7D4698`), units, thresholds and descriptions. Edit the generator, then run `go generate ./docs/monitoring`. `go test ./docs/monitoring` checks that the JSON matches the generator, that every panel has a description and a unique id and title, that only built-in panel types are used, and that every query uses only metric names from [`fleet-metrics.md`](fleet-metrics.md) (or Prometheus's `up`, `scrape_duration_seconds` and `ALERTS`). It also checks that every contract metric appears on a dashboard, and that every rule uses contract metrics and has a severity and summary. `promtool test rules docs/monitoring/dev/fleet-rules.test.yml` unit-tests some rules.

`dev/run-local-stack.sh` runs Prometheus and Grafana (official release tarballs, checksums pinned) on 127.0.0.1:9090 and :3000 with exactly the files `monitor install` writes (`dev/render`). Only paths, the URL, the HTTPS-only cookie and HSTS settings, and basic auth for the checker are overridden. It scrapes fleet serve on 127.0.0.1:9850:

```bash
docs/monitoring/dev/run-local-stack.sh fetch
make build && SERVE_BIN=bin/tor-relay-setup FLEET_ADDR=127.0.0.1:9850 docs/monitoring/dev/run-local-stack.sh start   # runs fleet serve --demo itself
# or, with a fleet serve --demo already listening on 9850 with its documented token:
printf trs_demo_metrics_token_not_secret > /tmp/demo-token && TOKEN_FILE=/tmp/demo-token docs/monitoring/dev/run-local-stack.sh start
# or the synthetic fleet with two days of history:
FAKE=1 BACKFILL_DAYS=2 docs/monitoring/dev/run-local-stack.sh start
docs/monitoring/dev/run-local-stack.sh check   # every panel query through Grafana's /api/ds/query
docs/monitoring/dev/run-local-stack.sh stop
```

Then open `http://127.0.0.1:3000/` and sign in as `tor-admin` with the password in `.local-stack/grafana-admin`. The daily bars ("Traffic per day") stay empty until the first full day (UTC) of data.

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
