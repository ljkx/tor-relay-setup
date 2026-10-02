# Operator guide

The day-two companion to `tor-relay-setup`: what to prepare, what to check after setup, how to run a family of relays, and how to fix the usual problems. Where this guide and the [Tor Project relay documentation](https://community.torproject.org/relay/) disagree, the Tor docs win.

## Before you start

Have these ready:

- A **nickname**: 1–19 letters or digits. Nicknames are not unique; your fingerprint is what identifies the relay.
- A working **contact email**. It is published, and Tor's [operator expectations](https://community.torproject.org/policies/relays/expectations-for-relay-operators/) require it to reach you.
- The **ORPort**: `9001` is common; `443` gets through more restrictive networks.
- Your provider's **monthly traffic quota** and how it is counted (in + out, outbound only, or per direction).
- Whether IPv6 really works on the server.
- Whether the provider has a **cloud firewall** in front of the VM. If so, open the ORPort there too.
- For exits only: written provider permission, a plan for abuse complaints, and ideally reverse DNS that says the server is a Tor exit.

Look around first. A dry run asks every question and shows the full plan without changing anything or needing root:

```bash
tor-relay-setup --dry-run
```

## Right after setup

The apply screen already checks the service, the listener, family warnings, and Tor's reachability self-test, which it keeps waiting for in the background. Afterwards:

```bash
sudo tor-relay-setup            # the console: health, Tor Metrics, live log
tor-relay-setup status          # one-shot summary; exit code 1 when something needs attention
journalctl -u tor@default -f    # the raw log
```

A healthy start logs `Self-testing indicates your ORPort <address>:<port> is reachable from the outside. Excellent.` If you configured IPv6, there is a second line for the IPv6 address.

## The first weeks

New relays ramp up slowly. That is expected ([lifecycle of a new relay](https://blog.torproject.org/lifecycle-of-a-new-relay/)):

- [Relay Search](https://metrics.torproject.org/rs.html) and the console's **Tor Metrics** card show the relay after about 3 hours.
- The bandwidth authorities measure it over the following days. Traffic grows as the measurements come in.
- The Guard flag needs about 8 days of stable uptime, and guard traffic then grows over several weeks.

Keep the relay online. Relays that disappear often, or hibernate early in the month, lose their weight.

## Relay families

Run more than one relay? They must be declared as one family, so clients never use two of them in the same circuit. Tor 0.4.9 families use a shared key:

1. **On your first relay**, choose *Create a new family key*, either in the wizard or from **console → Relay family (`f`) → Create**. The tool runs `tor --keygen-family`, installs the key in `/var/lib/tor/keys/` (mode `0600`, owner `debian-tor`), and adds `FamilyId <id>` to the torrc.
2. **Copy the key to each additional relay** over SSH. **Relay family → Share (`s`)** prints the commands, for example:

   ```bash
   scp /var/lib/tor/keys/relay-family.secret_family_key \
       /var/lib/tor/keys/relay-family.public_family_id root@relay-2:/root/
   ```

3. **On each additional relay**, choose *Import an existing family key* and give the path of the copied `.secret_family_key`. Delete the copies from `/root` afterwards.
4. **Check it**: the Relay family screen must show ✓ for every `FamilyId`. `tor-relay-setup status` warns about any `FamilyId` without its key. After a few hours, Relay Search should show the relays together.

**Rotating the key:** create the new key on one relay and keep the existing FamilyId lines when asked. Import the new key everywhere, wait a few days, then **Remove a FamilyId (`x`)** for the old one.

**CIISS proof:** if your ContactInfo has a `url:`, publish the family ID at `https://<your-domain>/.well-known/tor-relay/ed25519-family-id.txt` so tools can verify that the relays are yours. `tor-relay-setup proof --all` (or **console → ContactInfo proof (`c`)**) prints the exact file for every relay on the server. `proof --check` fetches the published copy and confirms it lists them. The file must be served over HTTPS, must not redirect to another domain, and must never contain the secret key; the check fails loudly if it does.

**MyFamily:** fingerprint lists are the pre-0.4.9 method, and Tor 0.4.8 is end-of-life, so current clients only use `FamilyId`. Once FamilyId is in place, **Relay family → Remove legacy MyFamily (`m`)** cleans up the old list.

## Bandwidth planning

- **Steady monthly budget** (recommended for VPS quotas) turns the quota into `RelayBandwidthRate`/`Burst`, calculated so the budget lasts a 31-day month. `AccountingMax` stays in place as a fuse. `10TB` is read as 10¹² bytes, the way providers bill it.
- **Manual rate** suits a server whose bandwidth you know and don't need to meter.
- **AccountingMax only** lets the relay run at full speed and then hibernate until the next period. Tor docs call this out as the less useful option.
- **Keep the current limits** appears when you reconfigure a relay whose torrc has hand-written limits. They are carried over exactly.
- If the relay still hibernates, raise the headroom or choose *in + out combined* in **console → Edit settings (`e`)**.

## Repeatable setups

The wizard's review screen saves your answers with `s`. You can also start from [`docs/examples/relay.toml`](examples/relay.toml):

```bash
tor-relay-setup apply --config relay.toml --dry-run    # every change, nothing touched
sudo tor-relay-setup apply --config relay.toml --yes   # unattended
```

Keep one file per relay in version control. The only values that should differ between relays are the nickname and, for family members, `family.mode = "import"` with the key path.

## Several relays on one server

A large server can run several relays: the directory authorities accept up to [eight relays per IPv4 address](https://community.torproject.org/relay/relays-requirements/). Each extra relay is a Debian tor instance created with `tor-instance-create`. It has its own torrc (`/etc/tor/instances/NAME/torrc`), user (`_tor-NAME`), data directory (`/var/lib/tor-instances/NAME`), and unit (`tor@NAME`).

- **Add one:** press **`n`** in the console, or apply a config with `relay.instance = "NAME"` (or `--instance NAME`). Names are letters and digits only.
- **What is chosen for you:** the next free ORPort, a MetricsPort from 9036 upwards, a numbered nickname, and the same contact. Two relays on one server must not draw from the same monthly quota twice, so quota-based limits are not copied; set each relay's share yourself.
- **Family:** every relay on a server shares one family key. The tool copies the existing key into the new instance and refuses to create a second family.
- **Checks:** apply refuses ORPort and MetricsPort collisions with the server's other relays, warns above eight relays, and scales the memory check with the number of relays.
- **Console:** with several relays you get an all-relays health line and a relay switcher (`[` `]`, or `1`–`9`). Every card and action works on the selected relay.
- **Status:** `status --instance NAME` reports one relay and `status --all` reports all of them (JSON is then an array). Prometheus samples carry a `tor_instance` label.

### Kernel tuning for fast relays

For relays expecting more than about 100 Mbit/s, the System step offers `system.tuning`. It writes `/etc/sysctl.d/60-tor-relay.conf` with each value's reason as a comment:
- a wider ephemeral port range (`15000 64000`), against the TCP port exhaustion Tor's [overload guide](https://support.torproject.org/relays/performance/overloaded/) describes;
- a larger connection-tracking table, only when `nf_conntrack` is loaded.

It only ever widens what the kernel already uses. If the installed tor unit allows fewer than 65536 open files, it also adds a systemd drop-in that raises the limit.

## Fleets

A fleet inventory describes every relay you run. Start from [`docs/examples/fleet.toml`](examples/fleet.toml):

```toml
config = "relay.toml"      # base relay.toml, relative to this file
parallel = 8               # servers applied at once after the family host
nickname = "MyRelay{n}"    # {n} = position, {host} = short hostname

[[host]]
address = "root@relay1.example.org"

[[host]]
address = "admin@relay2.example.org"
relay = { ipv6 = "2001:db8::2", or_port = 443 }

[[host]]
address = "root@big1.example.org"
relay = { instance = "relay2", or_port = 9002 }   # a second relay on a server
```

Any `relay.toml` table can be overridden per host, merged key by key. Before the first connection, the tool checks every merged config, that nicknames are unique, and that no server lists the same relay or ORPort twice.

```bash
tor-relay-setup apply --inventory fleet.toml --dry-run
tor-relay-setup apply --inventory fleet.toml --only relay2   # just some relays
```

- **SSH:** your `~/.ssh/config`, keys, jump hosts, and `known_hosts` apply, and connections are shared per host for the run. Ports and other options belong in `~/.ssh/config`; addresses are `[user@]host` only.
- **Remote user:** must be root or have passwordless `sudo`, since the remote side runs without a terminal. Each host must have the same CPU architecture as your workstation, because it gets a copy of this binary for the run.
- **Family:** with `family.mode = "generate"`, the first relay runs alone and creates the family key. The rest then import it, `parallel` servers at a time, with relays on the same server one after another. If the family host fails, the rest are skipped, so the fleet never ends up in separate families.
- **Failures:** `--keep-going` continues after a failed host (except the family host). A summary table ends every run.
- **One-off runs:** `apply --config relay.toml --host … --host …` still works, but every host then gets the same nickname.

### The fleet dashboard

```bash
tor-relay-setup fleet                    # dashboard (reads ./fleet.toml, or --inventory FILE)
tor-relay-setup fleet status --format json
tor-relay-setup fleet restart --yes      # also: reload, update-tor
```

The dashboard and `fleet status` run `tor-relay-setup fleet-probe` on every host over SSH, so install the tool on each relay with `install.sh`. Hosts without it, or with an older version, are shown as such.

- **Refresh:** relays are probed every 10 seconds, 16 at a time. Tor Metrics is asked about the whole fleet at once every 30 minutes.
- **Keys:** `s`/`S` changes the sort, `/` filters, and `enter` opens a relay's details. `R`, `O`, and `U` restart, reload, or update Tor on the relays in view, one at a time, after a confirmation.
- **Rolling actions** run `tor-relay-setup tor restart|reload|update` on each host, then wait up to two minutes until that relay is active and listening again before moving on. The first failure stops the rollout unless you pass `--keep-going`.
- **Lost flags** are measured against the previous dashboard run, kept in your cache directory.
- **Prometheus:** `fleet status --format prometheus` exports fleet totals and per-relay series (`tor_relay_fleet_*`, listed in [`docs/monitoring/fleet-metrics.md`](monitoring/fleet-metrics.md)).

### Grafana for the whole fleet

For a permanent, browser-based view, run the monitoring stack on a small management server: not a relay, 1 GiB of RAM, Debian 12/13 or Ubuntu 22.04/24.04/26.04, with a DNS name pointing at it.

**No spare server?** Run it on one of your **non-exit** relays with `monitor install --local`.
- **What changes:** Grafana and Prometheus listen on localhost only. There is no web server and no domain, and no port is opened.
- **How you open it:** through an SSH tunnel, `ssh -N -L 3000:127.0.0.1:3000 you@relay` (or Termius port forwarding: local 3000 to `127.0.0.1:3000`), then `http://localhost:3000`.
- **Exits:** `--local` refuses to run on an exit.
- **Inventory:** with only existing relays to watch, the inventory can be monitoring-only. Leave out `config` and list just the addresses:

  ```toml
  [[host]]
  address = "relay1.example.org"

  [[host]]
  address = "relay2.example.org"
  ```

Otherwise, for a dedicated management server:

1. **On the management server:** install tor-relay-setup with `install.sh`. Put your inventory at `/etc/tor-relay-setup/fleet.toml`, next to the `relay.toml` it names, readable by the `tor-relay-monitor` user. Write the addresses without `user@`.
2. **Install the stack:**

   ```bash
   sudo tor-relay-setup monitor install --domain grafana.example.org --email you@example.org --dry-run
   sudo tor-relay-setup monitor install --domain grafana.example.org --email you@example.org
   ```

   It installs fleet serve, Prometheus (loopback only, 400 days of history), Grafana from its signed repository (loopback only, hardened, with the dashboards provisioned) and Caddy (HTTPS with Let's Encrypt). It opens only ports 80 and 443. It prints the Grafana login and the monitoring SSH key, and keeps the generated admin password in `/etc/tor-relay-setup/grafana-admin`.
3. **On every relay,** allow that key for the read-only probe only, using the management server's address:

   ```bash
   sudo tor-relay-setup fleet authorize --key 'ssh-ed25519 AAAA… tor-relay-monitor@monitor' --from 203.0.113.5
   ```

   This creates a `tor-relay-probe` user whose key is locked to one forced command, `sudo -n tor-relay-setup fleet-probe`, by a single sudoers rule. It prints the relay's SSH host key as a `known_hosts` line.
4. **Back on the management server,** add each printed line to `/var/lib/tor-relay-monitor/.ssh/known_hosts`. Host keys are never accepted blindly. Then check:

   ```bash
   sudo -u tor-relay-monitor ssh relay1.example.org | head -c 300
   sudo tor-relay-setup monitor status
   ```

5. **Open** `https://grafana.example.org/` and sign in as `tor-admin`. *Tor fleet — overview* is the home page, and *Tor fleet — relay detail* shows a single relay. The fleet web view lives at `/fleet/`; add its logins with `sudo tor-relay-setup fleet serve passwd NAME`.

Prometheus evaluates the bundled fleet alert rules, and the overview lists what is firing. Notifications stay with each relay's own `tor-relay-setup alert`. `privacy = true` in `/etc/tor-relay-setup/serve.toml` keeps per-relay traffic out of the metrics, which is worth considering if anyone besides you can see the dashboards. To revoke a management server's access, run `sudo tor-relay-setup fleet authorize --remove` on a relay. The full design is in [`docs/monitoring/README.md`](monitoring/README.md).

## Monitoring

- **The console** refreshes on its own. With MetricsPort enabled, it shows live traffic every two seconds; health is re-checked every 30 seconds, and Tor Metrics, including a month of traffic history, every 30 minutes.
- **`tor-relay-setup status --json`** returns the console's health report as JSON (service, version, listener, reachability, family keys, Tor Metrics, warnings). The exit code is 1 when something needs attention, which makes it easy to wire into cron, systemd timers, or a monitoring agent.
- **Prometheus:** `status --format prometheus` prints the same report as `tor_relay_setup_*` gauges, such as `service_active`, `reachable`, `family_keys_missing`, `warnings`, and `consensus_weight`. It always exits 0, so it suits node_exporter's textfile collector:

  ```ini
  # /etc/systemd/system/tor-relay-metrics.service
  [Service]
  Type=oneshot
  ExecStart=/bin/sh -c 'tor-relay-setup status --format prometheus > /var/lib/prometheus/node-exporter/tor_relay.prom.tmp && mv /var/lib/prometheus/node-exporter/tor_relay.prom.tmp /var/lib/prometheus/node-exporter/tor_relay.prom'

  # /etc/systemd/system/tor-relay-metrics.timer
  [Timer]
  OnBootSec=2min
  OnUnitActiveSec=5min

  [Install]
  WantedBy=timers.target
  ```

  Enable it with `sudo systemctl enable --now tor-relay-metrics.timer`.
- **Alerts:** `sudo tor-relay-setup alert install` adds a systemd timer that runs `alert run` every five minutes (`--every` changes that). Notifiers and thresholds live in `/etc/tor-relay-setup/alerts.toml`, mode `600` because it may hold tokens; see [the example](monitoring/alerts.toml). `alert test` sends a test message, and `alert run --dry-run` shows what would be sent.
  - **Notifiers:** ntfy, webhooks (JSON, or Slack-compatible), email through the local `sendmail`, or any command, which gets the alert as JSON on stdin.
  - **What it watches:** service stopped, ORPort unreachable, unsupported tor, a missing family key, the relay missing from the consensus or not running in Tor Metrics, lost flags, Tor's overload signals, Relay Search's overloaded mark, an accounting budget that will run out before the period ends, an expiring signing certificate (offline master keys), and a bridge transport that stopped listening.
  - **When it notifies:** when a problem appears, then every `remind_every` (24 hours by default) while it lasts, and once when it resolves. If Tor Metrics or the MetricsPort can't be reached, the alerts that depend on them keep their state instead of resolving.
- **Grafana and Prometheus:** [`docs/monitoring/`](monitoring/README.md) has scrape configurations, alerting rules, and a Grafana dashboard.
- **Nyx:** `sudo -u debian-tor nyx`
- **MetricsPort:** if enabled, Prometheus metrics are served on `127.0.0.1:9035`, reachable from the server only:

  ```bash
  curl -s http://127.0.0.1:9035/metrics | grep -E '^tor_relay_(load|exit_dns_error)'
  ```

  Never expose it publicly. To scrape it from elsewhere, use an SSH tunnel or a TLS proxy with authentication. Tor's [overload guide](https://support.torproject.org/relays/performance/overloaded/) explains the overload metrics.
- If you publish statistics about your relay, aggregate them over at least one day.

## Exit relays

Exits carry the legal and abuse load of the network, so preparation matters more than configuration:

- Get the provider's permission in writing, and know how complaints reach you. The wizard will not continue without that confirmation.
- Set reverse DNS to something like `tor-exit.example.org`.
- Turn on the **exit notice** (wizard, or **console → Exit policy (`x`)**). tor itself then serves [`tor-exit-notice.html`](examples/tor-exit-notice.html) on port 80 (`DirPort 80` with `DirPortFrontPage`), so anyone who looks up the IP address learns it is a Tor exit. Edit the page's placeholders; the tool never overwrites an existing page.
- Keep the **local Unbound resolver** the tool installs. Don't forward DNS to large public resolvers. For busy exits, watch `tor_relay_exit_dns_error_total` via MetricsPort.
- Start with `ReducedExitPolicy` (`exit.policy = "reduced"`), Tor's built-in list of common ports. The other choices:
  - `web`: 80 and 443 only;
  - `default`: Tor's default policy, which draws more complaints;
  - `custom`: your own rules in `exit.custom_policy`.

  The console editor validates each rule (`accept`/`reject`/`accept6`/`reject6`, addresses or `*`/`*4`/`*6`/`private`, ports and ranges). It insists on a final `reject *:*` or `accept *:*`, and has tor verify the result before writing it.
- Answer complaints promptly. [`docs/examples/`](examples) has reply templates for copyright (DMCA) notices, other abuse reports, and law-enforcement requests. Fill in the placeholders and adapt them to your jurisdiction.

Read [Tor's exit guidelines](https://community.torproject.org/relay/community-resources/tor-exit-guidelines/) and the [EFF's legal FAQ](https://community.torproject.org/relay/community-resources/eff-tor-legal-faq/) before you publish an exit.

## Bridges

Bridges are relays that are not listed in the public consensus, for users whose networks block Tor. Choose **Bridge** as the relay type.

| | obfs4 | WebTunnel |
| --- | --- | --- |
| Looks like | random bytes | an ordinary HTTPS website |
| You need | a second open TCP port | a domain pointing at the server, TLS, nginx (or your own web server) |
| Packages | `obfs4proxy`, or `lyrebird` where Debian ships it | `webtunnel` from the Tor Project repository, plus `nginx` |
| Example | [`bridge-obfs4.toml`](examples/bridge-obfs4.toml) | [`bridge-webtunnel.toml`](examples/bridge-webtunnel.toml) |

- **Ports below 1024:** an obfs4 port below 1024 (443 is popular) needs extra privileges. The tool grants the transport `cap_net_bind_service` with `setcap`, adds a `NoNewPrivileges=no` drop-in for the tor unit, and adds a managed block to the AppArmor profile. The console warns if the capability is missing.
- **WebTunnel:** the tool writes the nginx site `tor-webtunnel-<instance>`, which proxies a secret random path to the bridge on `127.0.0.1`. It checks the site with `nginx -t` and restores the previous version if the check fails. Certificates come from files you already have, or from certbot after you confirm its terms (`certificate = "certbot"`, `certbot_agree_tos = true`). With `web_server = "manual"`, the review shows the location block for your own server.
- **Distribution:** `bridge.distribution` chooses how Tor hands out the bridge: `any`, `https`, `email`, `telegram`, `settings`, or `none` to share it only yourself. WebTunnel bridges are handed out by `https`.
- **Sharing:** **console → Bridge line (`i`)** shows the line to give to users, with the public address filled in. `y` copies it; `w` saves it to a root-only file. Test obfs4 reachability with [bridges.torproject.org/scan](https://bridges.torproject.org/scan/).
- **Privacy:** the bridge line is left out of `status --json`, so it never reaches monitoring systems or fleet probes. Tor Metrics only ever sees the bridge's hashed fingerprint.
- **Restrictions:** bridges never use a relay family, and run without Sandbox, because tor refuses Sandbox with pluggable transports.

## Identity keys

A relay's identity is its ed25519 master key plus an RSA key. By default both stay on the server, and tor renews its medium-term signing key by itself. For more protection, keep the master key offline:

1. **Back up first:** run **console → Back up keys (`b`)**, then copy the archive off the server.
2. **`sudo tor-relay-setup keys offline`** sets `OfflineMasterKey 1` (checked by tor, then reloaded). It exports the master key, its public key, and the RSA identity key to `/root/tor-master-key-<instance>-<time>/`, reading each copy back to verify it. Copy that directory somewhere safe and offline.
3. **`sudo tor-relay-setup keys offline --remove-master`** deletes the master key from the server. It only does so after you type the first 12 hex digits of the copy's SHA-256, while `OfflineMasterKey 1` is set and the current signing certificate is valid for at least another day.
4. **Before the signing key expires** (30 days by default; `status`, `alert` and the console warn a week ahead), make the next one:
   - **On the machine with the master key:** run `tor --keygen` with the master key's data directory, copy `ed25519_signing_secret_key` and `ed25519_signing_cert` to the relay, then run `sudo tor-relay-setup keys renew --from DIR`. That checks the certificate is signed by this relay's master key and not expired, installs both files for the tor user with mode `600`, and reloads tor. `keys renew` without flags prints these commands.
   - **Or briefly on the relay:** run `sudo tor-relay-setup keys renew --master DIR` with the master key copied over, then remove the copy.

`keys status` (console `k`) shows where each key lives and when the signing certificate expires.

## Backups

- Every file the tool replaces is backed up next to itself as `<file>.bak.<UTC timestamp>`.
- Each apply writes a full log to `/var/log/tor-relay-setup/<timestamp>.log`.
- **Console → Back up keys (`b`)** writes `/root/tor-relay-keys-<timestamp>.tar.gz` (mode `600`). It contains the relay identity keys and any family keys.
- Copy that archive off the server to somewhere private. With it, a rebuilt server keeps the relay's identity, reputation, and family membership.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No "reachable from the outside" line | The ORPort is blocked. Check `ufw status`, the provider's cloud firewall or security group, and NAT. The console's Health card shows whether tor is listening. |
| IPv6 address never published | The wizard shows how many IPv6 directory authorities answered. Check that the provider firewall allows inbound IPv6 on the ORPort. If it keeps failing, reconfigure without IPv6. |
| `FamilyId … key missing` | The key file is missing from the key directory or has the wrong owner. Re-import it. Files must be owned by `debian-tor` with mode `600`. |
| Relay hibernates mid-month | The quota is too small for the configured rate. Raise the headroom in **Edit settings**. `alert` warns when the budget is on course to run out early. |
| Relay Search shows "overloaded" | Tor publishes this for 72 hours after it ran out of memory for queues, ran out of TCP ports, or dropped at least 1% of circuit handshakes. The console's Traffic card and `alert` name the signal and its remedy: add RAM or set `MaxMemInQueues`, enable kernel tuning, or lower the bandwidth limit. |
| A fleet host shows "too old" or "not installed" | The dashboard needs tor-relay-setup on each host. Run `install.sh` there, or `sudo tor-relay-setup self-update`. |
| A fleet relay shows thin data (no fingerprint, no keys) | The remote user has no passwordless `sudo`, so `fleet-probe` ran unprivileged. |
| `tor X is older than 0.4.9` | The package came from the distribution instead of the Tor repository. Run **console → Reconfigure (`w`)** to repair the repository, then **Update Tor (`u`)**. |
| Tor apt suite missing | The Tor repository does not publish your codename yet. Use a supported release. |
| apt "Could not get lock" | Another apt process (often unattended-upgrades on a fresh VPS) holds the lock. The tool waits up to five minutes on its own; otherwise wait and retry. |
| `dpkg was interrupted` | Run `sudo dpkg --configure -a`, then retry. The apply screen shows this hint itself. |
| Exit DNS failures | Check `systemctl status unbound`, `unbound-checkconf`, and whether `/etc/resolv.conf` points at `127.0.0.1`. |

A failed apply shows the failing step, a hint, and the path of the full log. Every step is safe to run again: fix the cause and press `r` to retry.

## Uninstalling this tool

`sudo tor-relay-setup uninstall` removes the tool's own state and logs (`/var/lib/tor-relay-setup`, `/var/log/tor-relay-setup`), then offers to remove the binary itself. `--yes` removes it without asking. If you installed the `.deb`, it tells you to run `sudo apt remove tor-relay-setup` instead.

It never removes Tor, the torrc, `/var/lib/tor`, identity or family keys, firewall rules, logs, Unbound, or hostname changes. Those belong to the operator.

## Retiring a relay

1. Stop the service with **console → Stop / start Tor (`p`)**, then keep it off across reboots with `sudo systemctl disable tor@default`.
2. If the relay was in a family, remove its `FamilyId`. Keep the key on your other relays.
3. Keep the identity-key backup if you might bring the relay back. Deleting `/var/lib/tor` destroys the identity and its reputation for good.
