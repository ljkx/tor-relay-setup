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

**CIISS proof:** if your ContactInfo has a `url:`, publish the family ID at `https://<your-domain>/.well-known/tor-relay/ed25519-family-id.txt` so tools can verify that the relays are yours.

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

## Monitoring

- **`tor-relay-setup status --json`** returns the console's health report as JSON (service, version, listener, reachability, family keys, Tor Metrics, warnings). The exit code is 1 when something needs attention, which makes it easy to wire into cron, systemd timers, or a monitoring agent.
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
- Set reverse DNS to something like `tor-exit.example.org`, and consider a short web page on that name explaining that the server is a Tor exit.
- Keep the **local Unbound resolver** the tool installs. Don't forward DNS to large public resolvers. For busy exits, watch `tor_relay_exit_dns_error_total` via MetricsPort.
- Start with `ReducedExitPolicy`. Tor docs describe it as a good default.

Read [Tor's exit guidelines](https://community.torproject.org/relay/community-resources/tor-exit-guidelines/) before you publish an exit.

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
| Relay hibernates mid-month | The quota is too small for the configured rate. Raise the headroom in **Edit settings**. |
| `tor X is older than 0.4.9` | The package came from the distribution instead of the Tor repository. Run **console → Reconfigure (`w`)** to repair the repository, then **Update Tor (`u`)**. |
| Tor apt suite missing | The Tor repository does not publish your codename yet. Use a supported release. |
| apt "Could not get lock" | Another apt process (often unattended-upgrades on a fresh VPS) holds the lock. The tool waits up to five minutes on its own; otherwise wait and retry. |
| `dpkg was interrupted` | Run `sudo dpkg --configure -a`, then retry. The apply screen shows this hint itself. |
| Exit DNS failures | Check `systemctl status unbound`, `unbound-checkconf`, and whether `/etc/resolv.conf` points at `127.0.0.1`. |

A failed apply shows the failing step, a hint, and the path of the full log. Every step is safe to run again: fix the cause and press `r` to retry.

## Uninstalling this tool

`sudo tor-relay-setup uninstall` removes only the tool's own state and logs (`/var/lib/tor-relay-setup`, `/var/log/tor-relay-setup`). Delete the binary yourself afterwards, or run `sudo apt remove tor-relay-setup` if you installed the `.deb`.

It never removes Tor, the torrc, `/var/lib/tor`, identity or family keys, firewall rules, logs, Unbound, or hostname changes. Those belong to the operator.

## Retiring a relay

1. Stop the service with **console → Stop / start Tor (`p`)**, then keep it off across reboots with `sudo systemctl disable tor@default`.
2. If the relay was in a family, remove its `FamilyId`. Keep the key on your other relays.
3. Keep the identity-key backup if you might bring the relay back. Deleting `/var/lib/tor` destroys the identity and its reputation for good.
