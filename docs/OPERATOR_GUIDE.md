# Operator guide

The day-two companion to the installer: what to prepare, what to check after setup, how to run a family of relays, and how to fix the usual problems. Where this guide and the [Tor Project relay documentation](https://community.torproject.org/relay/) disagree, the Tor docs win.

## Before you start

Have these ready:

- A **nickname**: 1–19 letters or digits. Nicknames are not unique; your fingerprint is what identifies the relay.
- A working **contact email**. It is published, and Tor's [operator expectations](https://community.torproject.org/policies/relays/expectations-for-relay-operators/) require it to reach you.
- The **ORPort**: `9001` is common; `443` gets through more restrictive networks.
- Your provider's **monthly traffic quota** and how it is counted (in + out, outbound only, or per direction).
- Whether IPv6 really works on the server.
- Whether the provider has a **cloud firewall** in front of the VM. If so, open the ORPort there too.
- For exits only: written provider permission, a plan for abuse complaints, and ideally reverse DNS that says the server is a Tor exit.

Then do a dry run. It asks every question and prints the full plan without changing anything:

```bash
./setup-tor-guard-relay.sh --dry-run
```

## Right after setup

The script already checks the service, the listener, and Tor's reachability self-test. To look again yourself:

```bash
systemctl status tor@default --no-pager
journalctl -u tor@default -f
journalctl -u tor@default --since "1 hour ago" | grep -F "Self-testing indicates"
tor --version    # must be 0.4.9 or newer
```

A healthy start logs `Self-testing indicates your ORPort <address>:<port> is reachable from the outside. Excellent.` If you configured IPv6, there is a second line for the IPv6 address.

## The first weeks

New relays ramp up slowly. That is expected ([lifecycle of a new relay](https://blog.torproject.org/lifecycle-of-a-new-relay/)):

- [Relay Search](https://metrics.torproject.org/rs.html) usually lists the relay after about 3 hours.
- The bandwidth authorities measure it over the following days. Traffic grows as the measurements come in.
- The Guard flag needs about 8 days of stable uptime, and guard traffic then grows over several weeks.

Keep the relay online. Relays that disappear often, or hibernate early in the month, lose their weight.

## Relay families

Run more than one relay? They must be declared as one family, so clients never use two of them in the same circuit. Tor 0.4.9 families use a shared key:

1. **On your first relay**, choose *Create a new family key*, either during setup or later from **console → Relay family**. The script runs `tor --keygen-family`, installs the key in `/var/lib/tor/keys/`, and adds `FamilyId <id>` to the torrc.
2. **Copy the key to each additional relay** over SSH. **Relay family → Share with another relay** prints the commands, for example:

   ```bash
   scp /var/lib/tor/keys/relay-family.secret_family_key \
       /var/lib/tor/keys/relay-family.public_family_id root@relay-2:/root/
   ```

3. **On each additional relay**, choose *Import an existing family key* and give the path of the copied `.secret_family_key`. Delete the copies from `/root` afterwards.
4. **Check it**: **Relay family → Show family status** must say `key: installed` for every `FamilyId`. After a few hours, Relay Search should show the relays together.

**Rotating the key:** create the new key on one relay, choose to *keep the existing FamilyId lines*, import the new key everywhere, wait a few days, then remove the old `FamilyId`.

**CIISS proof:** if your ContactInfo has a `url:`, publish the family ID at `https://<your-domain>/.well-known/tor-relay/ed25519-family-id.txt` so tools can verify that the relays are yours.

**MyFamily:** fingerprint lists are the pre-0.4.9 method. Tor 0.4.8 is end-of-life, so current clients only use `FamilyId`. The legacy editor is still under **Relay family → Legacy MyFamily editor** if you want both. It resolves nicknames through Onionoo and always stores fingerprints.

## Bandwidth planning

- **Steady monthly budget** (recommended for VPS quotas) turns the quota into `RelayBandwidthRate`/`Burst`, calculated so the budget lasts a 31-day month. `AccountingMax` stays in place as a fuse. `10TB` is read as 10¹² bytes, the way providers bill it.
- **Manual rate** suits a server whose bandwidth you know and don't need to meter.
- **`AccountingMax` only** lets the relay run at full speed and then hibernate until the next period. Tor docs call this out as the less useful option.
- If the relay still hibernates, increase the headroom or choose *combined in + out* counting in **console → Configuration editor → Bandwidth**.

## Monitoring

- **Nyx:** `sudo -u debian-tor nyx`
- **MetricsPort:** if enabled, Prometheus metrics are served on `127.0.0.1:9035`, reachable from the server only:

  ```bash
  curl -s http://127.0.0.1:9035/metrics | grep -E '^tor_relay_(load|exit_dns_error)'
  ```

  Never expose it publicly. To scrape it from elsewhere, use an SSH tunnel or a TLS proxy with authentication. Tor's [overload guide](https://support.torproject.org/relays/performance/overloaded/) explains the overload metrics.
- If you publish statistics about your relay, aggregate them over at least one day.

## Exit relays

Exits carry the legal and abuse load of the network, so preparation matters more than configuration:

- Get the provider's permission in writing, and know how complaints reach you.
- Set reverse DNS to something like `tor-exit.example.org`, and consider a short web page on that name explaining that the server is a Tor exit.
- Keep the **local Unbound resolver** the script installs. Don't forward DNS to large public resolvers. For busy exits, watch `tor_relay_exit_dns_error_total` via MetricsPort.
- Start with `ReducedExitPolicy`. Tor docs describe it as a good default.

Read [Tor's exit guidelines](https://community.torproject.org/relay/community-resources/tor-exit-guidelines/) before you publish an exit.

## Backups

- Every file the script replaces is backed up next to itself as `<file>.bak.<UTC timestamp>`.
- **Console → Backups → Back up identity keys** writes `/root/tor-relay-identity-keys.<timestamp>.tar.gz` (mode `600`). It contains the relay identity keys and any family keys.
- Copy that archive off the server to somewhere private. With it, a rebuilt server keeps the relay's identity, reputation, and family membership.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No "reachable from the outside" line | The ORPort is blocked. Check `ufw status`, the provider's cloud firewall or security group, and NAT. `ss -ltn \| grep :9001` must show tor listening. |
| IPv6 address never published | Test outbound IPv6 (`ping -6 2001:67c:289c::9`). Check that the provider firewall allows inbound IPv6 on the ORPort. If it keeps failing, remove the IPv6 `ORPort` line. |
| `FamilyId … key: NOT FOUND` | The key file is missing from the key directory or has the wrong owner. Re-import it. Files must be owned by `debian-tor` with mode `600`. |
| Relay hibernates mid-month | The quota is too small for the configured rate. Recalculate the bandwidth with more headroom. |
| `tor X is older than 0.4.9` | The package came from the distribution instead of the Tor repository. Run **Packages → Repair Tor apt repo**, then **Update Tor**. |
| Tor apt suite missing | The Tor repository does not publish your codename yet. Use a supported release. |
| Signing key or keyring errors | Check the system time and DNS. The script refuses any key other than `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`. |
| `No space left on device` during apt | Run `df -h` and `df -ih`, free space, then `sudo apt clean && sudo apt update`. |
| Exit DNS failures | Check `systemctl status unbound`, `unbound-checkconf`, and whether `/etc/resolv.conf` points at `127.0.0.1`. |

For anything else, **console → Operator report** writes a local report (tor version, service state, relay directives, recent warnings) to `/tmp`. Review it before you share it.

## Cleaning up this tool

`--uninstall` removes only what this tool left behind: its state directory, its reports, fzf if the tool installed it, and optionally the downloaded script or a clean clone.

It never removes Tor, the torrc, `/var/lib/tor`, identity or family keys, firewall rules, logs, Unbound, or hostname changes. Those belong to the operator.

## Retiring a relay

1. Stop and disable the service: **console → Service controls**.
2. If the relay was in a family, remove its `FamilyId`. Keep the key on your other relays.
3. Keep the identity-key backup if you might bring the relay back. Deleting `/var/lib/tor` destroys the identity and its reputation for good.
