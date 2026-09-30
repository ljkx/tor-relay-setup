# Tor Relay Setup

[![CI](https://github.com/ljkx/tor-relay-setup/actions/workflows/ci.yml/badge.svg)](https://github.com/ljkx/tor-relay-setup/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ljkx/tor-relay-setup?include_prereleases&sort=semver)](https://github.com/ljkx/tor-relay-setup/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A guided, review-before-apply installer and operator console for public **Tor relays** (guard/middle or exit) on Debian and Ubuntu servers.

It asks the questions a relay operator actually has to answer, shows the full plan and the generated `torrc`, and only then changes the system. Everything it does follows the [Tor Project relay documentation](https://community.torproject.org/relay/):

- installs **tor ≥ 0.4.9** from the official Tor Project apt repository, after verifying the signing key and the package origin
- sets up **relay families** with `FamilyId` keys (Tor 0.4.9 "Happy Families")
- builds a **CIISS v3** ContactInfo string
- paces bandwidth over a **monthly traffic quota** so the relay never hibernates early
- configures the firewall, exit DNS (Unbound), unattended upgrades, and an optional local **MetricsPort**
- verifies the relay after start: service state, listener, and Tor's own ORPort reachability self-test

Run it again on an existing relay and it opens an **operator console** for families, health checks, directory status, logs, backups, updates, and repairs.

![Guided setup in a dry run](docs/assets/tor-relay-setup-first-run.svg)

## Quick start

Download the release, verify it, read it, dry-run it, then run it:

```bash
VERSION=v2.0.0-beta.1
curl -fsSLO "https://github.com/ljkx/tor-relay-setup/releases/download/${VERSION}/setup-tor-guard-relay.sh"
curl -fsSLO "https://github.com/ljkx/tor-relay-setup/releases/download/${VERSION}/SHA256SUMS"
sha256sum --check SHA256SUMS
gh attestation verify setup-tor-guard-relay.sh -R ljkx/tor-relay-setup   # optional, needs the GitHub CLI
less setup-tor-guard-relay.sh
chmod +x setup-tor-guard-relay.sh
./setup-tor-guard-relay.sh --dry-run
sudo ./setup-tor-guard-relay.sh
```

Every release asset carries a [Sigstore-signed build-provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations), so `gh attestation verify` proves the file was built by this repository's release workflow from the tagged commit.

Prefer git? Clone and check out the tag instead:

```bash
git clone https://github.com/ljkx/tor-relay-setup.git && cd tor-relay-setup
git checkout v2.0.0-beta.1
./setup-tor-guard-relay.sh --dry-run
```

> [!IMPORTANT]
> This is privileged server software and still a beta. Always run `--dry-run` first, read the review screen before you confirm, and prefer a fresh or disposable VPS. Piping the script straight into `sudo bash` works, but you lose the chance to verify and read it.

## Requirements

| | |
| --- | --- |
| **OS** | Debian 12 `bookworm`, Debian 13 `trixie`, Ubuntu 22.04 `jammy`, Ubuntu 24.04 `noble`, Ubuntu 26.04 `resolute` (all tested in CI). Other codenames work when the [Tor apt repository](https://deb.torproject.org/torproject.org/dists/) publishes them; the script checks before it adds the repository. |
| **CPU** | `amd64` or `arm64`, the only architectures the Tor apt repository builds. |
| **Init** | systemd (`tor@default.service`) |
| **Network** | A public, static IPv4 address; IPv6 is optional. Inbound TCP to the ORPort must be allowed, including in your provider's cloud firewall. |
| **Bandwidth** | At least 10 Mbit/s each way (16 Mbit/s or more recommended), and at least 100 GB of traffic per month in each direction. See [relay requirements](https://community.torproject.org/relay/relays-requirements/). |
| **Memory** | 512 MiB for a guard/middle relay under 40 Mbit/s, 1 GiB above that, and 1.5 GiB for an exit. The script warns when you are below this. |

## What the guided setup asks

1. **Hostname**: optionally rename the server. This is not the relay nickname.
2. **Relay mode**: guard/middle (`ExitRelay 0`) or exit. Exit mode requires you to confirm that your provider permits exits and that you are ready to handle abuse complaints.
3. **Identity**:
   - a nickname
   - ContactInfo, either built as [CIISS v3](https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/) (`email:you[]example.org … ciissversion:3`) or entered as free text
   - the ORPort
4. **IPv6**: auto-detects a global address. Offers Tor's documented outbound check (ping the IPv6 directory authorities) and flags manual overrides as unverified.
5. **Exit options** (exit mode only): `ReducedExitPolicy`, `IPv6Exit`, and a local caching, DNSSEC-validating **Unbound** resolver.
6. **Relay family**: none, create a new family key, or import the key from one of your other relays. See [Relay families](#relay-families).
7. **Bandwidth**:
   - *steady monthly budget*: recommended for VPS quotas
   - *manual rate and burst*
   - *hard `AccountingMax` only*
   - *no cap*
8. **Maintenance**: unattended upgrades, Nyx, a local MetricsPort, the firewall (UFW, firewalld, or an existing nftables `inet filter input` chain), and `Sandbox 1`.
9. **Review**: every setting, the complete `torrc`, and a list of every privileged change. Nothing is modified before you confirm.

![Final review in a dry run](docs/assets/tor-relay-setup-review.svg)

When [fzf](https://github.com/junegunn/fzf) is available, the script uses searchable selectors and scrollable command-output panels. If fzf isn't installed, the script offers to install it; you can decline and continue in plain line mode. `--plain` forces plain mode.

## Relay families

If you run more than one relay, clients must know they share an operator, so they never put two of them in the same circuit. Tor 0.4.9 replaced fingerprint lists (`MyFamily`) with a shared **family key**. Every relay in the family holds a copy of the same secret key, and its torrc has the matching `FamilyId` line.

- **First relay:** choose *Create a new family key*. After tor is installed, the script runs `tor --keygen-family`. It installs the key into Tor's key directory, readable only by `debian-tor`, and adds `FamilyId <id>` to the torrc.
- **Further relays:** copy `<name>.secret_family_key` and `<name>.public_family_id` to the new server over SSH. Then choose *Import an existing family key*. The console's **Relay family → Share with another relay** screen prints the exact `scp` commands.
- `tor --verify-config` does not check that the key exists, so the script checks it: the health check confirms every `FamilyId` has an installed key, and each restart reports any family warnings Tor logged.
- Key rotation works as documented: add the new key and `FamilyId` alongside the old ones, wait a few days, then remove the old `FamilyId`.
- The old MyFamily editor is still available under **Relay family → Legacy MyFamily editor**. Current clients no longer need it.

Details: [Tor's family ID guide](https://community.torproject.org/relay/setup/post-install/family-ids/).

## Bandwidth and monthly quotas

Most VPS plans include a monthly traffic quota. In Tor, `AccountingMax` on its own is only a fuse: once the quota is used up, the relay hibernates and drops out of the network until the next accounting period. The **steady monthly budget** mode spreads the quota across the whole month instead:

- Quotas are read the way providers bill them. `10TB` means 10¹² bytes. `TiB`/`GiB` and Tor's own `GBytes` are binary.
- You choose a safety margin (default 10%) and how your provider counts traffic: in + out combined, outbound only, or per direction.
- `RelayBandwidthRate` is calculated so the budget lasts a 31-day month. Burst is 5× the rate, and `AccountingMax` stays in place as a fuse.

A 10 TB combined quota with 10% headroom produces:

```torrc
RelayBandwidthRate 1640 KBytes
RelayBandwidthBurst 8200 KBytes
AccountingStart month 1 00:00
AccountingRule sum
AccountingMax 8381 GBytes
```

## What it changes

Nothing below is touched until you confirm the review screen. Every replaced file is first backed up as `<file>.bak.<UTC timestamp>`.

| Path / component | When |
| --- | --- |
| `/etc/apt/sources.list.d/tor.sources` (deb822), `/usr/share/keyrings/deb.torproject.org-keyring.gpg` | always. The key is checked against fingerprint `A3C4 F0F9 79CA A22C DBA8 F512 EE8C BC9E 886D DD89` and must be the only key in the file. |
| packages `tor`, `deb.torproject.org-keyring` | always. The `tor` candidate must come from `deb.torproject.org` and be ≥ 0.4.9. |
| `/etc/tor/torrc` | always. The candidate is validated with `tor --verify-config` using Debian's service defaults. |
| `/var/lib/tor/keys/<name>.secret_family_key` | when you create or import a family key. Existing keys are never overwritten. |
| `/etc/apt/apt.conf.d/52tor-relay-unattended-upgrades`, `20auto-upgrades`, packages `unattended-upgrades`, `apt-listchanges` | when unattended upgrades are enabled (security updates plus Tor Project packages) |
| packages `nyx`, `ufw`, `fzf`, `unbound` | when you choose them |
| firewall rules | when you confirm. SSH ports are allowed before UFW is enabled. |
| `/etc/resolv.conf` | exit relays with Unbound only. It is restored automatically if DNS stops resolving. |
| `/etc/hostname`, `/etc/hosts` | only when you rename the host |
| `/var/lib/tor-relay-setup/` | a tiny state file, so `--uninstall` knows what the script installed |

There is no telemetry. Outbound connections go only to `deb.torproject.org` and your distribution's mirrors (apt), `onionoo.torproject.org` (when you look up directory or family status), and the Tor directory authorities (only if you run the optional IPv6 ping check).

## Generated torrc

A guard relay that is the first member of a family, with MetricsPort enabled:

```torrc
Nickname ExampleRelay
ContactInfo "email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 ciissversion:3"

FamilyId flIHuuYy2vCWg+FgNibpOOHpRQ7rALbVUlS0WMmmuI8

ORPort 9001
SocksPort 0
ExitRelay 0
SafeLogging 1
Sandbox 1

MetricsPort 127.0.0.1:9035
MetricsPortPolicy accept 127.0.0.1
```

An exit relay adds `ExitRelay 1`, `ReducedExitPolicy 1` (unless you pick Tor's default exit policy), and `IPv6Exit 1` when IPv6 is enabled.

## Operator console

Running the script on a server whose `torrc` already has an `ORPort` opens the console instead of a new setup:

| Menu | What it does |
| --- | --- |
| Relay family | Family status, create/rotate keys, import, share instructions, remove, legacy MyFamily |
| Health check | Tor version floor, service, config, ORPort listener, reachability self-test, family keys |
| Directory status | Your relay as published in Tor Metrics (Onionoo): flags, bandwidth, addresses, family IDs |
| Service controls | Start, reload, restart (with verification), stop, disable |
| Logs | Recent logs, live follow, ORPort self-test messages |
| Configuration editor | Nickname, ContactInfo, bandwidth, Sandbox, SOCKS, MetricsPort. Every change is verified before it is written. |
| Backups | Back up or restore the torrc; archive identity and family keys (root-only) |
| Packages | Update Tor, repair the Tor apt repository, unattended upgrades, Nyx, fzf |
| Repair | Verify the config, restart, logs, firewall |
| Report / command logs / cleanup | A local troubleshooting report, the command output from this run, and removal of traces left by this tool |

## Command-line options

| Option | Effect |
| --- | --- |
| `--dry-run` | Go through every prompt and print what would change, without installing packages or writing system files. It doesn't need root. |
| `--plain` | Use the plain line interface even if fzf is installed. |
| `--uninstall` | Remove traces of this tool only: its state directory, its reports, fzf if the tool installed it, and optionally the script or clone itself. Tor, the torrc, keys, and firewall rules are left alone. |
| `--version`, `--help` | Print the version or the usage. |

`NO_COLOR=1` disables colours.

## Keeping it up to date

- **Tor** updates itself through unattended upgrades, when enabled. To update by hand, use console → *Packages and tools → Update Tor*, or run `sudo apt update && sudo apt install tor`.
- **This tool:** download a newer release, verify it, and run it with `--dry-run` first. On an existing relay it opens the console; it doesn't reinstall anything.

Day-two tasks, troubleshooting, exit-relay notes, and retiring a relay are covered in the **[Operator guide](docs/OPERATOR_GUIDE.md)**.

## Security

- Every change is shown before it is applied, and every replaced file is backed up first.
- Supply chain:
  - The Tor signing key is pinned by fingerprint.
  - The `tor` package must come from `deb.torproject.org`.
  - The generated `torrc` is validated by tor itself before it replaces the live config.
- Release assets come with `SHA256SUMS` and a signed build-provenance attestation.
- `ContactInfo`, the nickname, the fingerprint, and the `FamilyId` are **public**.
- Identity and family keys are secret. Back them up (console → *Backups*) and never share them except with your own relays.

Found a vulnerability? See [SECURITY.md](SECURITY.md). Please don't open a public issue.

## Development

```bash
make check        # pinned ShellCheck + shfmt + bats suites (unit, stubbed system, scripted dry runs)
make integration  # real Tor apt install, family keygen and tor --verify-config in a Debian container
```

CI runs the dry-run and integration suites on every supported distribution (amd64, plus arm64), and it also runs weekly. See [CONTRIBUTING.md](CONTRIBUTING.md) for how the tests are organised, and [docs/RELEASE.md](docs/RELEASE.md) for how releases are cut.

## References

- [Tor relay guide](https://community.torproject.org/relay/) and [Debian/Ubuntu guard setup](https://community.torproject.org/relay/setup/guard/debian-ubuntu/)
- [Exit relays](https://community.torproject.org/relay/setup/exit/) and [exit DNS on Debian/Ubuntu](https://community.torproject.org/relay/setup/exit/debian-ubuntu/)
- [Tor apt repository](https://support.torproject.org/little-t-tor/getting-started/installing/)
- [Post-install and good practices](https://community.torproject.org/relay/setup/post-install/) and [family IDs](https://community.torproject.org/relay/setup/post-install/family-ids/)
- [Relay requirements](https://community.torproject.org/relay/relays-requirements/) and [expectations for relay operators](https://community.torproject.org/policies/relays/expectations-for-relay-operators/)
- [Bandwidth limits](https://support.torproject.org/relays/performance/bandwidth-limits/) and [MetricsPort / overload](https://support.torproject.org/relays/performance/overloaded/)
- [ContactInfo Information Sharing Specification](https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/)
- [Relay Search](https://metrics.torproject.org/rs.html) and [Onionoo](https://metrics.torproject.org/onionoo.html)

## License

[MIT](LICENSE)
