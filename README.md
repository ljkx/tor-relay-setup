# Tor Relay Setup

[![CI](https://github.com/ljkx/tor-relay-setup/actions/workflows/ci.yml/badge.svg)](https://github.com/ljkx/tor-relay-setup/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ljkx/tor-relay-setup?include_prereleases&sort=semver)](https://github.com/ljkx/tor-relay-setup/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/ljkx/tor-relay-setup)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Set up and run a public **Tor relay** on Debian or Ubuntu from one small, signed binary. `tor-relay-setup` combines a guided setup wizard, a declarative `apply` mode for repeatable servers, and an operator console for everything after day one. Every change is shown before it happens.

<p align="center">
  <img src="docs/assets/setup.gif" width="900"
       alt="Setup wizard: guard relay, CIISS ContactInfo with a live torrc preview, a new family key, a 10 TB monthly budget paced to 13.4 Mbit/s, MetricsPort, the review screen, and the apply checklist finishing a dry run">
</p>

## What it does

- **Installs tor ≥ 0.4.9 from the Tor Project repository.**
  - The signing key is checked in Go against its pinned fingerprint and must be the only key in the file.
  - The `tor` package must come from `deb.torproject.org`.
  - Everything installs in a single apt transaction, with a real progress bar.
- **Relay families with FamilyId keys** (Tor 0.4.9 "Happy Families"): create a key on your first relay, then import it on the rest.
- **A ContactInfo that follows the CIISS v3 spec**, built for you.
- **Monthly quota pacing**, so a 10 TB VPS plan becomes a steady rate and the relay never hibernates halfway through the month.
- **The rest of the setup:** firewall rules (SSH is always allowed first), a local Unbound resolver for exit DNS, unattended upgrades, Nyx, and an optional local-only MetricsPort.
- **Verification before and after:** every torrc is checked by `tor --verify-config` before it replaces the live file. After Tor starts, the tool checks the service, the listener, family-key warnings, and Tor's own reachability self-test, which it keeps waiting for in the background.
- **A dashboard for existing relays:** run it again on a configured relay and you get health, Tor Metrics, a live log, family management, settings, updates, and key backups.

## Install

The recommended way is the verified installer. It checks the release against `SHA256SUMS`, and verifies the Sigstore build provenance too if the GitHub CLI is installed:

```bash
curl -fsSLO https://raw.githubusercontent.com/ljkx/tor-relay-setup/main/install.sh
less install.sh
sudo bash install.sh
```

<details>
<summary>Other ways: .deb package, manual download, from source</summary>

**Debian package** (`amd64` or `arm64`):

```bash
VERSION=v3.0.0
ARCH=$(dpkg --print-architecture)
curl -fsSLO "https://github.com/ljkx/tor-relay-setup/releases/download/${VERSION}/tor-relay-setup_${VERSION#v}_${ARCH}.deb"
gh attestation verify "tor-relay-setup_${VERSION#v}_${ARCH}.deb" -R ljkx/tor-relay-setup   # optional
sudo apt install "./tor-relay-setup_${VERSION#v}_${ARCH}.deb"
```

**Manual:** download `tor-relay-setup_<version>_linux_<arch>.tar.gz` and `SHA256SUMS` from the [releases page](https://github.com/ljkx/tor-relay-setup/releases). Then run `sha256sum --ignore-missing -c SHA256SUMS`, extract the archive, and put the binary on your `PATH`.

**From source** (Go 1.27+):

```bash
go install github.com/ljkx/tor-relay-setup/cmd/tor-relay-setup@latest
```

</details>

## Use

```bash
tor-relay-setup --dry-run      # the full experience; nothing on the server changes, no root needed
sudo tor-relay-setup           # setup wizard on a fresh server, operator console on an existing relay
```

On a fresh server you answer seven short steps:
1. relay type
2. contact
3. network
4. family
5. bandwidth
6. system
7. review

A live `torrc` preview and a panel of facts about the server (release, memory, repository availability, IPv6 reachability, firewall, SSH ports) sit beside the questions. Those facts are gathered in the background the moment the tool starts. Nothing is modified until you press `a` on the review screen and confirm.

> [!IMPORTANT]
> This is privileged server software. Run `--dry-run` first and read the review screen before you apply.

### Repeatable setups and fleets

Press `s` on the review screen to save your answers as `relay.toml`, or start from [`docs/examples/relay.toml`](docs/examples/relay.toml). Then apply the file on any number of servers:

```bash
sudo tor-relay-setup apply --config relay.toml          # shows the plan, asks once
sudo tor-relay-setup apply --config relay.toml --yes    # unattended, plain output
```

### Monitoring

```bash
tor-relay-setup status          # human summary, exit code 1 when something needs attention
tor-relay-setup status --json   # the same report as JSON, for scripts and monitoring
```

## The operator console

<p align="center">
  <img src="docs/assets/console.gif" width="900"
       alt="Operator console: relay, health, family and traffic cards, Tor Metrics, recent log, the live log view, family sharing instructions, and a Tor update">
</p>

| Key | Action | What it does |
| --- | --- | --- |
| `r` | Refresh | Re-reads everything; the cards load concurrently and Tor Metrics arrives asynchronously |
| `l` | Live logs | Follows the Tor journal in place, with self-test and warning lines highlighted |
| `f` | Relay family | FamilyId status, create or rotate a key, import, share instructions, remove, legacy MyFamily cleanup |
| `e` | Edit settings | Nickname, ContactInfo, bandwidth, MetricsPort, Sandbox. Verified by tor before anything is written. |
| `s` / `o` | Restart / Reload Tor | Restarts and verifies the service, or reloads after checking the torrc |
| `p` | Stop / start Tor | Takes the relay offline (with confirmation) or brings it back |
| `u` | Update Tor | Refreshes apt and upgrades tor from the Tor Project repository, with progress |
| `b` | Back up keys | Writes a root-only archive of the identity and family keys |
| `w` | Reconfigure | Reopens the full wizard, pre-filled from the current torrc, keeping its family |

## Requirements

| | |
| --- | --- |
| **OS** | Debian 12 `bookworm`, Debian 13 `trixie`, Ubuntu 22.04 `jammy`, Ubuntu 24.04 `noble`, Ubuntu 26.04 `resolute` (all tested in CI). Other codenames work once the [Tor apt repository](https://deb.torproject.org/torproject.org/dists/) publishes them. |
| **CPU** | `amd64` or `arm64`, the architectures the Tor repository builds |
| **Init** | systemd (`tor@default.service`) |
| **Network** | A public, static IPv4 address; IPv6 is optional. Inbound TCP to the ORPort must be open, including in your provider's cloud firewall. |
| **Relay capacity** | At least 10 Mbit/s each way (16 Mbit/s or more recommended), and at least 100 GB/month in each direction. Memory: 512 MiB, 1 GiB above 40 Mbit/s, 1.5 GiB for exits. See the [Tor relay requirements](https://community.torproject.org/relay/relays-requirements/). |

## Why it's fast

Version 3 replaced the Bash script with a Go binary. The script's own logic was never the bottleneck; the waiting around it was, and v3 removes it:

| | v2 (Bash) | v3 |
| --- | --- | --- |
| apt | up to 4× `apt-get update`, 7–8 separate installs | **one** update and **one** transaction; waits out apt locks instead of failing |
| Signing key | fetched with wget, checked with gpg | fetched and verified in-process; no gpg or wget needed |
| Server checks | run one by one, in the foreground | run concurrently at start-up (about 55 ms), while you answer questions |
| Between questions | a new fzf process for every prompt | one Bubble Tea program, so there is no delay |
| Command output | a window that waited for Enter after every step | a live checklist, a progress bar, and a log you can open |
| Reachability wait | blocked for up to 90 s | runs in the background with a timer; press Enter to finish now |

A complete dry run, including the real repository and key checks over the network, finishes in well under a second.

## Relay families

If you run more than one relay, clients must know that they share an operator. Tor 0.4.9 replaced fingerprint lists (`MyFamily`) with a shared **family key**:

1. On your first relay, choose **Create a new family key**. The tool runs `tor --keygen-family`, installs the key for `debian-tor` with mode `0600`, and adds `FamilyId <id>` to the torrc.
2. Copy the key to your other relays. **Console → Relay family → Share** prints the exact `scp` commands.
3. On each other relay, choose **Import an existing family key**.

`tor --verify-config` does not notice a missing key file, so the tool checks for one itself, and it reports any family warnings Tor logs after a restart. Details: [Tor's family ID guide](https://community.torproject.org/relay/setup/post-install/family-ids/) and the [operator guide](docs/OPERATOR_GUIDE.md#relay-families).

## What it changes

Nothing changes before you confirm the review screen. Every replaced file is first backed up as `<file>.bak.<UTC timestamp>`.

| Path / component | When |
| --- | --- |
| `/etc/apt/sources.list.d/tor.sources`, `/usr/share/keyrings/deb.torproject.org-keyring.gpg` | always |
| packages `tor`, `deb.torproject.org-keyring` (+ `nyx`, `unbound`, `ufw`, `unattended-upgrades`, `apt-listchanges` as chosen) | one apt transaction |
| `/etc/tor/torrc` | always, after `tor --verify-config` accepts the new version |
| `/var/lib/tor/keys/<name>.secret_family_key` | creating or importing a family; existing keys are never overwritten |
| `/etc/apt/apt.conf.d/52tor-relay-unattended-upgrades`, `20auto-upgrades` | automatic updates |
| firewall rules | when chosen; SSH ports are allowed before UFW is enabled |
| `/etc/resolv.conf` | exits using Unbound; rolled back automatically if DNS stops resolving |
| `/etc/hostname`, `/etc/hosts` | only if you rename the host |
| `/var/lib/tor-relay-setup/state.json`, `/var/log/tor-relay-setup/*.log` | the tool's own state, and a log of each apply |

There is no telemetry. The tool only contacts apt mirrors, `deb.torproject.org`, `onionoo.torproject.org` (for directory status), and the IPv6 directory authorities (for the optional IPv6 check).

## Command reference

```text
tor-relay-setup [flags]                   console on a configured relay, otherwise the setup wizard
tor-relay-setup setup [flags]             run the setup wizard
tor-relay-setup apply --config FILE       apply a saved relay.toml (--yes skips the confirmation)
tor-relay-setup console                   open the operator console
tor-relay-setup status [--json]           relay health; exit code 1 when something needs attention
tor-relay-setup uninstall                 remove this tool's state and logs (never Tor or its keys)
tor-relay-setup version

--dry-run   show every command and file change without making it (no root needed)
--plain     line-by-line prompts and output; also used automatically without a terminal
            (screen-reader friendly)
```

`NO_COLOR=1` disables colour. The interface adapts to light and dark terminals.

## Upgrading from 2.x

Version 3 replaces `setup-tor-guard-relay.sh`, and nothing needs migrating. Install the binary and run `sudo tor-relay-setup`. It reads your existing `/etc/tor/torrc` and opens the console. **Reconfigure** starts the wizard pre-filled from that torrc; existing `FamilyId`s are kept and bandwidth limits are carried over exactly. `/var/lib/tor-relay-setup` from 2.x can simply stay where it is.

## Security

- The review screen shows every privileged change and the complete torrc before anything is applied.
- **Supply chain:**
  - The Tor signing key is pinned by fingerprint and verified in-process, and the `tor` package must come from `deb.torproject.org`.
  - Release binaries, `.deb` packages, and archives carry `SHA256SUMS`, SBOMs, and [Sigstore-signed build-provenance attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations).
  - Builds are reproducible (`-trimpath`, fixed timestamps).
- ContactInfo, nickname, fingerprint, and FamilyId are **public**. Identity and family keys are secret: back them up (console → `b`) and share them only with your own relays.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```bash
make check         # golangci-lint, ShellCheck, shfmt, race tests, govulncheck
make integration   # real Tor apt setup, keygen and tor --verify-config in a Debian container
make demo          # re-record the GIFs above with VHS
```

CI runs the container integration test on every supported distribution (plus arm64) and also runs it weekly. See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture and how the tests are organised, and [docs/RELEASE.md](docs/RELEASE.md) for how releases are cut.

## References

- [Tor relay guide](https://community.torproject.org/relay/), [Debian/Ubuntu guard setup](https://community.torproject.org/relay/setup/guard/debian-ubuntu/), [exit relays](https://community.torproject.org/relay/setup/exit/), [exit DNS](https://community.torproject.org/relay/setup/exit/debian-ubuntu/)
- [Tor apt repository](https://support.torproject.org/little-t-tor/getting-started/installing/), [post-install](https://community.torproject.org/relay/setup/post-install/), [family IDs](https://community.torproject.org/relay/setup/post-install/family-ids/)
- [Relay requirements](https://community.torproject.org/relay/relays-requirements/), [expectations for relay operators](https://community.torproject.org/policies/relays/expectations-for-relay-operators/)
- [Bandwidth limits](https://support.torproject.org/relays/performance/bandwidth-limits/), [MetricsPort / overload](https://support.torproject.org/relays/performance/overloaded/)
- [ContactInfo Information Sharing Specification](https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/), [Relay Search](https://metrics.torproject.org/rs.html), [Onionoo](https://metrics.torproject.org/onionoo.html)

## License

[MIT](LICENSE)
