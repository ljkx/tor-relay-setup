# Security policy

This project configures privileged services on internet-facing servers, so every change is treated as security-sensitive.

## Supported versions

| Version | Supported |
| --- | --- |
| 3.x (latest release, Go binary) | Yes |
| 2.x (Bash script) | No. Replaced by 3.x; nothing needs migrating. |
| 1.0.0 betas | No. They don't verify reachability with tor ≥ 0.4.5 and don't install Debian security updates automatically. |

The tool requires tor 0.4.9 or newer, the only series the Tor network still accepts.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through [GitHub's private vulnerability reporting](https://github.com/ljkx/tor-relay-setup/security/advisories/new). Include:

- the output of `tor-relay-setup version`, plus your distribution and codename
- the relay mode and the screen, subcommand, or flags involved
- what an attacker can do, and the steps to reproduce

The maintainer aims to acknowledge reports within a week. Fixes are published as GitHub security advisories that credit the reporter, unless you prefer otherwise.

Vulnerabilities in **tor itself** belong to the Tor Project: see https://support.torproject.org/misc/bug-or-feedback/.

### What not to include

Never send relay identity or family keys, SSH keys, provider credentials, or unredacted logs. Sanitised `torrc` directives, `tor-relay-setup status --json` output, and error messages are enough. Remember that ContactInfo, nickname, fingerprint, and FamilyId are public anyway.

## Verifying what you run

Release artifacts are built by the tag-triggered [release workflow](.github/workflows/release.yml) with GoReleaser, and come with:

- `SHA256SUMS`: `sha256sum --ignore-missing --check SHA256SUMS`
- a Sigstore-signed SLSA build-provenance attestation for every archive and `.deb`: `gh attestation verify <file> -R ljkx/tor-relay-setup`
- SPDX SBOMs listing every Go module compiled into the binary

[`install.sh`](install.sh) performs the checksum check, plus the attestation check when the GitHub CLI is installed. Builds are reproducible: static, `-trimpath`, with commit timestamps.

Run `tor-relay-setup --dry-run` first. It performs every read (including the repository and key checks) but changes nothing, and it does not need root.

## Security design

The tool is designed to:

- install tor only from `deb.torproject.org`:
  - The signing key is fetched and verified in-process against its pinned fingerprint, and it must be the only key in the file.
  - The apt candidate must come from the Tor repository, with an exact URI match (look-alike paths are rejected), and must be ≥ 0.4.9.
- show every privileged change, and the complete `torrc`, before applying anything. `--dry-run` reports the same commands and writes without performing them.
- validate every `torrc` candidate with `tor --verify-config` (using Debian's service defaults) before it replaces the live file
- back up every file it replaces, write files atomically, and never overwrite relay identity or family keys
- install family keys `0600`, owned by `debian-tor`, and check that every `FamilyId` has its key (tor's own check does not)
- keep SSH reachable: detected SSH ports are allowed before UFW is enabled
- bind MetricsPort to localhost only, with a localhost-only policy
- restore `/etc/resolv.conf`, symlink included, if DNS stops resolving after the switch to Unbound
- archive keys through `os.Root`, so a swapped-in symlink cannot pull other files into a backup
- refuse the fixture override (`TOR_RELAY_SETUP_ROOT`) outside `--dry-run`
- collect no telemetry. It contacts only apt mirrors, `deb.torproject.org`, Onionoo (for directory status), and the IPv6 directory authorities (optional reachability check).

It is **not** designed to:

- harden a server that is already compromised, or replace general OS hardening
- manage provider or cloud firewalls
- give legal advice for running an exit relay
- set up bridges or onion services
- decommission a relay or delete its keys automatically

The development pipeline:

- pins every GitHub Action by commit SHA, runs workflows with least-privilege tokens, and audits them with zizmor
- runs golangci-lint (including gosec) and govulncheck on every change
- installs lint tools from checksum-verified pinned releases; Go modules are verified (`go mod verify`) before a release build
- tests the real installation path in containers on every supported distribution, weekly as well as on each change
- updates dependencies through Dependabot, with a 7-day cooldown on new releases
