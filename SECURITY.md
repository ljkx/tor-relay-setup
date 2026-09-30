# Security policy

This project configures privileged services on internet-facing servers, so every change is treated as security-sensitive.

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x (latest release) | Yes |
| 1.0.0 betas | No. They don't verify reachability with tor ≥ 0.4.5 and don't install Debian security updates automatically; upgrade to 2.x. |

The script itself requires tor 0.4.9 or newer, the only series the Tor network still accepts.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through [GitHub's private vulnerability reporting](https://github.com/ljkx/tor-relay-setup/security/advisories/new). Include:

- the script version (`./setup-tor-guard-relay.sh --version`), distribution and codename
- the relay mode and the menu path or flags involved
- what an attacker can do, and the steps to reproduce

The maintainer aims to acknowledge reports within a week. Fixes are published as GitHub security advisories that credit the reporter, unless you prefer otherwise.

Vulnerabilities in **tor itself** belong to the Tor Project: see https://support.torproject.org/misc/bug-or-feedback/.

### What not to include

Never send relay identity or family keys, SSH keys, provider credentials, or unredacted logs. Sanitised `torrc` directives and error messages are enough. Remember that ContactInfo, nickname, fingerprint and FamilyId are public anyway.

## Verifying what you run

Release assets are built by the tag-triggered [release workflow](.github/workflows/release.yml) and come with:

- `SHA256SUMS`: `sha256sum --check SHA256SUMS`
- a Sigstore-signed SLSA build-provenance attestation: `gh attestation verify setup-tor-guard-relay.sh -R ljkx/tor-relay-setup`

Read the script before running it as root, and run `--dry-run` first.

## Security design

The script is designed to:

- install tor only from `deb.torproject.org`. The signing key is pinned by fingerprint and must be the only key in the downloaded file, and the apt candidate must come from the Tor repository and be ≥ 0.4.9.
- show every privileged change, and the complete `torrc`, before applying anything
- validate every `torrc` candidate with `tor --verify-config` (using Debian's service defaults) before it replaces the live file
- back up every file it replaces, and never overwrite relay identity or family keys
- install family keys `0600`, owned by `debian-tor`
- keep SSH reachable: detected SSH ports are allowed before UFW is enabled
- bind MetricsPort to localhost only, with a localhost-only policy
- collect no telemetry. It contacts only apt mirrors, `deb.torproject.org`, Onionoo (on request), and the directory authorities (optional IPv6 ping).

It is **not** designed to:

- harden a server that is already compromised, or replace general OS hardening
- manage provider or cloud firewalls
- give legal advice for running an exit relay
- set up bridges or onion services
- decommission a relay or delete its keys automatically

The development pipeline:

- pins every GitHub Action by commit SHA and runs workflows with least-privilege tokens
- audits workflows with zizmor
- installs lint and test tools from checksum-verified pinned releases
- runs weekly, so changes to the Tor repository or its key surface quickly
