# Changelog

All notable changes to this project are documented here.

## Unreleased

### Fixed

- ORPort reachability checks now recognise the self-test notices of Tor 0.4.5 and later, which include the tested address. Previously a reachable relay was always reported as "not verified".
- The outbound IPv6 check pings the current IPv6 directory authorities; the old tor26 address was retired.
- Debian unattended-upgrades now match the `<codename>-security` suite, so Debian security updates are actually installed automatically.
- Monthly traffic budgets treat `TB`/`GB` as decimal provider units and `TiB`/`GiB`/`GBytes` as binary, and pace over a 31-day month. `10TB` previously produced an `AccountingMax` about 10% above the real quota.
- Candidate `torrc` files are verified with Debian's `tor-service-defaults-torrc`, matching what `tor@default` checks before it starts.
- The Tor signing key file must contain exactly one primary key before it is installed into the apt keyring.
- Declining the "DELETE SCRIPT TRACES" confirmation no longer silently drops the report cleanup the operator selected.
- The fzf review panel renders colours instead of showing raw escape codes.
- Dropped the obsolete `apt-transport-https` prerequisite.

## v1.0.0-beta.4 - 2026-05-18

### Changed

- Added fzf command-output windows for apt, systemctl, firewall, and service actions, with local command logs for the current run.
- Ported service status, recent logs, live log follow, repair logs, directory status, MyFamily status, backup listing, and command-log review into fzf/detail panels when available.
- Improved fzf cancel/back behavior and made deletion wording less surprising.
- Hardened plain checklist validation so hidden cleanup actions cannot be selected by typing arbitrary keys.
- Validates the local relay fingerprint before auto-pinning it in MyFamily.
- Verifies a selected torrc backup before restoring it and avoids overwriting identity-key backup archives in the same run.

## v1.0.0-beta.3 - 2026-05-18

### Changed

- `fzf` is now offered directly at startup, and accepting installs it before the guided setup flow so the current run can use the polished selector interface.
- Yes/no choices and guided text entry now use the fzf interface when available, keeping the setup closer to an `archinstall`-style workflow.
- The MyFamily manager now explains that leading `$` prefixes are Tor's documented fingerprint syntax in `torrc`.

## v1.0.0-beta.2 - 2026-05-18

### Fixed

- Lock acquisition now falls back to `/tmp/tor-relay-setup.lock` when `/run/lock/tor-relay-setup.lock` cannot be opened on a VPS.

## v1.0.0-beta.1 - 2026-05-18

First public beta release.

### Added

- Interactive Guard/middle and exit relay setup flow for Debian/Ubuntu VPSes.
- Existing-relay operator console with MyFamily management, health checks, service controls, logs, backups, package tools, repair tools, and script-trace cleanup.
- Tor Project apt repository setup with signing-key fingerprint verification.
- Apt candidate origin check to ensure `tor` comes from `deb.torproject.org`.
- Candidate `torrc` verification before replacing the live config.
- Monthly traffic budget calculator for steady `RelayBandwidthRate`, `RelayBandwidthBurst`, and `AccountingMax` planning.
- Optional Nyx, UFW, fzf, unattended-upgrades, and Unbound setup.
- WSL Ubuntu dry-run screenshots in the README.
- GitHub Actions CI for syntax, ShellCheck, function tests, and help/version smoke checks.

### Hardened

- Safer backup naming and atomic file replacement.
- Single-run lock for mutating flows.
- Cleanup mode that removes script traces only, not Tor state.
- IPv6 validation and manual-override warnings.
- UFW inactive detection and SSH port preservation.
- Exit relay readiness confirmations.

### Known Beta Boundaries

- The script is interactive and intentionally does not provide a full unattended install mode.
- WSL/container tests cover deterministic logic; real relay reachability still needs a VPS with reachable ORPort and provider firewall access.
- `fzf` is optional. Plain mode remains the fallback and should continue to work everywhere.
