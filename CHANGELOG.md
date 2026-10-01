# Changelog

All notable changes to this project are documented here.

## Unreleased

Version 3 rewrites the tool as a single static Go binary with a Bubble Tea interface. It replaces `setup-tor-guard-relay.sh`. Existing relays need no migration: the console reads the current torrc, and **Reconfigure** keeps its family and bandwidth limits.

### Added

- **Setup wizard** (Bubble Tea v2 + Huh):
  - A step indicator with back-navigation, inline validation, a **live torrc preview**, and a panel of facts about the server.
  - Those facts are detected concurrently at start-up: release, memory, Tor repository availability, IPv6 reachability, firewall, and SSH ports.
- **Review screen**: every setting, a numbered list of every privileged change, and the full highlighted torrc. `s` saves the answers as `relay.toml`.
- **Apply screen**:
  - A live checklist with per-step timings and notes, an overall progress bar driven by apt's `APT::Status-Fd`, and a collapsible output log written to `/var/log/tor-relay-setup/`.
  - On failure: a clear error, a hint, and retry.
  - Waits for Tor's reachability self-test in the background, with a timer.
- **Operator console**:
  - Health, family, traffic, and Tor Metrics cards that load concurrently, plus a recent-log panel.
  - A live log viewer, relay family management (create, rotate, import, share, remove, legacy MyFamily cleanup), and an editor for settings, all verified by tor before anything is written.
  - Restart, reload, stop and start with confirmation; Tor updates with progress; key backups; and **Reconfigure** pre-filled from the running torrc.
- **`apply --config relay.toml [--yes]`** for repeatable, unattended setups; example in `docs/examples/relay.toml`.
- **`status [--json]`**: a machine-readable health report, with exit code 1 when something needs attention.
- **`--plain`**: accessible line-by-line prompts and output, used automatically without a terminal.
- Light and dark terminal themes in Tor purple, and `NO_COLOR` support.
- **Distribution:**
  - GoReleaser builds static `amd64`/`arm64` binaries, `.tar.gz` archives, and `.deb` packages.
  - Every release ships SBOMs, `SHA256SUMS`, and Sigstore build-provenance attestations.
  - `install.sh` downloads and verifies a release.

### Changed

- **Speed:**
  - One `apt-get update` and one install transaction instead of up to four updates and eight installs.
  - apt waits out a held lock (`DPkg::Lock::Timeout`) instead of failing on a fresh VPS.
  - The signing key is fetched and verified in-process, so gpg and wget are no longer needed.
  - Server checks take about 55 ms, and a full dry run finishes in under a second.
  - No more "press Enter" command windows.
- **IPv6 check:** now a concurrent TCP probe of the directory authorities' ORPorts. It works without ICMP or root, and the result appears next to each detected address.
- **Repository origin check:** the apt candidate must match the Tor repository URI exactly; look-alike paths are rejected.
- **Version:** the build version comes from the release tag; there is no version string in the code.

### Removed

- The Bash script, its fzf interface, and the bats test suites. They are replaced by Go packages with unit, fake-host, end-to-end and container integration tests.

### Development

- Go 1.27 module with `internal/host` as the only code that touches the system (real, dry-run, and fake implementations).
- golangci-lint v2 (including gosec), govulncheck, ShellCheck, and shfmt, all pinned.
- **CI:** race-detector tests, amd64/arm64 builds, fixture-driven end-to-end dry runs of the binary, the real installation path on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (plus arm64), and zizmor.
- The README GIFs are recorded with VHS from `docs/demo/*.tape`; a Demo workflow re-records them on pull requests that touch the UI.

## v2.0.0-beta.1 - 2026-10-01

### Added

- **Relay families with FamilyId keys (Tor 0.4.9 "Happy Families").** Guided setup can create a family key with `tor --keygen-family` or import one copied from another relay. The key is installed `0600` for `debian-tor` in the Tor key directory, and `FamilyId` is written to torrc. The operator console gains a *Relay family* menu (status, create/rotate, import, share instructions, remove), and the old MyFamily editor stays available as a legacy option.
- Because `tor --verify-config` does not check family keys, the script verifies that every `FamilyId` has an installed key. It also reports family warnings Tor logs after a restart.
- Guided **CIISS v3 ContactInfo** builder (`email:… url:… proof:uri-familyid-ed25519 hoster:… ciissversion:3`), including where to publish the family ID for the `url` proof. Free-form ContactInfo is still available.
- Optional **MetricsPort** on `127.0.0.1:9035` with `MetricsPortPolicy accept 127.0.0.1`, in both guided setup and the configuration editor.
- Installing or updating tor now refuses versions older than **0.4.9**, which the directory authorities reject. The health check flags old versions too.
- Warns when the server has less RAM than the Tor Project minimum for the chosen relay type (512 MiB, or 1.5 GiB for exits).
- Directory status shows the family IDs published in Onionoo.

### Changed

- Toggling `Sandbox` in the configuration editor restarts Tor instead of reloading it, because Tor rejects Sandbox changes on reload.
- Identity-key backups note that they include family keys.
- fzf panels follow the terminal's own background colour instead of a hard-coded near-black one.
- Dry runs name the Tor user and the generated key file, and say what would be verified, instead of printing placeholders and warnings.
- The README's static screenshots are replaced by a recorded fzf-mode demo (`docs/demo/setup.tape`, VHS). A Demo workflow re-records it on pull requests that change the UI.

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

### Development

- Pinned, checksum-verified toolchain (`scripts/install-dev-tools.sh`): ShellCheck 0.11.0, shfmt 3.14.1, bats-core 1.14.0.
- Tests moved to bats: unit, stubbed-system, and scripted end-to-end dry-run suites, plus a container integration test that performs the real Tor apt setup and runs `tor --verify-config` on generated torrc files.
- CI runs on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (amd64) plus Debian 13 arm64, weekly as well as on pushes, with actions pinned by commit SHA, least-privilege tokens, and zizmor workflow auditing.
- Tag-driven release workflow publishes the script with `SHA256SUMS` and a Sigstore-signed SLSA provenance attestation.
- Dependabot keeps GitHub Actions current with a 7-day cooldown.
- The script's `run` helper is now `run_cmd`, and strict mode and traps are only installed when the script runs rather than when tests source it.
- Shell sources are formatted with shfmt.

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
