# Changelog

All notable changes to this project are documented here.

## v3.2.0 - 2026-10-02

Version 3.2 is for operators of many relays, and of every kind of relay: several relays per server, fleets with a shared dashboard, alerts, bridges, exit tools, and offline identity keys.

**Upgrade:** `sudo tor-relay-setup self-update`. Nothing needs migrating.

**How this release was tested:**
- CI installs a real relay unattended on a fresh Ubuntu 24.04 VM, adds a second relay on the same server, and checks `status --all`, `fleet-probe`, Prometheus output, an alert for a stopped relay, the hardened alert unit, and uninstall.
- Every generated torrc layout (bridges, exit policies, the exit notice, OfflineMasterKey) is checked with a real tor 0.4.9 `--verify-config`.
- obfs4 and WebTunnel bridges ran locally with the real transports, and the offline-key cycle ran with real tor.
- **Not yet tested on a real server:**
  - an obfs4 port below 1024 under systemd and AppArmor;
  - certbot issuance;
  - WebTunnel end to end through Tor Browser;
  - tor picking up a renewed signing key on reload;
  - fleet runs against real hosts.

  Please report what you find.

### Added

- **Several relays per server.** Each extra relay is a Debian tor instance (`tor-instance-create`, `tor@NAME`).
  - Set it up with `relay.instance` / `--instance`, or with the console's new **Add a relay** (`n`).
  - The tool chooses free ORPorts and MetricsPorts (9036 upwards) and installs the server's family key; a second family on one server is refused.
  - It warns above the directory authorities' 8 relays per IPv4 address.
  - The console gains a relay switcher (`[` `]`, `1`–`9`) and an all-relays health line. `status --all` reports every relay; its JSON is an array.
- **Kernel tuning** (`system.tuning`, offered above about 100 Mbit/s): a wider ephemeral port range, a larger conntrack table, and a `LimitNOFILE` check, each with its reason in the written file.
- **Fleets:**
  - **Inventory:** `fleet.toml` names a base config, a nickname template (`MyRelay{n}`), and one `[[host]]` per relay with per-host overrides. Everything is validated before connecting.
  - **Apply:** `apply --inventory` runs the family host first, then `--parallel N` servers at a time, over shared SSH connections.
  - **Dashboard:** `fleet` probes every relay every 10 seconds and asks Tor Metrics in bulk. It shows totals (relays running, consensus weight share, guard/exit probability, live and 30-day traffic), a sortable and filterable relay table with details, and a "Needs attention" panel (unreachable hosts, relays out of the consensus, missing or mismatched family keys, version drift, lost flags).
  - **Rolling actions:** `fleet restart|reload|update-tor` works through the relays one at a time, waiting until each is back. `fleet status --format text|json|prometheus` gives the same data without the dashboard.
  - **New commands:** `tor restart|reload|update` (also with `--instance`), and the plumbing command `fleet-probe`.
- **Overload detection:** the console shows tor's overload signals and Relay Search's overloaded mark, each with Tor's remedy. The signals are dropped circuit handshakes, out-of-memory, TCP port exhaustion, sockets near the limit, and rate limiting.
- **Alerts:** `alert run|test|install|uninstall`.
  - **Notifiers:** ntfy, webhooks (JSON or Slack-compatible), email through `sendmail`, or any command.
  - **What it reports:** the service stopping, an unreachable ORPort, an unsupported tor, a missing family key, the relay dropping out of the consensus, lost flags, overload, and an accounting budget that will run out early.
  - **When:** when a problem appears, as a reminder while it lasts, and when it resolves; per relay instance. `alert install` adds a hardened systemd timer.
- **Monitoring:** `docs/monitoring/` covers the textfile collector, safe MetricsPort scraping, Prometheus alerting rules, and a Grafana dashboard. `status --format prometheus` adds tor's load counters, the accounting budget (read from tor's state file), and Relay Search's overload mark.
- **Bridges:**
  - **obfs4:** `obfs4proxy`, or `lyrebird` where available. Ports below 1024 get the capability, the unit drop-in, and AppArmor access they need.
  - **WebTunnel:** the Tor Project's `webtunnel` package, with a managed nginx site (checked with `nginx -t`) and either existing certificates or certbot after confirmation.
  - **Sharing:** the console's **Bridge line** view (`i`) shows the line to share and links to the reachability scan and status page. Tor Metrics lookups use only the hashed fingerprint.
- **Exit tools:**
  - **Exit policy editor** (`x`, and in the wizard): Tor's built-in reduced policy, web-only, default, or validated custom rules, plus an IPv6 exit toggle.
  - **Exit notice:** a page served by tor itself on port 80.
  - **Templates:** abuse-reply templates in `docs/examples/`.
- **Identity keys:** `keys status|offline|renew` (console `k`).
  - Signing-certificate expiry is parsed and verified in Go, and `status`, `alert` and the console warn a week ahead.
  - `keys offline` exports the master key and sets `OfflineMasterKey 1`. The master key is removed only after you confirm the copy's SHA-256.
  - `keys renew` makes or installs the next signing key.
- **ContactInfo proofs:** `proof [--all] [--check]` (console `c`) prints the CIISS `ed25519-family-id.txt` file for your website. `--check` verifies the published copy over HTTPS, refusing redirects to another domain and flagging any secret key in the file.

### Changed

- Prometheus series carry a `tor_instance` label (`instance` would clash with Prometheus's own target label).
- `uninstall` also removes the alert timer.
- The console's service actions, the new `tor` command, and fleet rollouts share one implementation, which works on any tor instance.

### Security

- The bridge line is never written to `status --json`, so it does not reach monitoring systems or fleet probes.
- Fleet runs keep ssh host-key checking untouched, quote every remote argument, and never print family keys.
- Alert error messages never include tokens, URL paths or response bodies.

## v3.1.0 - 2026-10-01

**Upgrade:** run `curl -fsSLO https://raw.githubusercontent.com/ljkx/tor-relay-setup/main/install.sh && sudo bash install.sh` once. From now on, `sudo tor-relay-setup self-update` does it for you.

### Added

- **Live console:**
  - The dashboard refreshes on its own: service and health every 30 seconds, Tor Metrics every 30 minutes. The footer shows when the data was last updated.
  - **Live traffic** from the MetricsPort every 2 seconds: read and written rates, a two-minute sparkline, and open OR connections.
  - The Tor Metrics card shows **a month of traffic history** from Onionoo as a sparkline, with totals in and out.
  - The header shows when a newer release is available. This checks the GitHub API at most once a day, and never in dry runs or with `TOR_RELAY_SETUP_NO_UPDATE_CHECK=1`.
- **`self-update [--check]`** installs the newest release after the same checks as `install.sh`:
  - the SHA-256 is verified against `SHA256SUMS`, plus `gh attestation verify` when the GitHub CLI is installed;
  - the binary is replaced atomically;
  - a `.deb` install is left to apt;
  - `--check` exits 10 when an update exists.
- **Fleet apply:** `apply --config relay.toml --host user@relay1 --host user@relay2 [--keep-going]` applies one file over your own SSH:
  - With `family.mode = "generate"`, the first host creates the family key and the others import it.
  - It checks that each host has the same CPU architecture, and needs root or passwordless sudo on the remote side.
- **`status --format prometheus`:** `tor_relay_setup_*` gauges for node_exporter's textfile collector. `--format text|json` replaces `--json`, which still works.
- **`uninstall`** now also offers to remove the binary itself (`--yes` to skip the question), and points `.deb` installs to apt.
- The release workflow can publish a **signed apt repository** to GitHub Pages. It is opt-in, and turns on once a maintainer adds the signing key (see `docs/RELEASE.md`).

### Changed

- The review screen shows the bandwidth rate and the monthly cap on separate lines, and long entries in **What will change** wrap with a hanging indent.
- Usage text lists all exit codes and environment variables.

### Fixed

- `install.sh` selected the archive line in `SHA256SUMS` by prefix, so it also tried to check the SBOM listed after it and refused to install. It now matches the exact file name. A CI job runs the installer against the newest release on Debian and Ubuntu.
- Background updates (reports, Tor Metrics results) that arrived while another console view was open were dropped. They now always reach the dashboard.

### Development

- **Real install in CI:** every pull request runs `apply --yes` unattended on a fresh Ubuntu 24.04 VM, then checks:
  - systemd, UFW, the MetricsPort, and the running relay through `status --json`;
  - Prometheus output;
  - an idempotent second apply that keeps the family;
  - `uninstall`.
- **Tor canary:** a nightly workflow runs the integration test against Tor's `nightly-main` and `experimental` packages.
- **TUI snapshot tests** (`internal/tui/testdata/*.golden`) for the console, review, and apply screens.
- **CodeQL** (Go and Actions) and **OpenSSF Scorecard** workflows.
- `main` and `v*` tags are protected by rulesets, and the `release` environment only accepts `v*` tags.
- `docs/demo/fakerelay` feeds the console demo with live MetricsPort and Onionoo data.

## v3.0.0 - 2026-10-01

Version 3 rewrites the tool as a single static Go binary with a Bubble Tea interface. It replaces `setup-tor-guard-relay.sh`. Existing relays need no migration: the console reads the current torrc, and **Reconfigure** keeps its family and bandwidth limits.

**Install:** `curl -fsSLO https://raw.githubusercontent.com/ljkx/tor-relay-setup/main/install.sh && sudo bash install.sh`, or use the `.deb` for your architecture below. Start with `tor-relay-setup --dry-run`.

**How this release was tested:**
- The real installation path ran in CI on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (amd64) and Debian 13 (arm64): Tor repository and key verification, one apt transaction, `tor --keygen-family`, `tor --verify-config`, and an idempotent second run.
- Full dry runs of the binary ran against fixture relays.
- 670 unit and model tests passed.
- Steps that need a real server (systemd, the firewall, and Tor's outside reachability test) are covered by fake-host tests, but not yet by a public VPS run. Please report anything unexpected through the issue tracker.

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
