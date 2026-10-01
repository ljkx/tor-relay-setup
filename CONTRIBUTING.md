# Contributing

Thanks for helping make relay operation safer.

This tool changes privileged server configuration, so changes should be boring in the best way: small, easy to review, backed by Tor Project documentation, and tested before they ship.

## Ground rules

- Prefer official Tor Project documentation (and the tor source when the docs lag) over blog posts or forum snippets.
- Exit-relay behaviour must be explicit, opt-in, and documented.
- Never remove or overwrite operator-owned Tor state without a backup and a clear confirmation.
- Every privileged change must appear in the review screen (`plan.Step.Changes`) and in `--dry-run`.
- Keep `--plain` working: every prompt needs an accessible fallback.
- `uninstall` touches only this tool's own state, never Tor.

## Architecture

```text
cmd/tor-relay-setup     CLI: subcommands, flags, root checks, status output
internal/host           the only code that runs commands or writes files (Local, DryRun, Fake)
internal/plan           Setup + Facts -> ordered Steps; the executor emits events
internal/config         relay.toml model, validation, reading an existing torrc back into answers
internal/relay          torrc model and rendering, validators, quota pacing, CIISS, self-test parsing, tor --verify-config
internal/torproject     signing-key verification, deb822 source, candidate origin, version floor
internal/apt            one-transaction apt with APT::Status-Fd progress and lock waiting
internal/system         concurrent fact detection, firewall commands, /proc listeners, IPv6 reachability
internal/family         FamilyId keys: validate, generate with tor, install, list
internal/service        systemctl and journalctl, reachability wait, family warnings
internal/onionoo        Tor Metrics client
internal/status         the health report behind the console and status --json
internal/tui            Bubble Tea v2 app: wizard (huh forms), review, apply, console
internal/integration    real-system test, containers only
```

Two rules keep this testable:

1. **Nothing outside `internal/host` touches the machine.** Steps receive a `host.Host`, so a dry run (`host.DryRun`) and the tests (`host.Fake`) see exactly the commands and writes a real run would make.
2. **The UI only observes.** `plan.Run` emits events. The TUI, the plain runner, and the tests render those events differently, but nothing in the UI decides what gets changed.

## Development

Go 1.27+ on Linux x86_64; WSL works.

```bash
make help          # all targets
make check         # golangci-lint (+ gofmt/goimports), ShellCheck, shfmt, race tests, govulncheck
make build         # static binary in bin/
make integration   # real Tor apt setup, keygen, verify-config in a Debian container
make demo          # re-record docs/assets/*.gif (needs vhs, ttyd, ffmpeg; as root add VHS_NO_SANDBOX=true)
make snapshot      # local GoReleaser build of every release artifact
```

`scripts/install-dev-tools.sh` installs the pinned, checksum-verified golangci-lint, ShellCheck, and shfmt into `.tools/`. CI uses the same script.

### Trying the UI without a server

`docs/demo/demo-env.sh` builds a throwaway fixture: a running relay, or a fresh server with `fresh`. It also puts stub `systemctl`/`journalctl`/`tor` commands on PATH:

```bash
make build
source docs/demo/demo-env.sh          # or: source docs/demo/demo-env.sh fresh
bin/tor-relay-setup --dry-run         # console on the fixture relay
```

The binary reads the fixture through `TOR_RELAY_SETUP_ROOT`, and it refuses that variable outside `--dry-run`.

### Tests

- Steps and helpers are tested against `host.NewFake()`: assert on `Fake.Ran(...)`, `Fake.Files`, and the plan events.
- TUI tests exercise models directly (`update`/`view`) with ANSI stripped; they do not need a terminal.
- `internal/integration` runs the real Tor repository setup, a single apt transaction, `tor --keygen-family`, and `tor --verify-config` on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (plus arm64) in CI.
- The **Demo** workflow re-records the README GIFs on every PR that touches the UI and attaches them as artifacts. Look at them, and commit new GIFs when the UI changed.

## Pull requests

- Link the Tor documentation that justifies behaviour changes.
- Add or update tests; `make check` must pass.
- Add a `CHANGELOG.md` entry under **Unreleased**.
- Say which manual VPS tests you ran, and which still need doing.
- Never include secrets, real relay identity keys, private operator emails, or private server IPs in fixtures.

Releases are cut by pushing a tag; see [docs/RELEASE.md](docs/RELEASE.md).
