# Contributing

Thanks for helping make relay operation safer.

This project changes privileged server configuration, so changes should be boring in the best way: small, easy to review, backed by Tor Project documentation, and tested before they ship.

## Ground rules

- Prefer official Tor Project documentation (and the tor source when the docs lag) over blog posts or forum snippets.
- Exit-relay behaviour must be explicit, opt-in, and documented.
- Never remove or overwrite operator-owned Tor state without a backup and a clear confirmation.
- Keep `--plain` working whenever a feature uses fzf.
- Keep `--dry-run` useful and non-mutating.
- Keep `--uninstall` limited to traces of this tool, never Tor itself.

## Development setup

Everything runs on Linux x86_64 (WSL works). The toolchain is pinned and checksum-verified:

```bash
make tools   # installs ShellCheck, shfmt and bats into .tools/
make check   # lint + all local test suites
make fmt     # apply shfmt formatting
```

| Target | What it runs |
| --- | --- |
| `make lint` | `bash -n`, ShellCheck (config in `.shellcheckrc`), `shfmt --diff` (style in `.editorconfig`) |
| `make test` | `tests/unit.bats`, `tests/system.bats` (PATH stubs), `tests/e2e.bats` (scripted `--dry-run --plain` sessions) |
| `make integration` | `tests/integration/tor-repo.sh` in a Debian container: real Tor apt setup and `tor --verify-config` of generated torrc files |

CI runs the same targets, then repeats the dry-run and integration suites on Debian 12/13 and Ubuntu 22.04/24.04/26.04 (plus arm64).

### Writing tests

- Source the script through `load test_helper` and `load_script`. In source-only mode the script installs no traps or strict-mode options, so bats keeps its failure detection.
- `! cmd` only fails a bats test when it is the last command; use `refute cmd` instead.
- Stub system commands with `use_stubs` and `write_stub` rather than touching the host.
- New prompts shift the answers in `tests/e2e.bats`; update those sessions in the same change.

## Pull requests

- Link the Tor documentation that justifies behaviour changes.
- Include dry-run output or screenshots for UI changes.
- Add or update tests for parsing, generation, or cleanup logic.
- Add a `CHANGELOG.md` entry under **Unreleased**.
- Say which manual VPS tests you ran, and which still need doing.
- Never include secrets, real relay identity keys, private operator emails, or private server IPs in fixtures.

Releases are cut by pushing a tag; see [docs/RELEASE.md](docs/RELEASE.md).
