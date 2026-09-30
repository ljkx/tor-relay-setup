## Summary

<!-- What changes for relay operators, and why? Link the issue if there is one. -->

## Tor documentation

<!-- Link the official Tor Project page or tor source that backs any change to relay behaviour. Write "n/a" for tooling/docs-only changes. -->

## Safety

- [ ] `--dry-run` stays non-mutating.
- [ ] `--plain` still works when fzf is missing.
- [ ] Tor state, relay identity keys, and operator-owned config are never removed or overwritten without a backup and an explicit confirmation.
- [ ] Every new privileged change is listed in the final review screen.

## Checks

- [ ] `make check` passes locally (pinned ShellCheck, shfmt, and bats).
- [ ] New parsing, generation, or cleanup logic has tests in `tests/`.
- [ ] `CHANGELOG.md` has an entry under **Unreleased**.
- [ ] Anything that still needs a real VPS test is described below.

## Manual VPS testing

<!-- Distro, relay mode, and what you verified on a real server. -->
