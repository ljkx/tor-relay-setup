# Release guide

Releases are built and published by [`.github/workflows/release.yml`](../.github/workflows/release.yml) when a `v*` tag is pushed. Maintainers only prepare the version and the tag.

## 1. Prepare

1. Set `VERSION="X.Y.Z[-pre]"` near the top of `setup-tor-guard-relay.sh`.
2. In `CHANGELOG.md`, rename **Unreleased** to `## vX.Y.Z[-pre] - YYYY-MM-DD`. The release workflow uses this section as the release notes and fails if it is missing.
3. Run the local checks and merge through a pull request:

   ```bash
   make check
   ```

## 2. Tag

```bash
git switch main && git pull --ff-only
git tag -s vX.Y.Z -m vX.Y.Z   # -s signs the tag; use -a if you have no signing key
git push origin vX.Y.Z
```

## 3. What the workflow does

1. Runs the full CI workflow (lint, tests, distro matrix, zizmor).
2. Checks that the tag equals `VERSION` and that the changelog has a matching section.
3. Builds `dist/setup-tor-guard-relay.sh` and `dist/SHA256SUMS` with `make dist`.
4. Signs a SLSA build-provenance attestation for the script with `actions/attest` (Sigstore).
5. Creates the GitHub release. Tags with a `-` suffix (for example `v2.0.0-beta.1`) become pre-releases.

The job runs in the `release` environment, so you can require a reviewer in **Settings → Environments** before anything is published.

## 4. Verify

```bash
gh release download vX.Y.Z -R ljkx/tor-relay-setup
sha256sum --check SHA256SUMS
gh attestation verify setup-tor-guard-relay.sh -R ljkx/tor-relay-setup
```

Then confirm the README quick-start version matches the new tag.
