# Release guide

Releases are built and published by [`.github/workflows/release.yml`](../.github/workflows/release.yml) with [GoReleaser](https://goreleaser.com) when a `v*` tag is pushed. Maintainers only prepare the changelog and the tag. The version comes from the tag (`-X main.version`), so there is no version string to edit in the code.

## 1. Prepare

1. In `CHANGELOG.md`, rename **Unreleased** to `## vX.Y.Z[-pre] - YYYY-MM-DD`. The release workflow uses this section as the release notes and fails if it is missing.
2. Optionally check the artifacts locally:

   ```bash
   make check
   make snapshot   # builds everything into dist/ without publishing
   ```

3. Merge through a pull request.

## 2. Tag

```bash
git switch main && git pull --ff-only
git tag -s vX.Y.Z -m vX.Y.Z   # -s signs the tag; use -a if you have no signing key
git push origin vX.Y.Z
```

## 3. What the workflow does

1. Runs the full CI workflow: lint, tests, vulnerability scan, cross-builds, end-to-end dry runs, the container integration matrix, and zizmor.
2. Takes the release notes from the changelog section matching the tag.
3. Builds with GoReleaser (`.goreleaser.yaml`):
   - static `linux/amd64` and `linux/arm64` binaries (`CGO_ENABLED=0`, `-trimpath`, commit timestamps for reproducibility)
   - `.tar.gz` archives and `.deb` packages
   - SPDX SBOMs (syft) and `SHA256SUMS`
4. Signs SLSA build-provenance attestations for every archive and `.deb` with `actions/attest` (Sigstore).
5. Publishes the GitHub release. Tags with a `-` suffix (for example `v3.0.0-beta.1`) become pre-releases.

The job runs in the `release` environment, so you can require a reviewer in **Settings → Environments** before anything is published.

## 4. Verify

```bash
gh release download vX.Y.Z -R ljkx/tor-relay-setup
sha256sum --ignore-missing --check SHA256SUMS
gh attestation verify tor-relay-setup_X.Y.Z_linux_amd64.tar.gz -R ljkx/tor-relay-setup
TOR_RELAY_SETUP_VERSION=vX.Y.Z sudo -E bash install.sh   # the documented installer path
```

Then confirm the README's `.deb` example uses the new version.
