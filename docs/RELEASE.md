# Release guide

Releases are built and published by [`.github/workflows/release.yml`](../.github/workflows/release.yml) with [GoReleaser](https://goreleaser.com) when a `v*` tag is pushed. Maintainers only prepare the changelog and the tag. The version comes from the tag (`-X main.version`), so there is no version string to edit in the code.

## 1. Prepare

1. In `CHANGELOG.md`, rename **Unreleased** to `## vX.Y.Z[-pre] - YYYY-MM-DD`. The release workflow uses this section as the release notes and fails if it is missing.
2. Optionally check the artifacts locally:

   ```bash
   make check
   make snapshot   # builds everything into dist/ without publishing
   ```

3. Merge through a pull request. `main` is protected by a ruleset: changes land through pull requests whose required checks pass, and force-pushes and deletion are blocked.

## 2. Tag

```bash
git switch main && git pull --ff-only
git tag -s vX.Y.Z -m vX.Y.Z   # -s signs the tag (see "Signed tags" below)
git push origin vX.Y.Z
```

A second ruleset protects `v*` tags: once pushed, a release tag cannot be moved or deleted.

## 3. What the workflow does

1. Runs the full CI workflow: lint, tests, vulnerability scan, cross-builds, end-to-end dry runs, a real install on an Ubuntu VM, the container integration matrix, and zizmor.
2. Takes the release notes from the changelog section matching the tag.
3. Builds with GoReleaser (`.goreleaser.yaml`):
   - static `linux/amd64` and `linux/arm64` binaries (`CGO_ENABLED=0`, `-trimpath`, commit timestamps for reproducibility)
   - `.tar.gz` archives and `.deb` packages
   - SPDX SBOMs (syft) and `SHA256SUMS`
4. Signs SLSA build-provenance attestations for every archive and `.deb` with `actions/attest` (Sigstore).
5. Publishes the GitHub release. Tags with a `-` suffix (for example `v3.0.0-beta.1`) become pre-releases.
6. When the apt repository is set up (below), builds, signs, and deploys it to GitHub Pages.

The publish job runs in the `release` environment, which only accepts `v*` tags and waits for a maintainer's approval in the run's summary page before anything is published.

## 4. Verify

```bash
gh release download vX.Y.Z -R ljkx/tor-relay-setup
sha256sum --ignore-missing --check SHA256SUMS
gh attestation verify tor-relay-setup_X.Y.Z_linux_amd64.tar.gz -R ljkx/tor-relay-setup
TOR_RELAY_SETUP_VERSION=vX.Y.Z sudo -E bash install.sh   # the documented installer path
sudo tor-relay-setup self-update --check                  # an older install sees the new release
```

Then confirm the README's `.deb` example uses the new version.

## Signed tags

Git can sign tags with the SSH key you already push with. GitHub shows such tags as **Verified** once the key is also registered as a signing key:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global tag.gpgSign true
gh ssh-key add ~/.ssh/id_ed25519.pub --type signing --title "tag signing"
```

Check a tag with `git tag -v vX.Y.Z` (this needs `gpg.ssh.allowedSignersFile` to list your key).

## apt repository (optional)

The release workflow can publish a signed apt repository to <https://ljkx.github.io/tor-relay-setup/>, so servers get updates through `apt upgrade`. It is off until a signing key exists. The `apt-repo` job is skipped while the repository variable `APT_SIGNING_KEY_FINGERPRINT` is empty.

One-time setup, on a trusted machine:

```bash
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key 'tor-relay-setup apt repository' ed25519 sign 3y
fpr=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')
gpg --armor --export-secret-keys "$fpr" > apt-signing-key.asc   # keep an offline backup
gh secret set APT_SIGNING_KEY -R ljkx/tor-relay-setup < apt-signing-key.asc
gh variable set APT_SIGNING_KEY_FINGERPRINT -R ljkx/tor-relay-setup --body "$fpr"
rm -rf "$GNUPGHOME"
```

If the key has a passphrase, also store it as the secret `APT_SIGNING_PASSPHRASE`. The job refuses to sign when the secret's key does not match the fingerprint variable. GitHub Pages is already set to deploy from Actions, and the `github-pages` environment accepts `v*` tags.

The next release then publishes `dists/stable` for `amd64` and `arm64`, the public key as `tor-relay-setup.asc`, and an index page with the `sources` snippet. `scripts/build-apt-repo.sh` does the work, and the CI job **apt repository build** tests it with a throw-away key on every pull request. Keys expire after three years; extend the key with `gpg --quick-set-expire` and update the secret before then.
