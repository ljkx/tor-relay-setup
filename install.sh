#!/usr/bin/env bash
# Install tor-relay-setup from a GitHub release, verified.
#
#   curl -fsSLO https://raw.githubusercontent.com/ljkx/tor-relay-setup/main/install.sh
#   less install.sh && sudo bash install.sh
#
# Downloads the release archive for this CPU, checks it against SHA256SUMS,
# verifies the build-provenance attestation when the GitHub CLI is present,
# and installs /usr/local/bin/tor-relay-setup. Nothing else is changed.
#
# Environment:
#   TOR_RELAY_SETUP_VERSION  release tag to install (default: newest release)
#   PREFIX                   install prefix (default: /usr/local)
set -Eeuo pipefail

REPO="ljkx/tor-relay-setup"
PREFIX="${PREFIX:-/usr/local}"

say() { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
die() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

for tool in curl sha256sum tar install; do
  command -v "$tool" > /dev/null 2>&1 || die "$tool is required"
done

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m); Tor's apt repository only builds amd64 and arm64" ;;
esac

version="${TOR_RELAY_SETUP_VERSION:-}"
if [[ -z "$version" ]]; then
  # Newest release, pre-releases included (the /latest endpoint skips them).
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=1" \
    | sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [[ -n "$version" ]] || die "could not find a release of ${REPO}"
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "unexpected version '${version}'"

archive="tor-relay-setup_${version#v}_linux_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

say "Downloading tor-relay-setup ${version} (${arch})"
curl -fsSL --retry 3 -o "${work}/${archive}" "${base}/${archive}"
curl -fsSL --retry 3 -o "${work}/SHA256SUMS" "${base}/SHA256SUMS"

say "Verifying SHA256SUMS"
# Select the archive's line by exact file name: a prefix match would also
# pick up "<archive>.sbom.json", which is not downloaded.
sum_line=$(awk -v f="$archive" '$2 == f || $2 == "*" f' "${work}/SHA256SUMS")
[[ -n "$sum_line" ]] || die "${archive} is not listed in SHA256SUMS"
(cd "$work" && printf '%s\n' "$sum_line" | sha256sum --check --quiet -) \
  || die "checksum mismatch for ${archive}; do not install it"

if command -v gh > /dev/null 2>&1; then
  say "Verifying build provenance with gh attestation verify"
  gh attestation verify "${work}/${archive}" --repo "$REPO" > /dev/null \
    || die "attestation verification failed for ${archive}"
else
  say "GitHub CLI not found; skipping the attestation check (checksum verified)"
fi

tar -xzf "${work}/${archive}" -C "$work" tor-relay-setup
install -D -m 0755 "${work}/tor-relay-setup" "${PREFIX}/bin/tor-relay-setup"
say "Installed ${PREFIX}/bin/tor-relay-setup $("${PREFIX}/bin/tor-relay-setup" version | awk '{print $2}')"
printf '\nNext:\n  tor-relay-setup --dry-run     # look around, changes nothing\n  sudo tor-relay-setup          # guided setup, or the console on an existing relay\n'
