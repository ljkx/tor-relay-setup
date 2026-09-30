#!/usr/bin/env bash
# Install the pinned lint/test toolchain into .tools/bin.
#
# CI and `make` both use this script, so local checks run the exact versions
# CI runs. Every download is verified against a pinned SHA-256 digest.
set -Eeuo pipefail

SHELLCHECK_VERSION="v0.11.0"
SHELLCHECK_SHA256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
SHFMT_VERSION="v3.14.1"
SHFMT_SHA256="76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf"
BATS_VERSION="v1.14.0"
BATS_COMMIT="eb7f42f8d608ac693d7a4b67474f6714ea68cfc5"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TOOLS_DIR="${TOOLS_DIR:-${ROOT_DIR}/.tools}"
BIN_DIR="${TOOLS_DIR}/bin"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    printf 'install-dev-tools: pinned binaries are only provided for Linux x86_64.\n' >&2
    printf 'Install shellcheck %s, shfmt %s and bats %s yourself.\n' \
      "$SHELLCHECK_VERSION" "$SHFMT_VERSION" "$BATS_VERSION" >&2
    exit 1
    ;;
esac

download() {
  local url=$1
  local output=$2
  local sha256=$3

  curl -fsSL --retry 3 --connect-timeout 15 -o "$output" "$url"
  printf '%s  %s\n' "$sha256" "$output" | sha256sum --check --quiet -
}

have_version() {
  local binary=$1
  local version=$2
  [[ -x "${BIN_DIR}/${binary}" ]] && "${BIN_DIR}/${binary}" --version 2>/dev/null | grep -Fq -- "${version#v}"
}

mkdir -p "$BIN_DIR"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

if ! have_version shellcheck "$SHELLCHECK_VERSION"; then
  archive="${work_dir}/shellcheck.tar.xz"
  download "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
    "$archive" "$SHELLCHECK_SHA256"
  tar -xJf "$archive" -C "$work_dir"
  install -m 0755 "${work_dir}/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "${BIN_DIR}/shellcheck"
fi

if ! have_version shfmt "$SHFMT_VERSION"; then
  download "https://github.com/mvdan/sh/releases/download/${SHFMT_VERSION}/shfmt_${SHFMT_VERSION}_linux_amd64" \
    "${work_dir}/shfmt" "$SHFMT_SHA256"
  install -m 0755 "${work_dir}/shfmt" "${BIN_DIR}/shfmt"
fi

if ! have_version bats "$BATS_VERSION"; then
  rm -rf -- "${TOOLS_DIR}/bats-core"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$BATS_VERSION" \
    https://github.com/bats-core/bats-core.git "${TOOLS_DIR}/bats-core"
  actual_commit=$(git -C "${TOOLS_DIR}/bats-core" rev-parse HEAD)
  if [[ "$actual_commit" != "$BATS_COMMIT" ]]; then
    printf 'bats %s resolved to %s, expected %s\n' "$BATS_VERSION" "$actual_commit" "$BATS_COMMIT" >&2
    exit 1
  fi
  ln -sfn ../bats-core/bin/bats "${BIN_DIR}/bats"
fi

"${BIN_DIR}/shellcheck" --version | sed -n '2p'
printf 'shfmt %s\n' "$("${BIN_DIR}/shfmt" --version)"
"${BIN_DIR}/bats" --version
