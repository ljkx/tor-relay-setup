#!/usr/bin/env bash
# Install the pinned lint toolchain into .tools/bin.
#
# CI and `make lint` both use this script, so local checks run exactly the
# versions CI runs. Every download is verified against a pinned SHA-256.
set -Eeuo pipefail

GOLANGCI_VERSION="v2.14.0"
GOLANGCI_SHA256="ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab"
SHELLCHECK_VERSION="v0.11.0"
SHELLCHECK_SHA256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
SHFMT_VERSION="v3.14.1"
SHFMT_SHA256="76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TOOLS_DIR="${TOOLS_DIR:-${ROOT_DIR}/.tools}"
BIN_DIR="${TOOLS_DIR}/bin"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    printf 'install-dev-tools: pinned binaries are only provided for Linux x86_64.\n' >&2
    printf 'Install golangci-lint %s, shellcheck %s and shfmt %s yourself.\n' \
      "$GOLANGCI_VERSION" "$SHELLCHECK_VERSION" "$SHFMT_VERSION" >&2
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
  [[ -x "${BIN_DIR}/${binary}" ]] && "${BIN_DIR}/${binary}" --version 2> /dev/null | grep -Fq -- "${version#v}"
}

mkdir -p "$BIN_DIR"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

if ! have_version golangci-lint "$GOLANGCI_VERSION"; then
  name="golangci-lint-${GOLANGCI_VERSION#v}-linux-amd64"
  download "https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_VERSION}/${name}.tar.gz" \
    "${work_dir}/golangci.tar.gz" "$GOLANGCI_SHA256"
  tar -xzf "${work_dir}/golangci.tar.gz" -C "$work_dir"
  install -m 0755 "${work_dir}/${name}/golangci-lint" "${BIN_DIR}/golangci-lint"
fi

if ! have_version shellcheck "$SHELLCHECK_VERSION"; then
  download "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
    "${work_dir}/shellcheck.tar.xz" "$SHELLCHECK_SHA256"
  tar -xJf "${work_dir}/shellcheck.tar.xz" -C "$work_dir"
  install -m 0755 "${work_dir}/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "${BIN_DIR}/shellcheck"
fi

if ! have_version shfmt "$SHFMT_VERSION"; then
  download "https://github.com/mvdan/sh/releases/download/${SHFMT_VERSION}/shfmt_${SHFMT_VERSION}_linux_amd64" \
    "${work_dir}/shfmt" "$SHFMT_SHA256"
  install -m 0755 "${work_dir}/shfmt" "${BIN_DIR}/shfmt"
fi

"${BIN_DIR}/golangci-lint" --version
"${BIN_DIR}/shellcheck" --version | sed -n '2p'
printf 'shfmt %s\n' "$("${BIN_DIR}/shfmt" --version)"
