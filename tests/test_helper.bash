# Shared setup for the bats suites. Loaded with `load test_helper`.

ROOT_DIR=$(cd "${BATS_TEST_DIRNAME}/.." && pwd -P)
SCRIPT_PATH="${ROOT_DIR}/setup-tor-guard-relay.sh"

# Source the installer without running main(). In source-only mode the script
# leaves shell options and traps alone, so bats keeps its failure detection.
# The prefix assignment is not exported: scripts started with `run` still
# execute main() normally.
load_script() {
  export NO_COLOR=1
  # shellcheck source=../setup-tor-guard-relay.sh
  TOR_RELAY_SETUP_SOURCE_ONLY=1 source "$SCRIPT_PATH"
  TMP_DIR=$(mktemp -d "${BATS_TEST_TMPDIR}/work.XXXXXX")
}

# Put executable stubs from a directory in front of PATH.
use_stubs() {
  STUB_DIR="${BATS_TEST_TMPDIR}/stubs"
  mkdir -p "$STUB_DIR"
  PATH="${STUB_DIR}:${PATH}"
}

write_stub() {
  local name=$1
  cat > "${STUB_DIR}/${name}"
  chmod +x "${STUB_DIR}/${name}"
}

assert_file_contains() {
  local needle=$1
  local file=$2
  if ! grep -Fq -- "$needle" "$file"; then
    printf 'expected %s to contain: %s\n--- file ---\n' "$file" "$needle" >&2
    cat "$file" >&2
    return 1
  fi
}

refute_file_contains() {
  local needle=$1
  local file=$2
  if grep -Fq -- "$needle" "$file"; then
    printf 'expected %s not to contain: %s\n' "$file" "$needle" >&2
    return 1
  fi
}

# `! cmd` does not fail a bats test unless it is the last command, so use
# `refute cmd` for negative assertions.
refute() {
  if "$@"; then
    printf 'expected failure from: %s\n' "$*" >&2
    return 1
  fi
}
