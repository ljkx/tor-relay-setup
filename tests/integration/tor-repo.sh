#!/usr/bin/env bash
# Integration test for a disposable Debian/Ubuntu container, run as root:
#
#   docker run --rm -v "$PWD:/src:ro" -w /src debian:trixie tests/integration/tor-repo.sh
#
# It performs the real Tor Project apt setup (signing-key fingerprint check,
# deb822 source, candidate-origin check, package install) with the script's
# own functions, then validates generated torrc variants with the installed
# tor exactly the way tor@default.service does. Never run it on a real host.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

if [[ ! -f /.dockerenv && "${ALLOW_HOST_INTEGRATION:-0}" != "1" ]]; then
  printf 'Refusing to modify a non-container host. Set ALLOW_HOST_INTEGRATION=1 to override.\n' >&2
  exit 2
fi
((EUID == 0)) || {
  printf 'Run as root inside the container.\n' >&2
  exit 2
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg wget > /dev/null

# shellcheck source=../../setup-tor-guard-relay.sh
TOR_RELAY_SETUP_SOURCE_ONLY=1 source "${ROOT_DIR}/setup-tor-guard-relay.sh"
set -Eeuo pipefail
NO_COLOR=1
PLAIN_TUI=1
DRY_RUN=0
TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_DIR"' EXIT

# shellcheck disable=SC1091
. /etc/os-release
OS_ID=$ID
OS_CODENAME=$VERSION_CODENAME
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')

section "Tor Project apt repository"
install_repository_prerequisites
configure_tor_repository
install_tor_package

tor_version=$(tor --version | awk 'NR == 1 { sub(/\.$/, "", $3); print $3 }')
success "Installed tor ${tor_version}"
if ! printf '%s\n%s\n' "0.4.9" "$tor_version" | sort -V -C; then
  die "tor ${tor_version} is older than 0.4.9; the Tor network rejects it."
fi
tor_candidate_from_tor_project || die "Installed tor does not come from deb.torproject.org."

verify_variant() {
  local name=$1
  local output="${TMP_DIR}/torrc.${name}"

  build_torrc "$output"
  printf '\n--- %s ---\n' "$name"
  cat "$output"
  verify_tor_config_file "$output"
}

section "Family key"
# Real `tor --keygen-family`, installed into the package's key directory.
generate_family_key ci-family
keys_dir=$(tor_family_key_directory)
key_file="${keys_dir}/ci-family.secret_family_key"
family_key_file_valid "$key_file" || die "Generated family key is not valid: ${key_file}"
[[ "$(stat -c '%U %a' "$key_file")" == "debian-tor 600" ]] \
  || die "Family key has unexpected owner/mode: $(stat -c '%U %a' "$key_file")"
family_key_installed_for_id "$FAMILY_ID" || die "FamilyId ${FAMILY_ID} has no installed key."
success "Family key ${key_file} (FamilyId ${FAMILY_ID})"

section "torrc variants"
RELAY_NICKNAME="CiGuard"
CONTACT_INFO=$(build_ciiss_contact ci@example.org https://example.org)
OR_PORT="9001"
RELAY_MODE="guard"
ENABLE_TOR_SANDBOX=1
CONFIGURE_METRICS_PORT=1
reset_bandwidth_config
verify_variant guard-family-metrics
CONFIGURE_METRICS_PORT=0
FAMILY_ID=""

MONTHLY_TRAFFIC_GBYTES=$(parse_traffic_to_gbytes 10TB)
MONTHLY_TRAFFIC_USABLE_GBYTES=$((MONTHLY_TRAFFIC_GBYTES * 90 / 100))
MONTHLY_TRAFFIC_BILLING_RULE="sum"
ACCOUNTING_RULE="sum"
calculate_steady_monthly_limits
verify_variant guard-steady-budget

RELAY_NICKNAME="CiExit"
RELAY_MODE="exit"
EXIT_POLICY_MODE="reduced"
ENABLE_IPV6=1
IPV6_ADDRESS="2001:db8::10"
EXIT_ALLOW_IPV6=1
OR_PORT="443"
ENABLE_TOR_SANDBOX=0
reset_bandwidth_config
verify_variant exit-ipv6

success "All torrc variants passed tor --verify-config."
