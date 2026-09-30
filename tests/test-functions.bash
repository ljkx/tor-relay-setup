#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck disable=SC2034

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

export TOR_RELAY_SETUP_SOURCE_ONLY=1
# shellcheck source=../setup-tor-guard-relay.sh
source "${ROOT_DIR}/setup-tor-guard-relay.sh"
trap - ERR INT TERM EXIT

fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local expected=$1
  local actual=$2
  local label=$3
  [[ "$actual" == "$expected" ]] || fail "${label}: expected '${expected}', got '${actual}'"
}

assert_contains() {
  local needle=$1
  local file=$2
  local label=$3
  grep -Fq -- "$needle" "$file" || fail "${label}: missing '${needle}'"
}

test_version() {
  assert_eq "1.0.0-beta.4" "$VERSION" "script version"
}

test_traffic_parser_and_steady_budget() {
  # Provider units are decimal; Tor's GBytes are binary.
  assert_eq "9313" "$(parse_traffic_to_gbytes 10TB)" "10TB parser"
  assert_eq "9313" "$(parse_traffic_to_gbytes 10t)" "10t parser"
  assert_eq "2328" "$(parse_traffic_to_gbytes 2.5TB)" "fractional TB parser"
  assert_eq "4656" "$(parse_traffic_to_gbytes '5000 GB')" "5000GB parser"
  assert_eq "10240" "$(parse_traffic_to_gbytes 10TiB)" "10TiB parser"
  assert_eq "5000" "$(parse_traffic_to_gbytes 5000GBytes)" "Tor GBytes parser"
  if parse_traffic_to_gbytes "10 bananas" >/dev/null 2>&1; then
    fail "invalid traffic unit was accepted"
  fi
  if parse_traffic_to_gbytes "900MB" >/dev/null 2>&1; then
    fail "sub-GByte budget was accepted"
  fi

  reset_bandwidth_config
  MONTHLY_TRAFFIC_GBYTES=9313
  MONTHLY_TRAFFIC_USABLE_GBYTES=8381
  MONTHLY_TRAFFIC_BILLING_RULE="sum"
  calculate_steady_monthly_limits

  # 4190 GBytes per direction paced over a 31-day month.
  assert_eq "1640" "$RELAY_BANDWIDTH_RATE_VALUE" "steady rate for 10TB sum"
  assert_eq "8200" "$RELAY_BANDWIDTH_BURST_VALUE" "steady burst for 10TB sum"
  assert_eq "8381" "$ACCOUNTING_MAX_GBYTES" "steady AccountingMax"
  assert_eq "4190" "$STEADY_PER_DIRECTION_GBYTES" "steady per-direction budget"
  if ((RELAY_BANDWIDTH_RATE_VALUE * 1024 * 31 * 86400 > STEADY_PER_DIRECTION_GBYTES * 1024 ** 3)); then
    fail "steady rate would exhaust the per-direction budget in a 31-day month"
  fi

  reset_bandwidth_config
  MONTHLY_TRAFFIC_GBYTES=1024
  MONTHLY_TRAFFIC_USABLE_GBYTES=921
  MONTHLY_TRAFFIC_BILLING_RULE="sum"
  if calculate_steady_monthly_limits >/dev/null 2>&1; then
    fail "sub-10Mbit steady budget was accepted"
  fi
}

test_myfamily_helpers() {
  local -a family=()
  append_unique_fingerprint family "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  append_unique_fingerprint family '$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  append_unique_fingerprint family "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  assert_eq "2" "${#family[@]}" "duplicate MyFamily prevention"
  assert_eq '$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' "$(format_myfamily_csv "${family[@]}")" "MyFamily CSV format"
}

test_ipv6_validation() {
  valid_ipv6_address "2001:db8::1" || fail "valid IPv6 address was rejected"
  if valid_ipv6_address "hello:world" >/dev/null 2>&1; then
    fail "invalid IPv6 address was accepted"
  fi
  if valid_ipv6_address "fe80::1" >/dev/null 2>&1; then
    fail "link-local IPv6 address was accepted"
  fi
}

test_torrc_generation() {
  local temp_file
  temp_file=$(mktemp)
  RELAY_NICKNAME="TestRelay"
  CONTACT_INFO="operator@example.org"
  OR_PORT="9001"
  ENABLE_IPV6=0
  RELAY_MODE="guard"
  ENABLE_TOR_SANDBOX=1
  reset_bandwidth_config

  build_torrc "$temp_file"
  assert_contains "Nickname TestRelay" "$temp_file" "torrc nickname"
  assert_contains 'ContactInfo "operator@example.org"' "$temp_file" "torrc ContactInfo"
  assert_contains "SocksPort 0" "$temp_file" "torrc SocksPort"
  assert_contains "ExitRelay 0" "$temp_file" "torrc non-exit"
  assert_contains "Sandbox 1" "$temp_file" "torrc Sandbox"
  rm -f -- "$temp_file"
}

test_ufw_inactive_detection() {
  local stub_dir old_path
  stub_dir=$(mktemp -d)
  old_path=$PATH
  cat > "${stub_dir}/ufw" <<'EOF'
#!/usr/bin/env bash
printf 'Status: inactive\n'
EOF
  chmod +x "${stub_dir}/ufw"
  PATH="${stub_dir}:${PATH}"

  detect_firewall
  assert_eq "ufw" "$FIREWALL_KIND" "ufw detection"
  assert_eq "inactive" "$FIREWALL_STATE" "ufw inactive parsing"

  PATH=$old_path
  rm -rf -- "$stub_dir"
}

test_tor_candidate_from_tor_project_uses_candidate_block() {
  local stub_dir old_path
  stub_dir=$(mktemp -d)
  old_path=$PATH

  cat > "${stub_dir}/apt-cache" <<'EOF'
#!/usr/bin/env bash
cat <<'POLICY'
tor:
  Installed: 0.4.8.12-1~d12.bookworm+1
  Candidate: 99.0-evil1
  Version table:
     99.0-evil1 1001
       1001 http://evil.example/debian bookworm/main amd64 Packages
 *** 0.4.8.12-1~d12.bookworm+1 100
       500 https://deb.torproject.org/torproject.org bookworm/main amd64 Packages
POLICY
EOF
  chmod +x "${stub_dir}/apt-cache"
  PATH="${stub_dir}:${PATH}"

  if tor_candidate_from_tor_project; then
    fail "candidate-origin verifier accepted non-Tor candidate"
  fi

  cat > "${stub_dir}/apt-cache" <<'EOF'
#!/usr/bin/env bash
cat <<'POLICY'
tor:
  Installed: (none)
  Candidate: 0.4.8.12-1~d12.bookworm+1
  Version table:
     0.4.8.12-1~d12.bookworm+1 500
       500 https://deb.torproject.org/torproject.org bookworm/main amd64 Packages
POLICY
EOF
  chmod +x "${stub_dir}/apt-cache"

  tor_candidate_from_tor_project || fail "candidate-origin verifier rejected Tor Project candidate"

  PATH=$old_path
  rm -rf -- "$stub_dir"
}

test_orport_self_test_log_matching() {
  local modern_v4='Oct 01 12:00:00 relay Tor[123]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent. Publishing server descriptor.'
  local modern_v6='Oct 01 12:00:01 relay Tor[123]: Self-testing indicates your ORPort [2001:db8::5]:9001 is reachable from the outside. Excellent.'
  local legacy='Self-testing indicates your ORPort is reachable from the outside. Excellent.'
  local failed='Your server has not managed to confirm reachability for its ORPort(s) at 203.0.113.5:9001. Relays do not publish descriptors until their ORPort(s) are reachable.'

  orport_self_test_succeeded <<< "$modern_v4" || fail "modern IPv4 self-test success was not recognised"
  orport_self_test_succeeded <<< "$legacy" || fail "legacy self-test success was not recognised"
  orport_self_test_succeeded ipv6 <<< "$modern_v6" || fail "IPv6 self-test success was not recognised"
  if orport_self_test_succeeded ipv6 <<< "$modern_v4"; then
    fail "IPv4 self-test success was reported as IPv6"
  fi
  orport_self_test_failed <<< "$failed" || fail "modern self-test failure was not recognised"
  if orport_self_test_succeeded <<< "$failed"; then
    fail "self-test failure was reported as success"
  fi
}

test_unattended_upgrades_origins() {
  local temp_file
  temp_file=$(mktemp)

  OS_ID="debian"
  build_unattended_tor_config "$temp_file"
  assert_contains 'codename=${distro_codename}-security,label=Debian-Security' "$temp_file" "Debian security origin"
  assert_contains '"origin=TorProject";' "$temp_file" "Debian Tor Project origin"

  OS_ID="ubuntu"
  build_unattended_tor_config "$temp_file"
  assert_contains '"${distro_id}:${distro_codename}-security";' "$temp_file" "Ubuntu security origin"
  assert_contains '"TorProject:${distro_codename}";' "$temp_file" "Ubuntu Tor Project origin"
  rm -f -- "$temp_file"
}

test_signing_key_rejects_extra_primary_keys() {
  local stub_dir old_path
  stub_dir=$(mktemp -d)
  old_path=$PATH
  DRY_RUN=0

  cat > "${stub_dir}/gpg" <<'EOF'
#!/usr/bin/env bash
printf 'pub:-:4096:1:EE8CBC9E886DDD89:1:::-:::scESC::::::23::0:\n'
printf 'fpr:::::::::A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89:\n'
printf 'sub:-:2048:1:74A941BA219EC810:1:::::s::::::23:\n'
printf 'fpr:::::::::2265EB4CB2BF88D900AE8D1B74A941BA219EC810:\n'
if [[ "${STUB_EXTRA_KEY:-0}" == "1" ]]; then
  printf 'pub:-:4096:1:1111111111111111:1:::-:::scESC::::::23::0:\n'
  printf 'fpr:::::::::1111111111111111111111111111111111111111:\n'
fi
EOF
  chmod +x "${stub_dir}/gpg"
  PATH="${stub_dir}:${PATH}"

  (verify_tor_signing_key_file /dev/null >/dev/null 2>&1) || fail "genuine Tor signing key was rejected"
  if (export STUB_EXTRA_KEY=1 && verify_tor_signing_key_file /dev/null >/dev/null 2>&1); then
    fail "key file with an extra primary key was accepted"
  fi

  PATH=$old_path
  rm -rf -- "$stub_dir"
}

test_version
test_signing_key_rejects_extra_primary_keys
test_traffic_parser_and_steady_budget
test_myfamily_helpers
test_ipv6_validation
test_torrc_generation
test_ufw_inactive_detection
test_tor_candidate_from_tor_project_uses_candidate_block
test_orport_self_test_log_matching
test_unattended_upgrades_origins

printf 'ok - function tests passed\n'
