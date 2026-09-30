#!/usr/bin/env bats
# Unit tests for pure helpers in setup-tor-guard-relay.sh.
# Literal '$' fingerprints and apt macros are intentional in single quotes.
# shellcheck disable=SC2016

setup() {
  load test_helper
  load_script
}

@test "version is a semantic version" {
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]
}

@test "--version and --help run without root" {
  run "$SCRIPT_PATH" --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"$VERSION"* ]]

  run "$SCRIPT_PATH" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--dry-run"* ]]
  [[ "$output" == *"--uninstall"* ]]
}

@test "unknown options exit with usage status 2" {
  run "$SCRIPT_PATH" --definitely-not-an-option
  [ "$status" -eq 2 ]
}

@test "traffic parser treats provider units as decimal and Tor units as binary" {
  [ "$(parse_traffic_to_gbytes 10TB)" = 9313 ]
  [ "$(parse_traffic_to_gbytes 10t)" = 9313 ]
  [ "$(parse_traffic_to_gbytes 2.5TB)" = 2328 ]
  [ "$(parse_traffic_to_gbytes '5000 GB')" = 4656 ]
  [ "$(parse_traffic_to_gbytes 10TiB)" = 10240 ]
  [ "$(parse_traffic_to_gbytes 5000GBytes)" = 5000 ]
}

@test "traffic parser rejects unknown units and sub-GByte budgets" {
  run parse_traffic_to_gbytes "10 bananas"
  [ "$status" -ne 0 ]
  run parse_traffic_to_gbytes 900MB
  [ "$status" -ne 0 ]
}

@test "steady budget paces a 10TB combined quota over 31 days" {
  reset_bandwidth_config
  MONTHLY_TRAFFIC_GBYTES=9313
  MONTHLY_TRAFFIC_USABLE_GBYTES=8381
  MONTHLY_TRAFFIC_BILLING_RULE="sum"
  calculate_steady_monthly_limits

  [ "$STEADY_PER_DIRECTION_GBYTES" = 4190 ]
  [ "$RELAY_BANDWIDTH_RATE_VALUE" = 1640 ]
  [ "$RELAY_BANDWIDTH_BURST_VALUE" = 8200 ]
  [ "$ACCOUNTING_MAX_GBYTES" = 8381 ]
  # The paced rate must fit the per-direction budget even in a 31-day month.
  ((RELAY_BANDWIDTH_RATE_VALUE * 1024 * 31 * 86400 <= STEADY_PER_DIRECTION_GBYTES * 1024 ** 3))
}

@test "steady budget refuses rates below the 10 Mbit/s relay floor" {
  reset_bandwidth_config
  MONTHLY_TRAFFIC_GBYTES=1024
  MONTHLY_TRAFFIC_USABLE_GBYTES=921
  MONTHLY_TRAFFIC_BILLING_RULE="sum"
  run calculate_steady_monthly_limits
  [ "$status" -ne 0 ]
}

@test "nickname, port, ContactInfo and hostname validation" {
  valid_nickname "Relay01"
  refute valid_nickname "has space"
  refute valid_nickname "ThisNicknameIsTooLong1"

  valid_port 9001
  valid_port 443
  refute valid_port 0
  refute valid_port 65536
  refute valid_port 90a1

  valid_contact_info "email:ops[]example.org ciissversion:2"
  refute valid_contact_info ""
  refute valid_contact_info "ops@example.org # comment"

  valid_system_hostname "relay-1.example.org"
  refute valid_system_hostname "localhost"
  refute valid_system_hostname "bad_host"
  refute valid_system_hostname "-leading.example.org"
}

@test "IPv6 validation accepts global addresses only" {
  valid_ipv6_address "2001:db8::1"
  refute valid_ipv6_address "hello:world"
  refute valid_ipv6_address "fe80::1"
  refute valid_ipv6_address "[2001:db8::1]"
  refute valid_ipv6_address "2001:db8::/64"
}

@test "fingerprint helpers normalise and deduplicate MyFamily entries" {
  local -a family=()
  append_unique_fingerprint family "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  append_unique_fingerprint family '$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  append_unique_fingerprint family "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  [ "${#family[@]}" -eq 2 ]
  [ "$(format_myfamily_csv "${family[@]}")" = '$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' ]
  valid_fingerprint '$0123456789ABCDEF0123456789ABCDEF01234567'
  refute valid_fingerprint "0123456789ABCDEF"
}

@test "MyFamily parser reads every fingerprint and ignores comments" {
  TORRC_PATH="${BATS_TEST_TMPDIR}/torrc"
  cat > "$TORRC_PATH" << 'EOF'
Nickname Test
# MyFamily $CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
MyFamily $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  run torrc_myfamily_fingerprints
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ]
  [ "${lines[1]}" = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB ]
  [ "${#lines[@]}" -eq 2 ]
}

@test "guard torrc is relay-only and non-exit" {
  RELAY_NICKNAME="TestRelay"
  CONTACT_INFO="operator@example.org"
  OR_PORT="9001"
  ENABLE_IPV6=0
  RELAY_MODE="guard"
  ENABLE_TOR_SANDBOX=1
  reset_bandwidth_config

  build_torrc "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "Nickname TestRelay" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains 'ContactInfo "operator@example.org"' "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "SocksPort 0" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "ExitRelay 0" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "Sandbox 1" "${BATS_TEST_TMPDIR}/torrc"
  refute_file_contains "ExitRelay 1" "${BATS_TEST_TMPDIR}/torrc"
}

@test "exit torrc writes the reduced policy and IPv6 exit" {
  RELAY_NICKNAME="TestExit"
  CONTACT_INFO='quote " and \ backslash'
  OR_PORT="443"
  ENABLE_IPV6=1
  IPV6_ADDRESS="2001:db8::5"
  RELAY_MODE="exit"
  EXIT_POLICY_MODE="reduced"
  EXIT_ALLOW_IPV6=1
  ENABLE_TOR_SANDBOX=0
  reset_bandwidth_config

  build_torrc "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains 'ContactInfo "quote \" and \\ backslash"' "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "ORPort [2001:db8::5]:443" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "ExitRelay 1" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "ReducedExitPolicy 1" "${BATS_TEST_TMPDIR}/torrc"
  assert_file_contains "IPv6Exit 1" "${BATS_TEST_TMPDIR}/torrc"
  refute_file_contains "Sandbox 1" "${BATS_TEST_TMPDIR}/torrc"
}

@test "Tor apt source is deb822 and pinned to the Tor keyring" {
  OS_CODENAME="trixie"
  build_tor_sources "${BATS_TEST_TMPDIR}/tor.sources"
  assert_file_contains "URIs: https://deb.torproject.org/torproject.org/" "${BATS_TEST_TMPDIR}/tor.sources"
  assert_file_contains "Suites: trixie" "${BATS_TEST_TMPDIR}/tor.sources"
  assert_file_contains "Signed-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg" "${BATS_TEST_TMPDIR}/tor.sources"
}

@test "unattended-upgrades origins cover security and Tor Project updates" {
  OS_ID="debian"
  build_unattended_tor_config "${BATS_TEST_TMPDIR}/debian"
  assert_file_contains 'codename=${distro_codename}-security,label=Debian-Security' "${BATS_TEST_TMPDIR}/debian"
  assert_file_contains '"origin=TorProject";' "${BATS_TEST_TMPDIR}/debian"

  OS_ID="ubuntu"
  build_unattended_tor_config "${BATS_TEST_TMPDIR}/ubuntu"
  assert_file_contains '"${distro_id}:${distro_codename}-security";' "${BATS_TEST_TMPDIR}/ubuntu"
  assert_file_contains '"TorProject:${distro_codename}";' "${BATS_TEST_TMPDIR}/ubuntu"
}

@test "ORPort self-test matching follows current Tor log wording" {
  local modern_v4='Tor[1]: Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the outside. Excellent. Publishing server descriptor.'
  local modern_v6='Tor[1]: Self-testing indicates your ORPort [2001:db8::5]:9001 is reachable from the outside. Excellent.'
  local legacy='Self-testing indicates your ORPort is reachable from the outside. Excellent.'
  local failed='Your server has not managed to confirm reachability for its ORPort(s) at 203.0.113.5:9001. Relays do not publish descriptors until their ORPort(s) are reachable.'

  orport_self_test_succeeded <<< "$modern_v4"
  orport_self_test_succeeded <<< "$legacy"
  orport_self_test_succeeded ipv6 <<< "$modern_v6"
  refute orport_self_test_succeeded ipv6 <<< "$modern_v4"
  orport_self_test_failed <<< "$failed"
  refute orport_self_test_succeeded <<< "$failed"
}

@test "plain checklist ignores keys that were not offered" {
  PLAIN_TUI=1
  USE_FZF=0
  local -a picked=()
  choose_checklist picked "Pick" \
    "state" "/var/lib/tor-relay-setup" "state" "safe" \
    "reports" "/tmp/reports" "reports" "safe" \
    <<< "reports repo state state" 2> /dev/null

  [ "${#picked[@]}" -eq 2 ]
  [ "${picked[0]}" = reports ]
  [ "${picked[1]}" = state ]
}

@test "prompt sanitiser strips terminal escapes and control characters" {
  [ "$(sanitize_reply $'ab\e[31mc\x01d\x7f')" = abcd ]
}
