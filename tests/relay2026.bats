#!/usr/bin/env bats
# Tests for Tor 0.4.9-era relay features: FamilyId families, CIISS v3
# ContactInfo, MetricsPort, and the supported-version floor.
# Each @test runs in its own subshell, so per-test globals are intentional.
# shellcheck disable=SC2030,SC2031

setup() {
  load test_helper
  load_script
  use_stubs
  DRY_RUN=0
  PLAIN_TUI=1
}

FAMILY_ID_A="flIHuuYy2vCWg+FgNibpOOHpRQ7rALbVUlS0WMmmuI8"
FAMILY_ID_B="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

# Emulates `tor --keygen-family NAME`, which writes into the working directory.
keygen_stub() {
  write_stub tor << STUB
#!/usr/bin/env bash
name=\${*: -1}
{ printf '== ed25519v1-secret: fmly-id ==\\0'; head -c 64 /dev/urandom; } > "\${name}.secret_family_key"
printf '%s\\n' "${FAMILY_ID_A}" > "\${name}.public_family_id"
printf 'FamilyId %s\\n' "${FAMILY_ID_A}"
STUB
}

use_temp_torrc() {
  TORRC_PATH="${BATS_TEST_TMPDIR}/torrc"
  printf 'DataDirectory %s/data\n' "$BATS_TEST_TMPDIR" > "$TORRC_PATH"
}

@test "CIISS v3 ContactInfo puts email first and adds a proof for url" {
  [ "$(build_ciiss_contact ops@example.org)" = "email:ops[]example.org ciissversion:3" ]
  [ "$(build_ciiss_contact ops@example.org https://example.org hetzner.com)" \
    = "email:ops[]example.org url:https://example.org proof:uri-familyid-ed25519 hoster:hetzner.com ciissversion:3" ]
  [ "$(url_domain https://example.org/about/relays)" = example.org ]
}

@test "ContactInfo builder inputs are validated" {
  valid_contact_email "tor-ops@example.org"
  refute valid_contact_email "not an email"
  refute valid_contact_email "a#b@example.org"
  valid_contact_url "https://example.org/tor"
  refute valid_contact_url "http://example.org"
  valid_hoster_domain "hetzner.com"
  refute valid_hoster_domain "https://hetzner.com"
}

@test "FamilyId values and family key names are validated" {
  valid_family_id "$FAMILY_ID_A"
  refute valid_family_id "${FAMILY_ID_A%?}"
  refute valid_family_id "notbase64!notbase64!notbase64!notbase64!abc"
  valid_family_key_name "relay-family"
  refute valid_family_key_name "../escape"
  refute valid_family_key_name ".hidden"
}

@test "family key files are recognised by name, size, and header" {
  local key="${BATS_TEST_TMPDIR}/fam.secret_family_key"
  {
    printf '%s\0' "$FAMILY_KEY_HEADER"
    head -c 64 /dev/zero
  } > "$key"
  printf '%s\n' "$FAMILY_ID_A" > "${BATS_TEST_TMPDIR}/fam.public_family_id"

  family_key_file_valid "$key"
  [ "$(family_id_for_key_file "$key")" = "$FAMILY_ID_A" ]

  head -c 95 "$key" > "${BATS_TEST_TMPDIR}/short.secret_family_key"
  refute family_key_file_valid "${BATS_TEST_TMPDIR}/short.secret_family_key"
  cp "$key" "${BATS_TEST_TMPDIR}/fam.key"
  refute family_key_file_valid "${BATS_TEST_TMPDIR}/fam.key"
}

@test "torrc includes FamilyId and a local-only MetricsPort when chosen" {
  RELAY_NICKNAME="TestRelay"
  CONTACT_INFO="email:ops[]example.org ciissversion:3"
  OR_PORT="9001"
  RELAY_MODE="guard"
  FAMILY_ID=$FAMILY_ID_A
  CONFIGURE_METRICS_PORT=1
  reset_bandwidth_config

  build_torrc "${BATS_TEST_TMPDIR}/out"
  assert_file_contains "FamilyId ${FAMILY_ID_A}" "${BATS_TEST_TMPDIR}/out"
  assert_file_contains "MetricsPort 127.0.0.1:9035" "${BATS_TEST_TMPDIR}/out"
  assert_file_contains "MetricsPortPolicy accept 127.0.0.1" "${BATS_TEST_TMPDIR}/out"
  refute_file_contains "MyFamily" "${BATS_TEST_TMPDIR}/out"
}

@test "FamilyId lines are replaced in place and other settings are kept" {
  TORRC_PATH="${BATS_TEST_TMPDIR}/torrc"
  cat > "$TORRC_PATH" << TORRC
Nickname Test
ContactInfo "ops@example.org"

# Managed relay family (Tor 0.4.9 FamilyId). Every relay in the family shares the key.
FamilyId ${FAMILY_ID_A}
# FamilyId CommentedOutCommentedOutCommentedOutComment
ORPort 9001
TORRC

  write_family_ids_to_torrc "${BATS_TEST_TMPDIR}/out" "$FAMILY_ID_A" "$FAMILY_ID_B"
  [ "$(grep -c '^FamilyId ' "${BATS_TEST_TMPDIR}/out")" -eq 2 ]
  [ "$(grep -c 'Managed relay family' "${BATS_TEST_TMPDIR}/out")" -eq 1 ]
  assert_file_contains "# FamilyId CommentedOut" "${BATS_TEST_TMPDIR}/out"
  assert_file_contains "ORPort 9001" "${BATS_TEST_TMPDIR}/out"

  write_family_ids_to_torrc "${BATS_TEST_TMPDIR}/none"
  refute_file_contains "FamilyId ${FAMILY_ID_A}" "${BATS_TEST_TMPDIR}/none"
  refute_file_contains "Managed relay family" "${BATS_TEST_TMPDIR}/none"

  cp "${BATS_TEST_TMPDIR}/out" "$TORRC_PATH"
  run torrc_family_ids
  [ "${lines[0]}" = "$FAMILY_ID_A" ]
  [ "${lines[1]}" = "$FAMILY_ID_B" ]
}

@test "MetricsPort toggle is idempotent and reversible" {
  TORRC_PATH="${BATS_TEST_TMPDIR}/torrc"
  printf 'Nickname Test\nORPort 9001\n' > "$TORRC_PATH"

  write_torrc_metrics_port "${BATS_TEST_TMPDIR}/on" 1
  cp "${BATS_TEST_TMPDIR}/on" "$TORRC_PATH"
  write_torrc_metrics_port "${BATS_TEST_TMPDIR}/on2" 1
  [ "$(grep -c '^MetricsPort ' "${BATS_TEST_TMPDIR}/on2")" -eq 1 ]

  cp "${BATS_TEST_TMPDIR}/on2" "$TORRC_PATH"
  write_torrc_metrics_port "${BATS_TEST_TMPDIR}/off" 0
  refute_file_contains "Metrics" "${BATS_TEST_TMPDIR}/off"
  assert_file_contains "ORPort 9001" "${BATS_TEST_TMPDIR}/off"
}

@test "version comparison enforces the 0.4.9 floor" {
  version_at_least 0.4.9.13 "$MIN_TOR_VERSION"
  version_at_least 0.4.9 "$MIN_TOR_VERSION"
  version_at_least 0.5.0.1-alpha "$MIN_TOR_VERSION"
  refute version_at_least 0.4.8.25 "$MIN_TOR_VERSION"
}

@test "installed tor version is parsed and accepted" {
  write_stub tor << 'STUB'
#!/usr/bin/env bash
printf 'Tor version 0.4.9.13.\nTor is running on Linux with Libevent 2.1.12-stable.\n'
STUB
  [ "$(tor_installed_version)" = 0.4.9.13 ]
  run require_supported_tor_version
  [ "$status" -eq 0 ]
}

@test "tor older than 0.4.9 is refused" {
  write_stub tor << 'STUB'
#!/usr/bin/env bash
printf 'Tor version 0.4.8.25.\n'
STUB
  run require_supported_tor_version
  [ "$status" -ne 0 ]
  [[ "$output" == *"rejects relays older than 0.4.9"* ]]
}

@test "a generated family key is installed privately with its FamilyId" {
  keygen_stub
  use_temp_torrc

  generate_family_key relay-family
  [ "$FAMILY_ID" = "$FAMILY_ID_A" ]
  family_key_file_valid "${BATS_TEST_TMPDIR}/data/keys/relay-family.secret_family_key"
  [ "$(stat -c %a "${BATS_TEST_TMPDIR}/data/keys/relay-family.secret_family_key")" = 600 ]
  [ "$(stat -c %a "${BATS_TEST_TMPDIR}/data/keys")" = 700 ]
  family_key_installed_for_id "$FAMILY_ID_A"
  refute family_key_installed_for_id "$FAMILY_ID_B"
}

@test "an existing family key is never overwritten" {
  keygen_stub
  use_temp_torrc

  generate_family_key relay-family
  run generate_family_key relay-family
  [ "$status" -ne 0 ]
  [[ "$output" == *"existing keys are never overwritten"* ]]
}

@test "FamilyKeyDirectory overrides the default key directory" {
  use_temp_torrc
  printf 'FamilyKeyDirectory %s/family-keys/\n' "$BATS_TEST_TMPDIR" >> "$TORRC_PATH"
  [ "$(tor_family_key_directory)" = "${BATS_TEST_TMPDIR}/family-keys" ]
}
