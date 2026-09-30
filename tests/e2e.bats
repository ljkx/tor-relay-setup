#!/usr/bin/env bats
# End-to-end dry runs of the interactive flow in --plain mode.
#
# Answers are piped in line by line. systemctl, hostnamectl, and ufw are
# stubbed so every host (CI runner, container, laptop) sees the same prompts.
# Dry runs never need root and never change the system.

setup() {
  load test_helper
  use_stubs
  write_stub systemctl << 'EOF'
#!/usr/bin/env bash
exit 3
EOF
  write_stub hostnamectl << 'EOF'
#!/usr/bin/env bash
printf 'e2e-host\n'
EOF
  write_stub ufw << 'EOF'
#!/usr/bin/env bash
printf 'Status: inactive\n'
EOF
}

dry_run() {
  printf '%s\n' "$@" | NO_COLOR=1 "$SCRIPT_PATH" --dry-run --plain 2>&1
}

@test "guard relay: CIISS ContactInfo, new family key, steady budget, MetricsPort" {
  run dry_run \
    n `# change hostname` \
    n `# exit relay` \
    E2eGuard \
    '' `# ContactInfo format: guided CIISS v3` \
    ops@example.org \
    https://example.org/tor \
    '' `# hoster` \
    '' `# ORPort 9001` \
    n `# IPv6` \
    2 `# create a new family key` \
    '' `# key name relay-family` \
    n `# legacy MyFamily` \
    1 `# steady monthly budget` \
    10TB \
    '' `# headroom 10%` \
    1 `# combined in+out` \
    '' `# unattended upgrades` \
    '' `# nyx` \
    y `# MetricsPort` \
    '' `# ufw rules + enable` \
    '' `# sandbox` \
    y `# apply`

  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Nickname E2eGuard"* ]]
  [[ "$output" == *'ContactInfo "email:ops[]example.org url:https://example.org/tor proof:uri-familyid-ed25519 ciissversion:3"'* ]]
  [[ "$output" == *"https://example.org/.well-known/tor-relay/ed25519-family-id.txt"* ]]
  [[ "$output" == *"# FamilyId <generated with tor --keygen-family during apply>"* ]]
  [[ "$output" == *"tor --keygen-family relay-family"* ]]
  [[ "$output" == *"ExitRelay 0"* ]]
  [[ "$output" == *"MetricsPort 127.0.0.1:9035"* ]]
  [[ "$output" == *"RelayBandwidthRate 1640 KBytes"* ]]
  [[ "$output" == *"AccountingMax 8381 GBytes"* ]]
  [[ "$output" == *"ufw allow 9001/tcp"* ]]
  [[ "$output" == *"Dry run complete."* ]]
  [[ "$output" != *"[ERROR]"* ]]
}

@test "exit relay: IPv6, reduced policy, Unbound, free-form ContactInfo" {
  run dry_run \
    n `# change hostname` \
    y `# exit relay` \
    E2eExit \
    2 `# ContactInfo format: free-form` \
    abuse@example.org \
    443 \
    y `# IPv6` \
    2001:db8::10 \
    n `# skip connectivity check` \
    y `# provider permission` \
    y `# exit notice` \
    '' `# ReducedExitPolicy` \
    '' `# IPv6Exit` \
    '' `# Unbound` \
    n `# chattr resolv.conf` \
    1 `# single relay, no family` \
    4 `# no bandwidth cap` \
    '' `# unattended upgrades` \
    n `# nyx` \
    '' `# MetricsPort (default no)` \
    '' `# ufw rules + enable` \
    '' `# sandbox` \
    y `# apply`

  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
  [[ "$output" == *'ContactInfo "abuse@example.org"'* ]]
  [[ "$output" == *"ExitRelay 1"* ]]
  [[ "$output" == *"ReducedExitPolicy 1"* ]]
  [[ "$output" == *"IPv6Exit 1"* ]]
  [[ "$output" == *"ORPort [2001:db8::10]:443"* ]]
  [[ "$output" == *"apt-get install -y unbound"* ]]
  [[ "$output" != *"MetricsPort 127.0.0.1"* ]]
  # torrc preview lines are indented by four spaces.
  [[ "$output" != *"    FamilyId "* ]]
  [[ "$output" == *"Dry run complete."* ]]
}

@test "second relay imports an existing family key" {
  local key="${BATS_TEST_TMPDIR}/ops.secret_family_key"
  {
    printf '== ed25519v1-secret: fmly-id ==\0'
    head -c 64 /dev/zero
  } > "$key"
  printf 'flIHuuYy2vCWg+FgNibpOOHpRQ7rALbVUlS0WMmmuI8\n' > "${BATS_TEST_TMPDIR}/ops.public_family_id"

  run dry_run \
    n n E2eSecond \
    2 ops@example.org \
    '' n \
    3 `# import family key` \
    "${BATS_TEST_TMPDIR}/missing.secret_family_key" `# rejected, asked again` \
    "$key" \
    n `# legacy MyFamily` \
    4 '' '' '' '' '' \
    y

  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Expected a 96-byte Tor family key file"* ]]
  [[ "$output" == *"FamilyId flIHuuYy2vCWg+FgNibpOOHpRQ7rALbVUlS0WMmmuI8"* ]]
  [[ "$output" == *"ops.secret_family_key"* ]]
  [[ "$output" == *"Dry run complete."* ]]
}

@test "declining the final review aborts without changes" {
  run dry_run n n E2eGuard 2 ops@example.org '' n 1 4 '' '' '' '' '' n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Aborted before making changes."* ]]
  [[ "$output" != *"Applying Changes"* ]]
}

@test "exit setup stops when provider permission is not confirmed" {
  run dry_run n y E2eExit 2 abuse@example.org '' n n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Exit relay setup aborted."* ]]
}
