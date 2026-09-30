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

@test "guard relay dry run with a steady 10TB budget" {
  run dry_run \
    n `# change hostname` \
    n `# exit relay` \
    E2eGuard \
    'email:ops[]example.org ciissversion:2' \
    '' `# ORPort 9001` \
    n `# IPv6` \
    n `# other relays in family` \
    1 `# steady monthly budget` \
    10TB \
    '' `# headroom 10%` \
    1 `# combined in+out` \
    '' `# unattended upgrades` \
    '' `# nyx` \
    '' `# ufw rules + enable` \
    '' `# sandbox` \
    y `# apply`

  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Nickname E2eGuard"* ]]
  [[ "$output" == *'ContactInfo "email:ops[]example.org ciissversion:2"'* ]]
  [[ "$output" == *"ExitRelay 0"* ]]
  [[ "$output" == *"RelayBandwidthRate 1640 KBytes"* ]]
  [[ "$output" == *"AccountingMax 8381 GBytes"* ]]
  [[ "$output" == *"ufw allow 9001/tcp"* ]]
  [[ "$output" == *"apt-get install -y tor"* || "$output" == *"Would install tor"* ]]
  [[ "$output" == *"Dry run complete."* ]]
  [[ "$output" != *"[ERROR]"* ]]
}

@test "exit relay dry run with IPv6, reduced policy, and Unbound" {
  run dry_run \
    n `# change hostname` \
    y `# exit relay` \
    E2eExit \
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
    n `# other relays in family` \
    4 `# no bandwidth cap` \
    '' `# unattended upgrades` \
    n `# nyx` \
    '' `# ufw rules + enable` \
    '' `# sandbox` \
    y `# apply`

  printf '%s\n' "$output"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ExitRelay 1"* ]]
  [[ "$output" == *"ReducedExitPolicy 1"* ]]
  [[ "$output" == *"IPv6Exit 1"* ]]
  [[ "$output" == *"ORPort [2001:db8::10]:443"* ]]
  [[ "$output" == *"apt-get install -y unbound"* ]]
  [[ "$output" == *"Dry run complete."* ]]
}

@test "declining the final review aborts without changes" {
  run dry_run n n E2eGuard ops@example.org '' n n 4 '' '' '' '' n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Aborted before making changes."* ]]
  [[ "$output" != *"Applying Changes"* ]]
}

@test "exit setup stops when provider permission is not confirmed" {
  run dry_run n y E2eExit abuse@example.org '' n n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Exit relay setup aborted."* ]]
}
