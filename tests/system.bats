#!/usr/bin/env bats
# Tests for helpers that inspect the system, using PATH stubs instead of the
# real ufw, apt-cache, and gpg.

setup() {
  load test_helper
  load_script
  use_stubs
}

@test "inactive UFW is detected" {
  write_stub ufw << 'EOF'
#!/usr/bin/env bash
printf 'Status: inactive\n'
EOF
  detect_firewall
  [ "$FIREWALL_KIND" = ufw ]
  [ "$FIREWALL_STATE" = inactive ]
}

@test "active UFW is detected" {
  write_stub ufw << 'EOF'
#!/usr/bin/env bash
printf 'Status: active\n'
EOF
  detect_firewall
  [ "$FIREWALL_STATE" = active ]
}

@test "apt candidate from another origin is rejected even if Tor's is installed" {
  write_stub apt-cache << 'EOF'
#!/usr/bin/env bash
cat << 'POLICY'
tor:
  Installed: 0.4.9.13-1~d13.trixie+1
  Candidate: 99.0-evil1
  Version table:
     99.0-evil1 1001
       1001 http://evil.example/debian trixie/main amd64 Packages
 *** 0.4.9.13-1~d13.trixie+1 100
       500 https://deb.torproject.org/torproject.org trixie/main amd64 Packages
POLICY
EOF
  run tor_candidate_from_tor_project
  [ "$status" -ne 0 ]
}

@test "apt candidate from deb.torproject.org is accepted" {
  write_stub apt-cache << 'EOF'
#!/usr/bin/env bash
cat << 'POLICY'
tor:
  Installed: (none)
  Candidate: 0.4.9.13-1~d13.trixie+1
  Version table:
     0.4.9.13-1~d13.trixie+1 500
       500 https://deb.torproject.org/torproject.org trixie/main amd64 Packages
     0.4.8.16-1 500
       500 http://deb.debian.org/debian trixie/main amd64 Packages
POLICY
EOF
  tor_candidate_from_tor_project
}

gpg_stub() {
  write_stub gpg << 'EOF'
#!/usr/bin/env bash
printf 'pub:-:2048:1:EE8CBC9E886DDD89:1:::-:::scESC::::::23::0:\n'
printf 'fpr:::::::::A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89:\n'
printf 'sub:-:2048:1:74A941BA219EC810:1:::::s::::::23:\n'
printf 'fpr:::::::::2265EB4CB2BF88D900AE8D1B74A941BA219EC810:\n'
if [[ "${STUB_EXTRA_KEY:-0}" == "1" ]]; then
  printf 'pub:-:4096:1:1111111111111111:1:::-:::scESC::::::23::0:\n'
  printf 'fpr:::::::::1111111111111111111111111111111111111111:\n'
fi
EOF
}

@test "the genuine Tor signing key file is accepted" {
  gpg_stub
  DRY_RUN=0
  run verify_tor_signing_key_file /dev/null
  [ "$status" -eq 0 ]
}

@test "a key file with an extra primary key is rejected" {
  gpg_stub
  DRY_RUN=0
  export STUB_EXTRA_KEY=1
  run verify_tor_signing_key_file /dev/null
  [ "$status" -ne 0 ]
  [[ "$output" == *"Unexpected Tor Project signing key"* ]]
}
