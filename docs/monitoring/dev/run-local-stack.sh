#!/usr/bin/env bash
# Run Prometheus and Grafana on this machine with exactly the configuration,
# rules and dashboards `tor-relay-setup monitor install` provisions, to look
# at the fleet dashboards in a browser without a management server.
#
#   docs/monitoring/dev/run-local-stack.sh fetch    # download Prometheus and Grafana OSS (checksums pinned)
#   docs/monitoring/dev/run-local-stack.sh start    # Prometheus 127.0.0.1:9090, Grafana 127.0.0.1:3000
#   docs/monitoring/dev/run-local-stack.sh check    # every panel query must return data
#   docs/monitoring/dev/run-local-stack.sh stop
#
# start scrapes fleet serve on $FLEET_ADDR (default 127.0.0.1:9850) with the
# bearer token in $TOKEN_FILE (default $STACK_DIR/token, created on first
# start; its SHA-256 is printed for serve.toml's metrics_token_sha256).
# Three ways to feed it:
#
#   # 1. Let the script run `fleet serve --demo` with the serve.toml that
#   #    monitor install writes (and a fresh token):
#   SERVE_BIN=bin/tor-relay-setup docs/monitoring/dev/run-local-stack.sh start
#
#   # 2. A `fleet serve --demo` that already runs with its documented token:
#   printf trs_demo_metrics_token_not_secret > /tmp/demo-token
#   TOKEN_FILE=/tmp/demo-token docs/monitoring/dev/run-local-stack.sh start
#
#   # 3. The synthetic fleet in dev/fakefleet, with two days of history:
#   FAKE=1 BACKFILL_DAYS=2 docs/monitoring/dev/run-local-stack.sh start
#
# Environment: STACK_DIR (default .local-stack in the repository), TOKEN_FILE,
# FLEET_ADDR, SERVE_BIN, FAKE=1, BACKFILL_DAYS=N, PRIVACY=1 (fakefleet
# without per-relay traffic).
# Run it from the repository; it needs go, curl, sha256sum and tar.
set -euo pipefail

PROMETHEUS_VERSION=2.53.5
PROMETHEUS_SHA256=456eb31530484d181e860e329fa0c6628e79eb388fac670cdeb4fa5d57c74ed9
GRAFANA_VERSION=13.2.3
GRAFANA_SHA256=6107ad27016296aac38e0d7ffa8753ab540b5541ad27e94790f771289d733235

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
dir=${STACK_DIR:-$repo/.local-stack}
token_file=${TOKEN_FILE:-$dir/token}
fleet_addr=${FLEET_ADDR:-127.0.0.1:9850}
prom_home=$dir/prometheus-$PROMETHEUS_VERSION.linux-amd64
graf_home=$dir/grafana-$GRAFANA_VERSION
admin_user=tor-admin

say() { printf '==> %s\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

fetch() {
  mkdir -p "$dir"
  cd "$dir"
  local p="prometheus-$PROMETHEUS_VERSION.linux-amd64.tar.gz"
  local g="grafana-$GRAFANA_VERSION.linux-amd64.tar.gz"
  [ -f "$p" ] || curl -fL --proto '=https' -o "$p" "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/$p"
  [ -f "$g" ] || curl -fL --proto '=https' -o "$g" "https://dl.grafana.com/oss/release/$g"
  printf '%s  %s\n%s  %s\n' "$PROMETHEUS_SHA256" "$p" "$GRAFANA_SHA256" "$g" | sha256sum -c -
  tar xzf "$p"
  tar xzf "$g"
  say "Prometheus and Grafana unpacked in $dir"
}

running() { [ -f "$dir/$1.pid" ] && kill -0 "$(cat "$dir/$1.pid")" 2> /dev/null; }

stop() {
  for s in grafana prometheus fakefleet serve; do
    if running "$s"; then
      kill "$(cat "$dir/$s.pid")"
      say "stopped $s"
    fi
    rm -f "$dir/$s.pid"
  done
}

wait_http() {
  for _ in $(seq 1 90); do
    if curl -fs -o /dev/null "$1"; then
      return 0
    fi
    sleep 1
  done
  die "$1 did not answer; see $dir/logs"
}

start() {
  [ -x "$prom_home/prometheus" ] && [ -x "$graf_home/bin/grafana" ] || die "run '$0 fetch' first"
  stop
  mkdir -p "$dir/logs" "$dir/data/prometheus" "$dir/data/grafana"
  if [ ! -s "$token_file" ]; then
    (umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$token_file")
  fi
  say "metrics token: $token_file"
  say "serve.toml: metrics_token_sha256 = \"$(tr -d '\n' < "$token_file" | sha256sum | cut -d' ' -f1)\""

  say "rendering the monitor install configuration"
  (cd "$repo" && go run ./docs/monitoring/dev/render -out "$dir/config" -domain 127.0.0.1.nip.io -target "$fleet_addr" -token-file "$token_file" > /dev/null)
  cp "$token_file" "$dir/config/prometheus/token"
  # The grafana package creates these provisioning directories.
  mkdir -p "$dir/config/grafana/provisioning/alerting" "$dir/config/grafana/provisioning/plugins"

  if [ -n "${SERVE_BIN:-}" ]; then
    # The generated serve.toml has no users, so --demo adds its demo login.
    "$SERVE_BIN" fleet serve --demo --config "$dir/config/serve.toml" > "$dir/logs/serve.log" 2>&1 &
    echo $! > "$dir/serve.pid"
    wait_http "http://$fleet_addr/healthz"
    say "fleet serve --demo on http://$fleet_addr/ (web login demo / tor-relay-demo)"
  fi

  if [ "${FAKE:-}" = 1 ]; then
    local privacy=()
    [ "${PRIVACY:-}" = 1 ] && privacy=(-privacy)
    (cd "$repo" && go build -o "$dir/fakefleet" ./docs/monitoring/dev/fakefleet)
    if [ -n "${BACKFILL_DAYS:-}" ]; then
      say "backfilling $BACKFILL_DAYS days of synthetic history (replaces the stored metrics)"
      rm -rf "$dir/data/prometheus"
      mkdir -p "$dir/data/prometheus"
      "$dir/fakefleet" "${privacy[@]}" -openmetrics "$dir/backfill.om" -days "$BACKFILL_DAYS"
      "$prom_home/promtool" tsdb create-blocks-from openmetrics "$dir/backfill.om" "$dir/data/prometheus" > "$dir/logs/backfill.log"
      rm -f "$dir/backfill.om"
    fi
    "$dir/fakefleet" "${privacy[@]}" -listen "$fleet_addr" -token-file "$token_file" > "$dir/logs/fakefleet.log" 2>&1 &
    echo $! > "$dir/fakefleet.pid"
  fi

  # Same flags as /etc/default/prometheus, plus the local paths.
  "$prom_home/prometheus" \
    --config.file="$dir/config/prometheus/prometheus.yml" \
    --storage.tsdb.path="$dir/data/prometheus" \
    --web.listen-address=127.0.0.1:9090 \
    --storage.tsdb.retention.time=400d --storage.tsdb.retention.size=20GB \
    > "$dir/logs/prometheus.log" 2>&1 &
  echo $! > "$dir/prometheus.pid"

  # grafana.ini as monitor install writes it; only paths, the URL and the
  # cookie/HSTS settings that need HTTPS are overridden for 127.0.0.1, and
  # basic auth is allowed so 'check' can use the API.
  export GF_PATHS_DATA="$dir/data/grafana" GF_PATHS_LOGS="$dir/logs" \
    GF_PATHS_PLUGINS="$dir/data/grafana/plugins" GF_PATHS_PROVISIONING="$dir/config/grafana/provisioning" \
    GF_SERVER_DOMAIN=127.0.0.1 GF_SERVER_ROOT_URL=http://127.0.0.1:3000/ \
    GF_SECURITY_COOKIE_SECURE=false GF_SECURITY_STRICT_TRANSPORT_SECURITY=false \
    GF_AUTH_BASIC_ENABLED=true \
    GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH="$dir/config/grafana/dashboards/tor-fleet-overview.json"
  local pw_file=$dir/grafana-admin
  rm -f "$dir/logs/grafana.log"
  if [ ! -s "$pw_file" ]; then
    (umask 077 && head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$pw_file")
    "$graf_home/bin/grafana" cli --homepath "$graf_home" --config "$dir/config/grafana/grafana.ini" \
      admin reset-admin-password --password-from-stdin < "$pw_file" > "$dir/logs/grafana-cli.log" 2>&1
  fi
  "$graf_home/bin/grafana" server --homepath "$graf_home" --config "$dir/config/grafana/grafana.ini" \
    > "$dir/logs/grafana.out" 2>&1 &
  echo $! > "$dir/grafana.pid"

  wait_http http://127.0.0.1:9090/-/ready
  wait_http http://127.0.0.1:3000/api/health
  say "Prometheus  http://127.0.0.1:9090/targets"
  say "Grafana     http://127.0.0.1:3000/  user $admin_user, password in $pw_file"
  if grep -iE 'level=(error|crit)' "$dir/logs/grafana.log" | grep -i provision; then
    die "Grafana reported provisioning errors (above)"
  fi
}

check() {
  (cd "$repo" && go run ./docs/monitoring/dev/checkpanels -url http://127.0.0.1:3000 -user "$admin_user" -password-file "$dir/grafana-admin" "$@")
}

case "${1:-}" in
  fetch) fetch ;;
  start) start ;;
  stop) stop ;;
  check)
    shift
    check "$@"
    ;;
  *)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
