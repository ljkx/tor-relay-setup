#!/usr/bin/env bash
# Tests source this file with TOR_RELAY_SETUP_SOURCE_ONLY=1 to reach the
# helpers; strict mode and traps are only installed for real runs.
if [[ "${TOR_RELAY_SETUP_SOURCE_ONLY:-0}" != "1" ]]; then
  set -Eeuo pipefail
fi

SCRIPT_NAME="${0##*/}"
case "$SCRIPT_NAME" in
  bash | sh | dash | bash.exe | sh.exe | dash.exe)
    SCRIPT_NAME="setup-tor-guard-relay.sh"
    ;;
esac
VERSION="2.0.0-beta.1"
DRY_RUN=0
CLEANUP_MODE=0
USE_FZF=0
PLAIN_TUI=0
INSTALL_FZF=0

TMP_DIR=""
TIMESTAMP=""
BACKUPS_CREATED=()
RUN_LOCK_PATH=""
LAST_BACKUP_PATH=""
COMMAND_LOG_DIR=""
LAST_COMMAND_LOG=""
STEP_NUMBER=0
CURRENT_STEP_LABEL=""
CURRENT_STEP_TITLE=""
SELECTED_RELAY_FINGERPRINTS=()

OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""
OS_PRETTY_NAME=""
ARCHITECTURE=""

CHANGE_HOSTNAME=0
CURRENT_HOSTNAME=""
NEW_HOSTNAME=""

RELAY_NICKNAME=""
CONTACT_INFO=""
OR_PORT="9001"
ENABLE_IPV6=0
IPV6_ADDRESS=""
IPV6_MANUAL_OVERRIDE=0
RELAY_MODE="guard"
EXIT_POLICY_MODE="reduced"
EXIT_ALLOW_IPV6=0
CONFIGURE_UNBOUND=0
LOCK_RESOLV_CONF=0
CONFIGURE_RELAY_BANDWIDTH=0
RELAY_BANDWIDTH_RATE_VALUE=""
RELAY_BANDWIDTH_RATE_UNIT="MBits"
RELAY_BANDWIDTH_BURST_VALUE=""
RELAY_BANDWIDTH_BURST_UNIT="MBits"
CONFIGURE_ACCOUNTING=0
ACCOUNTING_MAX_GBYTES=""
ACCOUNTING_RULE="max"
BANDWIDTH_MODE="none"
MONTHLY_TRAFFIC_INPUT=""
MONTHLY_TRAFFIC_GBYTES=""
MONTHLY_TRAFFIC_USABLE_GBYTES=""
MONTHLY_TRAFFIC_HEADROOM_PERCENT=10
MONTHLY_TRAFFIC_BILLING_RULE="sum"
STEADY_PER_DIRECTION_GBYTES=""
ENABLE_AUTO_UPDATES=1
INSTALL_NYX=1
ENABLE_FIREWALL=0
FIREWALL_KIND="none"
FIREWALL_STATE="unavailable"
INSTALL_UFW=0
ENABLE_UFW_AFTER_RULES=0
SSH_PORTS_FOR_UFW="22"
ENABLE_TOR_SANDBOX=1
CONFIGURE_METRICS_PORT=0
METRICS_PORT_ADDRESS="127.0.0.1:9035"
INITIAL_MYFAMILY_AFTER_SETUP=0
CONTACT_INFO_URL=""
FAMILY_MODE="none"
FAMILY_ID=""
FAMILY_KEY_NAME="relay-family"
FAMILY_IMPORT_KEY_PATH=""
FAMILY_KEY_HEADER="== ed25519v1-secret: fmly-id =="

# Tor 0.4.8 reached end-of-life on 2026-06-01 and the directory authorities
# now reject it (tor 0.4.9.12 release notes), so 0.4.9 is the floor.
MIN_TOR_VERSION="0.4.9"

TORRC_PATH="/etc/tor/torrc"
TOR_SERVICE_DEFAULTS_TORRC="/usr/share/tor/tor-service-defaults-torrc"
TOR_APT_BASE_URL="https://deb.torproject.org/torproject.org"
TOR_SIGNING_KEY_FINGERPRINT="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
TOR_SOURCES_PATH="/etc/apt/sources.list.d/tor.sources"
TOR_KEYRING_PATH="/usr/share/keyrings/deb.torproject.org-keyring.gpg"
UNATTENDED_TOR_PATH="/etc/apt/apt.conf.d/52tor-relay-unattended-upgrades"
AUTO_UPGRADES_PATH="/etc/apt/apt.conf.d/20auto-upgrades"
TOR_SERVICE="tor@default"
RESOLV_CONF_PATH="/etc/resolv.conf"
ONIONOO_BASE_URL="https://onionoo.torproject.org"
STATE_DIR="/var/lib/tor-relay-setup"
STATE_FILE="${STATE_DIR}/install-state"
# fzf palette: -1 keeps the terminal's own foreground/background so panels
# blend into any theme; accents use the 256-colour palette.
FZF_COLORS="fg:-1,bg:-1,hl:81,fg+:255,bg+:24,hl+:51,prompt:43,pointer:43,marker:154,info:141,border:66,header:110"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  CYAN=$'\033[36m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  CYAN=""
  RESET=""
fi

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
    case "$TMP_DIR" in
      /tmp/* | /var/tmp/*)
        rm -rf -- "$TMP_DIR"
        ;;
      *)
        warn "Refusing to remove unexpected temporary directory: ${TMP_DIR}"
        ;;
    esac
  fi
}

on_error() {
  local exit_code=$?
  local line_number=${1:-unknown}
  printf '\n%b[ERROR]%b %s failed near line %s (exit %s).\n' "$RED" "$RESET" "$SCRIPT_NAME" "$line_number" "$exit_code" >&2
  printf '%b       Review the message above, fix the issue, and re-run the script.%b\n' "$DIM" "$RESET" >&2
  exit "$exit_code"
}

on_interrupt() {
  printf '\n%b[STOP]%b Interrupted. No further changes will be made.\n' "$YELLOW" "$RESET" >&2
  exit 130
}

install_traps() {
  trap cleanup EXIT
  trap 'on_error "$LINENO"' ERR
  trap on_interrupt INT TERM
}

print_help() {
  cat << EOF
${SCRIPT_NAME} ${VERSION}

Interactively configure a Tor relay on a fresh Debian or Ubuntu VPS.

Usage:
  ./${SCRIPT_NAME}
  ./${SCRIPT_NAME} --dry-run
  ./${SCRIPT_NAME} --uninstall
  ./${SCRIPT_NAME} --plain
  ./${SCRIPT_NAME} --help

Options:
  --dry-run   Prompt normally and print the system changes that would be made,
              without installing packages or writing system files.
  --uninstall Remove traces of this installer/tool only. It does not remove
              Tor, torrc, relay keys, firewall rules, logs, or relay state.
  --plain     Use the built-in line interface instead of the fzf selectors.
  --help      Show this help text and exit.
  --version   Show the script version and exit.

Supported targets:
  Debian and Ubuntu releases whose codenames are published by the
  official Tor Project apt repository.

This script can configure either a Guard/middle relay or an exit relay.
If an existing relay is detected, it opens the relay operator console:
relay family (FamilyId keys and legacy MyFamily), health checks, directory
status, service controls, logs, safe config edits, backups, package tools,
repair, and script cleanup.

Requires tor ${MIN_TOR_VERSION} or newer, installed from deb.torproject.org.
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --uninstall)
        CLEANUP_MODE=1
        ;;
      --plain | --no-tui)
        PLAIN_TUI=1
        ;;
      --help | -h)
        print_help
        exit 0
        ;;
      --version)
        printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"
        exit 0
        ;;
      *)
        printf '%b[ERROR]%b Unknown option: %s\n\n' "$RED" "$RESET" "$1" >&2
        print_help >&2
        exit 2
        ;;
    esac
    shift
  done
}

banner() {
  printf '\n%bTor Relay Setup%b %s\n' "$BOLD$CYAN" "$RESET" "$VERSION"
  printf '%s\n' "Guided installer for public Guard/middle and exit relays."
  printf '%s\n\n' "It reviews privileged changes before applying them."
}

section() {
  STEP_NUMBER=$((STEP_NUMBER + 1))
  CURRENT_STEP_LABEL=$(printf '%02d' "$STEP_NUMBER")
  CURRENT_STEP_TITLE=$1
  printf '\n%b[%s]%b %b+--%b %b%s%b\n' "$CYAN" "$CURRENT_STEP_LABEL" "$RESET" "$DIM" "$RESET" "$BOLD$BLUE" "$CURRENT_STEP_TITLE" "$RESET"
}

step_prefix() {
  if [[ -n "${CURRENT_STEP_LABEL:-}" ]]; then
    printf '%b[%s]%b %b|%b ' "$CYAN" "$CURRENT_STEP_LABEL" "$RESET" "$DIM" "$RESET"
  fi
}

prompt_step_prefix() {
  if [[ -z "${CURRENT_STEP_LABEL:-}" ]]; then
    return 0
  fi

  step_prefix >&2
}

info() {
  step_prefix
  printf '%b[INFO]%b %s\n' "$BLUE" "$RESET" "$*"
}

success() {
  step_prefix
  printf '%b[OK]%b %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
  step_prefix >&2
  printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$*" >&2
}

die() {
  step_prefix >&2
  printf '%b[ERROR]%b %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

acquire_run_lock() {
  local lock_path

  if ! command_exists flock; then
    warn "flock is not available; continuing without a single-run lock."
    return 0
  fi

  for lock_path in /run/lock/tor-relay-setup.lock /tmp/tor-relay-setup.lock; do
    RUN_LOCK_PATH=$lock_path
    if { exec 9> "$RUN_LOCK_PATH"; } 2> /dev/null; then
      if ! flock -n 9; then
        die "Another ${SCRIPT_NAME} run appears to be active (${RUN_LOCK_PATH})."
      fi
      return 0
    fi

    warn "Could not open lock file at ${RUN_LOCK_PATH}; trying a fallback path."
  done

  die "Could not create a lock file in /run/lock or /tmp."
}

fzf_available() {
  ((USE_FZF)) \
    && command_exists fzf \
    && [[ -e /dev/tty && -r /dev/tty && -w /dev/tty ]] \
    && [[ -n "${TERM:-}" && "${TERM:-}" != "dumb" ]]
}

tui_available() {
  fzf_available
}

bootstrap_tui() {
  ((PLAIN_TUI)) && {
    info "Plain terminal mode selected."
    return 0
  }

  if command_exists fzf && [[ -e /dev/tty && -r /dev/tty && -w /dev/tty ]] && [[ -n "${TERM:-}" && "${TERM:-}" != "dumb" ]]; then
    USE_FZF=1
    success "Polished selector mode enabled with fzf."
    return 0
  fi

  if ((DRY_RUN)); then
    warn "fzf is not installed. Dry run will use the built-in line interface."
    return 0
  fi

  warn "fzf is not installed. It powers the searchable setup interface."
  warn "Installing it now runs apt-get update and apt-get install -y fzf before the final relay review."
  if ask_yes_no "Install fzf now and use the full selector interface for this run?" "no"; then
    install_fzf_for_current_run
    return 0
  fi

  warn "Plain line mode selected because fzf installation was declined."
}

python_command() {
  if command_exists python3 && python3 -c 'import json, sys' > /dev/null 2>&1; then
    printf 'python3'
    return 0
  fi

  if command_exists python && python -c 'import json, sys' > /dev/null 2>&1; then
    printf 'python'
    return 0
  fi

  return 1
}

apt_package_available() {
  local package=$1
  local candidate

  command_exists apt-cache || return 1
  candidate=$(apt-cache policy "$package" 2> /dev/null | awk '/Candidate:/ { print $2; exit }')
  [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

apt_package_installed() {
  local package=$1
  command_exists dpkg-query || return 1
  dpkg-query -W -f='${Status}' "$package" 2> /dev/null | grep -Fq 'install ok installed'
}

tor_candidate_from_tor_project() {
  command_exists apt-cache || return 1
  apt-cache policy tor 2> /dev/null | awk '
    $1 == "Candidate:" {
      candidate = $2
      next
    }
    candidate == "" || candidate == "(none)" {
      next
    }
    $1 == "***" {
      in_candidate = ($2 == candidate)
      next
    }
    $1 ~ /^[0-9]/ && $2 ~ /^[0-9]+$/ {
      in_candidate = ($1 == candidate)
      next
    }
    in_candidate && /deb\.torproject\.org\/torproject\.org/ {
      ok = 1
      exit
    }
    END {
      exit ok ? 0 : 1
    }
  '
}

verify_tor_signing_key_file() {
  local key_file=$1
  local fingerprint

  if ((DRY_RUN)); then
    info "Would verify Tor Project signing key fingerprint ${TOR_SIGNING_KEY_FINGERPRINT}."
    return 0
  fi

  # Print every primary-key fingerprint. Exactly one is allowed, so a key file
  # with an extra injected key cannot slip into the apt keyring.
  fingerprint=$(gpg --show-keys --with-colons --fingerprint "$key_file" 2> /dev/null \
    | awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print toupper($10); want = 0 }' \
    | paste -sd ' ' -)

  if [[ "$fingerprint" != "$TOR_SIGNING_KEY_FINGERPRINT" ]]; then
    die "Unexpected Tor Project signing key fingerprint '${fingerprint:-unreadable}'. Expected ${TOR_SIGNING_KEY_FINGERPRINT}."
  fi
  success "Verified Tor Project signing key fingerprint."
}

tor_project_suite_url() {
  printf '%s/dists/%s/Release' "$TOR_APT_BASE_URL" "$OS_CODENAME"
}

check_tor_project_suite() {
  local mode=${1:-required}
  local url
  local status

  url=$(tor_project_suite_url)

  if ((DRY_RUN)); then
    info "Would verify official Tor Project apt suite: ${url}"
    return 0
  fi

  if command_exists curl; then
    status=$(curl -L -sS -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 20 "$url" 2> /dev/null || true)
    status=${status:-000}
    case "$status" in
      200)
        success "Official Tor Project apt suite found for '${OS_CODENAME}'."
        return 0
        ;;
      404)
        die "The official Tor Project apt repository does not publish suite '${OS_CODENAME}' yet. Check ${TOR_APT_BASE_URL}/dists/ or use a supported Debian/Ubuntu release."
        ;;
      000)
        if [[ "$mode" == "optional" ]]; then
          warn "Could not verify the Tor Project apt suite yet; will retry before adding the Tor repository."
          return 0
        fi
        die "Could not reach ${url}. Check DNS/network connectivity and retry."
        ;;
      *)
        if [[ "$mode" == "optional" ]]; then
          warn "Tor Project apt suite check returned HTTP ${status}; will retry before adding the Tor repository."
          return 0
        fi
        die "Tor Project apt suite check returned unexpected HTTP ${status} for ${url}."
        ;;
    esac
  fi

  if command_exists wget; then
    if wget -q --spider "$url"; then
      success "Official Tor Project apt suite found for '${OS_CODENAME}'."
      return 0
    fi

    if [[ "$mode" == "optional" ]]; then
      warn "Could not verify the Tor Project apt suite yet; will retry before adding the Tor repository."
      return 0
    fi
    die "Could not verify ${url}. Check whether the Tor Project apt repository publishes suite '${OS_CODENAME}'."
  fi

  if [[ "$mode" == "optional" ]]; then
    warn "curl/wget is not available yet, so Tor Project apt suite verification is deferred."
    return 0
  fi

  die "curl or wget is required to verify the Tor Project apt repository suite."
}

print_command() {
  printf '    +'
  printf ' %q' "$@"
  printf '\n'
}

shell_quote() {
  printf '%q' "$1"
}

ensure_command_log_dir() {
  if [[ -z "${COMMAND_LOG_DIR:-}" ]]; then
    COMMAND_LOG_DIR="${TMP_DIR:-/tmp}/command-logs"
  fi
  mkdir -p "$COMMAND_LOG_DIR"
}

command_log_path() {
  local description=$1
  local safe_description

  ensure_command_log_dir
  safe_description=$(printf '%s' "$description" | tr -cs '[:alnum:]' '-' | sed 's/^-//; s/-$//; s/--*/-/g')
  safe_description=${safe_description:-command}
  mktemp "${COMMAND_LOG_DIR%/}/$(date -u '+%H%M%S').${safe_description}.XXXXXX.log"
}

write_command_header() {
  local log_file=$1
  local description=$2
  shift 2

  {
    printf 'Tor Relay Setup command window\n'
    printf 'Started: %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
    printf 'Action: %s\n' "$description"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'
  } > "$log_file"
}

show_file_panel() {
  local title=$1
  local file=$2
  local display_file

  if [[ ! -s "$file" ]]; then
    printf '(no output)\n' > "$file"
  fi

  if tui_available; then
    display_file=$(mktemp_in_workspace)
    # Drop leading blank lines, then number the rest.
    sed '/./,$!d' "$file" | nl -ba -w4 -s '  ' > "$display_file"
    # --ansi renders the bold/colour codes the review summary contains.
    env FZF_DEFAULT_OPTS= fzf \
      --ansi \
      --height=90% \
      --reverse \
      --border \
      --margin=1,2 \
      --disabled \
      --no-sort \
      --prompt="view> " \
      --pointer=">" \
      --header="${title} | Scroll with arrows/PageUp/PageDown. Enter, q, or Esc returns." \
      --bind=enter:accept,q:abort \
      --color="$FZF_COLORS" \
      < "$display_file" > /dev/null || true
    rm -f -- "$display_file"
  else
    printf '\n%s\n' "$title"
    sed -n '1,240p' "$file"
  fi
}

show_live_log_panel() {
  local title=$1
  local file=$2
  local pid=$3
  local input_file
  local quoted_file
  local preview_command

  tui_available || return 0

  input_file=$(mktemp_in_workspace)
  printf 'output\t%s\t%s\n' "$title" "Command output streams in the preview pane." > "$input_file"
  quoted_file=$(shell_quote "$file")
  if tail --help 2> /dev/null | grep -Fq -- '--pid'; then
    preview_command="tail --pid=${pid} -n +1 -f ${quoted_file}"
  else
    preview_command="tail -n +1 -f ${quoted_file}"
  fi

  env FZF_DEFAULT_OPTS= fzf \
    --height=90% \
    --reverse \
    --border \
    --margin=1,2 \
    --disabled \
    --no-sort \
    --delimiter=$'\t' \
    --with-nth=2,3 \
    --prompt="command> " \
    --pointer=">" \
    --header="CLI window: watch output below. Press Enter after the command finishes; Esc returns and waits safely." \
    --preview="$preview_command" \
    --preview-window=down:82%:wrap:follow \
    --bind=enter:accept,q:abort \
    --color="$FZF_COLORS" \
    < "$input_file" > /dev/null || true
  rm -f -- "$input_file"
}

run_tui_command() {
  local description=$1
  local log_file
  local exit_code
  local pid
  shift

  log_file=$(command_log_path "$description")
  LAST_COMMAND_LOG=$log_file
  write_command_header "$log_file" "$description" "$@"

  (
    set +e
    if command_exists stdbuf; then
      stdbuf -oL -eL "$@"
    else
      "$@"
    fi
    exit_code=$?
    printf '\n[exit %s]\n' "$exit_code"
    exit "$exit_code"
  ) >> "$log_file" 2>&1 &
  pid=$!

  show_live_log_panel "$description" "$log_file" "$pid"
  if kill -0 "$pid" 2> /dev/null; then
    info "Waiting for '${description}' to finish. Output is still being written to ${log_file}."
  fi

  set +e
  wait "$pid"
  exit_code=$?
  set -e

  if ((exit_code == 0)); then
    success "${description} completed. Log: ${log_file}"
  else
    warn "${description} failed with exit ${exit_code}. Showing command log."
    show_file_panel "Command failed: ${description}" "$log_file"
  fi
  return "$exit_code"
}

run_cmd() {
  local description=$1
  local exit_code
  shift

  info "$description"
  if ((DRY_RUN)); then
    print_command "$@"
    return 0
  fi

  if tui_available; then
    run_tui_command "$description" "$@"
    return $?
  fi

  set +e
  "$@"
  exit_code=$?
  set -e

  if ((exit_code != 0)); then
    printf '%b[ERROR]%b Command failed with exit %s:' "$RED" "$RESET" "$exit_code" >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    return "$exit_code"
  fi
}

capture_command_panel() {
  local title=$1
  local log_file
  local exit_code
  shift

  log_file=$(command_log_path "$title")
  LAST_COMMAND_LOG=$log_file
  write_command_header "$log_file" "$title" "$@"

  set +e
  "$@" >> "$log_file" 2>&1
  exit_code=$?
  set -e
  printf '\n[exit %s]\n' "$exit_code" >> "$log_file"

  show_file_panel "$title" "$log_file"
  return "$exit_code"
}

follow_command_panel() {
  local title=$1
  local log_file
  local pid
  shift

  if ! tui_available; then
    info "Press Ctrl+C to stop following logs."
    "$@" || true
    return 0
  fi

  log_file=$(command_log_path "$title")
  LAST_COMMAND_LOG=$log_file
  write_command_header "$log_file" "$title" "$@"

  "$@" >> "$log_file" 2>&1 &
  pid=$!
  show_live_log_panel "$title" "$log_file" "$pid"
  if kill -0 "$pid" 2> /dev/null; then
    kill "$pid" 2> /dev/null || true
  fi
  wait "$pid" 2> /dev/null || true
}

install_fzf_for_current_run() {
  local fzf_was_installed=0

  apt_package_installed fzf && fzf_was_installed=1

  if command_exists df; then
    check_path_capacity /var/lib/apt/lists 128000 2048
    check_path_capacity /var/cache/apt/archives 128000 2048
    check_path_capacity /tmp 65536 512
  fi

  run_cmd "Updating apt package lists for fzf" env DEBIAN_FRONTEND=noninteractive apt-get update
  run_cmd "Installing fzf selector interface" env DEBIAN_FRONTEND=noninteractive apt-get install -y fzf

  if ! command_exists fzf; then
    die "fzf installation completed, but fzf is still not available in PATH."
  fi

  USE_FZF=1
  if ((fzf_was_installed == 0)); then
    mark_script_installed_fzf
  fi
  success "fzf selector mode enabled for this run."
}

trim() {
  local value=$*
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

sanitize_reply() {
  local value=$1

  value=$(printf '%s' "$value" | sed -E $'s/\x1B\[[0-?]*[ -\/]*[@-~]//g')
  value=$(printf '%s' "$value" | tr -d '\000-\010\013\014\016-\037\177')
  printf '%s' "$value"
}

prompt_line() {
  local prompt=$1
  local default_value=${2:-}
  local reply

  if tui_available; then
    if ! prompt_line_fzf reply "$prompt" "$default_value"; then
      reply=$default_value
    fi
    trim "$reply"
    return 0
  fi

  prompt_step_prefix
  if [[ -n "$default_value" ]]; then
    prompt_printf '%b%s%b [%s]: ' "$BOLD" "$prompt" "$RESET" "$default_value"
  else
    prompt_printf '%b%s%b: ' "$BOLD" "$prompt" "$RESET"
  fi

  read_reply reply
  reply=$(sanitize_reply "$reply")
  if [[ -z "$reply" && -n "$default_value" ]]; then
    reply=$default_value
  fi
  trim "$reply"
}

prompt_printf() {
  local format=$1
  shift

  # shellcheck disable=SC2059
  printf "$format" "$@" >&2
}

read_reply() {
  local variable_name=$1

  if [[ -t 0 && -e /dev/tty && -r /dev/tty && -w /dev/tty ]]; then
    if IFS= read -r "${variable_name?}" < /dev/tty 2> /dev/null; then
      return 0
    fi
  fi

  if IFS= read -r "${variable_name?}"; then
    return 0
  fi

  die "Interactive input is required. Run from a terminal, or use --help for noninteractive usage."
}

ask_yes_no() {
  local prompt=$1
  local default_answer=${2:-}
  local suffix
  local reply
  local default_choice

  case "$default_answer" in
    yes) suffix="[Y/n]" ;;
    no) suffix="[y/N]" ;;
    *) suffix="[y/n]" ;;
  esac

  if tui_available; then
    case "$default_answer" in
      yes) default_choice="y" ;;
      no) default_choice="n" ;;
      *) default_choice="y" ;;
    esac
    choose_menu reply "$prompt" "$default_choice" \
      "y" "Yes" "Apply this choice" \
      "n" "No" "Skip this choice"
    case "$reply" in
      y) return 0 ;;
      n) return 1 ;;
    esac
  fi

  while true; do
    prompt_step_prefix
    prompt_printf '%b%s%b %s: ' "$BOLD" "$prompt" "$RESET" "$suffix"
    read_reply reply
    reply=$(sanitize_reply "$reply")
    reply=$(trim "$reply")
    reply=${reply,,}

    if [[ -z "$reply" && -n "$default_answer" ]]; then
      reply=$default_answer
    fi

    case "$reply" in
      y | yes) return 0 ;;
      n | no) return 1 ;;
      *) warn "Please answer yes or no." ;;
    esac
  done
}

mktemp_in_workspace() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
    mktemp "${TMP_DIR%/}/fzf.XXXXXX"
  else
    mktemp
  fi
}

choose_with_fzf() {
  local output_file=$1
  local title=$2
  local mode=$3
  local input_file=$4
  local expect_keys=${5:-}
  local prompt_label="${title}> "
  # shellcheck disable=SC2054
  local -a args=(
    --height=80%
    --reverse
    --border
    --margin=1,2
    --delimiter=$'\t'
    --with-nth=1,2
    --prompt="$prompt_label"
    --pointer=">"
    --marker="*"
    --color="$FZF_COLORS"
    --preview='printf "%s\n\n%s\n\n%s\n" {2} {3} {4}'
    --preview-window=down:6:wrap
  )

  case "$mode" in
    multi)
      args+=(--multi --bind=space:toggle --header="Space toggles rows. Enter accepts; Esc cancels.")
      ;;
    delete)
      # shellcheck disable=SC2054
      args+=(--multi --bind=space:toggle,d:accept --header="Space marks rows. Press d or Enter to review selected deletion(s); Esc goes back.")
      ;;
    single)
      args+=(--header="Type to filter. Enter selects; Esc cancels.")
      if [[ -n "$expect_keys" ]]; then
        args+=(--expect="$expect_keys")
      fi
      ;;
    *)
      die "Unknown fzf mode: ${mode}"
      ;;
  esac

  env FZF_DEFAULT_OPTS= fzf "${args[@]}" < "$input_file" > "$output_file"
}

menu_cancel_choice() {
  local default_choice=$1
  shift
  local -a options=("$@")
  local key
  local label
  local i

  for ((i = 0; i < ${#options[@]}; i += 3)); do
    key=${options[i]}
    label=${options[i + 1]}
    case "$key" in
      q | x)
        printf '%s' "$key"
        return 0
        ;;
    esac
    case "${label,,}" in
      back | exit | cancel)
        printf '%s' "$key"
        return 0
        ;;
    esac
  done

  printf '%s' "$default_choice"
}

prompt_line_fzf() {
  local result_name=$1
  local prompt=$2
  local default_value=${3:-}
  local -n result_ref=$result_name
  local list_file
  local output_file
  local query
  local -a fzf_lines=()
  # shellcheck disable=SC2054
  local -a args=(
    --height=40%
    --reverse
    --border
    --margin=1,2
    --delimiter=$'\t'
    --with-nth=2,3
    --prompt="${prompt}> "
    --pointer=">"
    --color="$FZF_COLORS"
    --print-query
    --query="$default_value"
    --phony
    --no-sort
    --header="Type the value, then press Enter. Leave blank only when the field says blank is allowed. Esc cancels."
    --preview='printf "%s\n\n%s\n" {2} {3}'
    --preview-window=down:5:wrap
  )

  list_file=$(mktemp_in_workspace)
  output_file=$(mktemp_in_workspace)
  if [[ -n "$default_value" ]]; then
    printf 'input\tCurrent default: %s\tEdit the query field or press Enter to keep the default.\n' "$default_value" > "$list_file"
  else
    printf 'input\tType a value\tEdit the query field, then press Enter.\n' > "$list_file"
  fi

  if ! env FZF_DEFAULT_OPTS= fzf "${args[@]}" < "$list_file" > "$output_file"; then
    rm -f -- "$list_file" "$output_file"
    return 1
  fi

  mapfile -t fzf_lines < "$output_file"
  rm -f -- "$list_file" "$output_file"
  query=${fzf_lines[0]:-}
  query=$(sanitize_reply "$query")
  if [[ -z "$query" && -n "$default_value" ]]; then
    query=$default_value
  fi
  result_ref=$query
}

choose_menu() {
  local result_name=$1
  local title=$2
  local default_choice=$3
  shift 3
  local -n result_ref=$result_name
  local -a options=("$@")
  local -a fzf_lines=()
  local menu_reply
  local expect_keys=""
  local key_pressed=0
  local key
  local label
  local description
  local i
  local pass

  if tui_available; then
    local list_file
    local output_file
    list_file=$(mktemp_in_workspace)
    output_file=$(mktemp_in_workspace)

    for pass in default rest; do
      for ((i = 0; i < ${#options[@]}; i += 3)); do
        key=${options[i]}
        [[ "$pass" == "default" && "$key" != "$default_choice" ]] && continue
        [[ "$pass" == "rest" && "$key" == "$default_choice" ]] && continue

        label=${options[i + 1]}
        description=${options[i + 2]}
        if [[ "$key" == "$default_choice" ]]; then
          printf '%s\t%s\t%s\t%s\n' "$key" "$label" "${description:-}" "Default if you press Enter" >> "$list_file"
        else
          printf '%s\t%s\t%s\t%s\n' "$key" "$label" "${description:-}" "" >> "$list_file"
        fi
        if [[ "$key" =~ ^[[:alnum:]]$ ]]; then
          if [[ -n "$expect_keys" ]]; then
            expect_keys+=","
          fi
          expect_keys+="$key"
        fi
      done
    done

    if ! choose_with_fzf "$output_file" "$title" single "$list_file" "$expect_keys"; then
      rm -f -- "$list_file" "$output_file"
      result_ref=$(menu_cancel_choice "$default_choice" "${options[@]}")
      return 0
    fi
    mapfile -t fzf_lines < "$output_file"
    menu_reply=${fzf_lines[0]:-}
    if [[ "$menu_reply" != *$'\t'* ]]; then
      key_pressed=0
      for ((i = 0; i < ${#options[@]}; i += 3)); do
        if [[ "$menu_reply" == "${options[i]}" ]]; then
          key_pressed=1
          break
        fi
      done
      if ((key_pressed == 0)) && ((${#fzf_lines[@]} > 1)); then
        menu_reply=${fzf_lines[1]}
      fi
    fi
    menu_reply=${menu_reply%%$'\t'*}
    rm -f -- "$list_file" "$output_file"
    result_ref=$menu_reply
    return 0
  fi

  while true; do
    step_prefix >&2
    printf '%b%s%b\n' "$BOLD" "$title" "$RESET" >&2
    for ((i = 0; i < ${#options[@]}; i += 3)); do
      key=${options[i]}
      label=${options[i + 1]}
      description=${options[i + 2]}
      step_prefix >&2
      printf '  %-4s %s' "$key)" "$label" >&2
      if [[ -n "$description" ]]; then
        printf ' - %s' "$description" >&2
      fi
      printf '\n' >&2
    done

    menu_reply=$(prompt_line "Choose" "$default_choice")
    for ((i = 0; i < ${#options[@]}; i += 3)); do
      key=${options[i]}
      if [[ "${menu_reply,,}" == "${key,,}" ]]; then
        result_ref=$key
        return 0
      fi
    done
    warn "Choose one of the listed actions."
  done
}

choose_checklist() {
  local result_name=$1
  local title=$2
  shift 2
  local fzf_mode="multi"
  if [[ "${1:-}" == "--delete" ]]; then
    fzf_mode="delete"
    shift
  fi
  local -n result_ref=$result_name
  local -a options=("$@")
  local key
  local label
  local description
  local status
  local line
  local token
  local valid_token
  local i

  result_ref=()

  if tui_available; then
    local list_file
    local output_file
    list_file=$(mktemp_in_workspace)
    output_file=$(mktemp_in_workspace)

    for ((i = 0; i < ${#options[@]}; i += 4)); do
      key=${options[i]}
      label=${options[i + 1]}
      description=${options[i + 2]}
      status=${options[i + 3]}
      printf '%s\t%s\t%s\t%s\n' "$key" "$label" "$description" "$status" >> "$list_file"
    done

    if ! choose_with_fzf "$output_file" "$title" "$fzf_mode" "$list_file"; then
      rm -f -- "$list_file" "$output_file"
      return 1
    fi

    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      result_ref+=("${line%%$'\t'*}")
    done < "$output_file"
    rm -f -- "$list_file" "$output_file"
    ((${#result_ref[@]} > 0))
    return $?
  fi

  step_prefix >&2
  printf '%b%s%b\n' "$BOLD" "$title" "$RESET" >&2
  for ((i = 0; i < ${#options[@]}; i += 4)); do
    key=${options[i]}
    label=${options[i + 1]}
    description=${options[i + 2]}
    step_prefix >&2
    printf '  %-4s %s' "$key)" "$label" >&2
    if [[ -n "$description" ]]; then
      printf ' - %s' "$description" >&2
    fi
    printf '\n' >&2
  done

  line=$(prompt_line "Choose one or more entries separated by spaces or commas (blank to cancel)")
  [[ -n "$line" ]] || return 1
  line=${line//,/ }
  read -r -a result_ref <<< "$line"

  for token in "${result_ref[@]}"; do
    valid_token=0
    for ((i = 0; i < ${#options[@]}; i += 4)); do
      if [[ "$token" == "${options[i]}" ]]; then
        valid_token=1
        break
      fi
    done
    if ((valid_token == 0)); then
      warn "Invalid selection ignored: ${token}"
    fi
  done

  local -a validated=()
  for token in "${result_ref[@]}"; do
    valid_token=0
    for ((i = 0; i < ${#options[@]}; i += 4)); do
      if [[ "$token" == "${options[i]}" ]] && ! selection_contains "$token" "${validated[@]}"; then
        validated+=("$token")
        valid_token=1
        break
      fi
    done
  done
  result_ref=("${validated[@]}")
  ((${#result_ref[@]} > 0))
}

valid_integer() {
  [[ $1 =~ ^[0-9]+$ ]]
}

valid_fingerprint() {
  [[ $1 =~ ^\$?[A-Fa-f0-9]{40}$ ]]
}

normalize_fingerprint() {
  local value=$1
  value=${value#\$}
  value=${value^^}
  printf '%s' "$value"
}

valid_percent() {
  local value=$1
  valid_integer "$value" || return 1
  ((10#$value >= 0 && 10#$value <= 50))
}

parse_traffic_to_gbytes() {
  local raw=$1
  local compact
  local number
  local unit

  compact=$(trim "$raw")
  compact=${compact//[[:space:]]/}
  compact=${compact^^}

  [[ "$compact" =~ ^([0-9]+([.][0-9]+)?)(K|KB|KIB|KBYTE|KBYTES|M|MB|MIB|MBYTE|MBYTES|G|GB|GIB|GBYTE|GBYTES|T|TB|TIB|TBYTE|TBYTES)$ ]] || return 1
  number=${BASH_REMATCH[1]}
  unit=${BASH_REMATCH[3]}

  # Providers bill in decimal units (1 TB = 10^12 bytes), while Tor's
  # AccountingMax "GBytes" are binary (2^30 bytes). Treat K/M/G/T and KB/MB/
  # GB/TB as decimal, and KiB/MiB/GiB/TiB plus Tor's KBytes/GBytes spelling as
  # binary, then return whole binary GBytes (rounded down, never up).
  awk -v number="$number" -v unit="$unit" '
    BEGIN {
      prefix = substr(unit, 1, 1)
      power = index("KMGT", prefix)
      base = (unit ~ /^.(IB|BYTE|BYTES)$/) ? 1024 : 1000
      bytes = number * (base ^ power)
      value = bytes / (1024 ^ 3)
      if (value < 1) exit 1
      printf "%d", value
    }'
}

format_mbits_from_kbytes() {
  local kbytes=$1
  local tenths
  tenths=$((10#$kbytes * 8192 / 100000))
  printf '%d.%d' "$((tenths / 10))" "$((tenths % 10))"
}

valid_port() {
  local value=$1
  valid_integer "$value" || return 1
  local number=$((10#$value))
  ((number >= 1 && number <= 65535))
}

valid_nickname() {
  [[ $1 =~ ^[A-Za-z0-9]{1,19}$ ]]
}

valid_contact_info() {
  local value=$1
  [[ -n "$value" ]] || return 1
  [[ ${#value} -le 250 ]] || return 1
  [[ "$value" != *$'\n'* ]] || return 1
  [[ "$value" != *"#"* ]] || return 1
}

valid_system_hostname() {
  local value=$1
  local label
  local lower_value=${value,,}
  local -a labels

  [[ -n "$value" && ${#value} -le 253 ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  [[ "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
  [[ "$lower_value" != "localhost" && "$lower_value" != "localhost.localdomain" ]] || return 1

  IFS='.' read -r -a labels <<< "$value"
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 ]] || return 1
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

valid_ipv6_address() {
  local value=$1
  local python_bin
  [[ "$value" == *:* ]] || return 1
  [[ "$value" != *" "* ]] || return 1
  [[ "$value" != *"["* && "$value" != *"]"* ]] || return 1
  [[ "$value" != */* ]] || return 1

  if python_bin=$(python_command); then
    "$python_bin" - "$value" << 'PY'
import ipaddress
import sys

try:
    address = ipaddress.IPv6Address(sys.argv[1])
except ValueError:
    raise SystemExit(1)

if address.is_link_local or address.is_loopback or address.is_multicast or address.is_unspecified:
    raise SystemExit(1)
PY
    return $?
  fi

  [[ "$value" =~ ^[0-9A-Fa-f:.]+$ ]]
}

torrc_quote() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

require_supported_system() {
  section "System Check"

  [[ "$(uname -s)" == "Linux" ]] || die "This installer supports Linux targets only."
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release; unsupported system."

  # shellcheck disable=SC1091
  . /etc/os-release

  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-}"
  OS_PRETTY_NAME="${PRETTY_NAME:-${OS_ID} ${OS_VERSION_ID}}"

  if [[ -z "$OS_CODENAME" ]] && command_exists lsb_release; then
    OS_CODENAME=$(lsb_release -cs)
  fi

  case "$OS_ID" in
    debian | ubuntu) ;;
    *)
      die "Unsupported OS: ${OS_PRETTY_NAME}. This installer currently supports Debian and Ubuntu releases with a Tor Project apt repository suite."
      ;;
  esac

  [[ -n "$OS_CODENAME" ]] || die "Could not detect the Debian/Ubuntu codename for ${OS_PRETTY_NAME}."

  command_exists apt-get || die "apt-get is required."
  command_exists dpkg || die "dpkg is required."
  command_exists systemctl || die "systemd/systemctl is required."

  ARCHITECTURE=$(dpkg --print-architecture)
  case "$ARCHITECTURE" in
    amd64 | arm64) ;;
    *)
      die "Unsupported CPU architecture '${ARCHITECTURE}'. The Tor Project apt repository currently offers amd64 and arm64 packages."
      ;;
  esac

  success "Accepted target: ${OS_PRETTY_NAME} (${OS_CODENAME}, ${ARCHITECTURE})"
  check_tor_project_suite optional

  if ((DRY_RUN)); then
    warn "Dry-run mode is active. No packages or system files will be changed."
  elif ((EUID != 0)); then
    die "Run this script as root, for example: sudo ./${SCRIPT_NAME}"
  fi
}

detect_firewall() {
  FIREWALL_KIND="none"
  FIREWALL_STATE="unavailable"
  INSTALL_UFW=0
  ENABLE_UFW_AFTER_RULES=0

  if command_exists ufw; then
    FIREWALL_KIND="ufw"
    local ufw_status=""
    ufw_status=$(ufw status 2> /dev/null | head -n 1 || true)
    case "${ufw_status,,}" in
      *inactive*) FIREWALL_STATE="inactive" ;;
      *active*) FIREWALL_STATE="active" ;;
      *) FIREWALL_STATE="installed" ;;
    esac
    return 0
  fi

  if command_exists firewall-cmd; then
    FIREWALL_KIND="firewalld"
    if systemctl is-active --quiet firewalld 2> /dev/null; then
      FIREWALL_STATE="active"
    else
      FIREWALL_STATE="inactive"
    fi
    return 0
  fi

  if command_exists nft; then
    if nft list chain inet filter input > /dev/null 2>&1; then
      FIREWALL_KIND="nftables"
      FIREWALL_STATE="inet filter input chain found"
    else
      FIREWALL_KIND="nftables"
      FIREWALL_STATE="no supported inet filter input chain"
    fi
  fi
}

detect_ssh_port() {
  local port=""
  local config
  local -a ports=()
  local candidate

  if command_exists sshd; then
    while IFS= read -r candidate; do
      [[ "$candidate" =~ ^[0-9]+$ ]] || continue
      ports+=("$candidate")
    done < <(sshd -T 2> /dev/null | awk 'tolower($1) == "port" { print $2 }' || true)
  fi

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    # SSH_CONNECTION: client-ip client-port server-ip server-port
    port=$(awk '{ print $4 }' <<< "$SSH_CONNECTION")
    [[ "$port" =~ ^[0-9]+$ ]] && ports+=("$port")
  fi

  if ((${#ports[@]} == 0)); then
    for config in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
      [[ -r "$config" ]] || continue
      port=$(awk '
        /^[[:space:]]*#/ { next }
        tolower($1) == "port" && $2 ~ /^[0-9]+$/ {
          print $2
          exit
        }
      ' "$config")
      [[ -n "$port" ]] && ports+=("$port")
    done
  fi

  if ((${#ports[@]} == 0)); then
    ports=("22")
  fi

  SSH_PORTS_FOR_UFW=$(printf '%s\n' "${ports[@]}" | awk '!seen[$0]++' | paste -sd ' ' -)
}

collect_firewall_options() {
  detect_firewall
  detect_ssh_port

  step_prefix
  printf '%s\n' "Detected firewall: ${FIREWALL_KIND} (${FIREWALL_STATE})"

  case "$FIREWALL_KIND:$FIREWALL_STATE" in
    none:*)
      info "No supported local firewall manager was detected."
      if ask_yes_no "Install UFW, allow SSH and TCP ${OR_PORT}, then enable it?" "yes"; then
        FIREWALL_KIND="ufw"
        FIREWALL_STATE="absent"
        INSTALL_UFW=1
        ENABLE_FIREWALL=1
        ENABLE_UFW_AFTER_RULES=1
      else
        ENABLE_FIREWALL=0
        warn "No local firewall rule will be applied. You may still need to open TCP ${OR_PORT} in the VPS provider firewall."
      fi
      ;;
    nftables:"no supported inet filter input chain")
      ENABLE_FIREWALL=0
      warn "nftables is present, but no 'inet filter input' chain was found. The script will not guess a ruleset."
      if ask_yes_no "Install UFW instead and let it manage SSH plus TCP ${OR_PORT}?" "no"; then
        FIREWALL_KIND="ufw"
        FIREWALL_STATE="absent"
        INSTALL_UFW=1
        ENABLE_FIREWALL=1
        ENABLE_UFW_AFTER_RULES=1
      fi
      ;;
    ufw:inactive | ufw:installed)
      if ask_yes_no "Allow SSH and TCP ${OR_PORT}, then enable UFW?" "yes"; then
        ENABLE_FIREWALL=1
        ENABLE_UFW_AFTER_RULES=1
      elif ask_yes_no "Add the UFW rules but leave UFW inactive?" "yes"; then
        ENABLE_FIREWALL=1
        ENABLE_UFW_AFTER_RULES=0
      else
        ENABLE_FIREWALL=0
      fi
      ;;
    firewalld:inactive)
      if ask_yes_no "Add an ORPort rule anyway? The script will not enable inactive firewalld." "no"; then
        ENABLE_FIREWALL=1
      else
        ENABLE_FIREWALL=0
      fi
      ;;
    *)
      if ask_yes_no "Open TCP ${OR_PORT} in ${FIREWALL_KIND}?" "yes"; then
        ENABLE_FIREWALL=1
      else
        ENABLE_FIREWALL=0
      fi
      ;;
  esac
}

collect_system_hostname() {
  section "System Hostname"

  if command_exists hostnamectl; then
    CURRENT_HOSTNAME=$(hostnamectl --static 2> /dev/null || true)
  fi
  if [[ -z "$CURRENT_HOSTNAME" ]] && command_exists hostname; then
    CURRENT_HOSTNAME=$(hostname 2> /dev/null || true)
  fi
  CURRENT_HOSTNAME=${CURRENT_HOSTNAME:-unknown}

  info "Current system hostname: ${CURRENT_HOSTNAME}"
  info "This is the Linux server name, not your public Tor relay nickname."

  if ! command_exists hostnamectl; then
    warn "hostnamectl is not available, so this installer will not change the system hostname."
    CHANGE_HOSTNAME=0
    return 0
  fi

  if ! ask_yes_no "Change the system hostname before configuring Tor?" "no"; then
    CHANGE_HOSTNAME=0
    return 0
  fi

  while true; do
    NEW_HOSTNAME=$(prompt_line "New system hostname" "$CURRENT_HOSTNAME")
    if valid_system_hostname "$NEW_HOSTNAME"; then
      break
    fi
    warn "Use DNS-style hostname labels: letters, numbers, hyphens, and dots; no spaces or underscores."
  done

  if [[ "$NEW_HOSTNAME" == "$CURRENT_HOSTNAME" ]]; then
    success "System hostname will stay unchanged."
    CHANGE_HOSTNAME=0
  else
    CHANGE_HOSTNAME=1
  fi
}

collect_relay_mode() {
  section "Relay Mode"
  info "Guard/middle relays forward traffic inside the Tor network."
  info "Exit relays also connect Tor traffic to destinations on the public Internet, according to an exit policy."

  if ask_yes_no "Configure this relay as an exit relay?" "no"; then
    RELAY_MODE="exit"
  else
    RELAY_MODE="guard"
  fi
  check_relay_resources
}

list_ipv6_candidates() {
  if ! command_exists ip; then
    return 0
  fi

  ip -6 addr show scope global 2> /dev/null \
    | awk '/inet6/ { sub(/\/.*/, "", $2); print $2 }' \
    | grep -v '^fe80:' || true
}

check_ipv6_connectivity() {
  # IPv6 directory authorities from tor's src/app/config/auth_dirs.inc
  # (tor26, gabelmoo, dannenberg, maatuska, bastet).
  local authorities=(
    "2a02:16a8:662:2203::1"
    "2001:638:a000:4140::ffff:189"
    "2001:678:558:1000::244"
    "2001:67c:289c::9"
    "2620:13:4000:6000::1000:118"
  )
  local ping_cmd=()
  local address
  local failed=0

  if command_exists ping6; then
    ping_cmd=(ping6 -c 2)
  elif command_exists ping; then
    ping_cmd=(ping -6 -c 2)
  else
    warn "Neither ping6 nor ping is available; cannot run the Tor-documented IPv6 ping check."
    return 2
  fi

  printf '%s\n' "Tor-documented check: ping each Tor directory authority IPv6 address from this server."
  for address in "${authorities[@]}"; do
    if "${ping_cmd[@]}" "$address" > /dev/null 2>&1; then
      success "IPv6 ping succeeded: ${address}"
    else
      warn "IPv6 ping failed: ${address}"
      failed=1
    fi
  done

  return "$failed"
}

# Build a ContactInfo string following the ContactInfo Information Sharing
# Specification v3 (https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/).
# Arguments: email, website URL (optional), hoster domain (optional).
build_ciiss_contact() {
  local email=$1
  local url=${2:-}
  local hoster=${3:-}
  local -a fields=()

  [[ -n "$email" ]] && fields+=("email:${email//@/[]}")
  if [[ -n "$url" ]]; then
    # CIISS requires a proof whenever url is set. v3 proves ownership with
    # the relay family ID published under the website's /.well-known path.
    fields+=("url:${url}" "proof:uri-familyid-ed25519")
  fi
  [[ -n "$hoster" ]] && fields+=("hoster:${hoster}")
  fields+=("ciissversion:3")
  printf '%s' "${fields[*]}"
}

valid_contact_email() {
  [[ $1 =~ ^[^[:space:]@#]+@[^[:space:]@#]+\.[^[:space:]@#]+$ ]]
}

valid_contact_url() {
  [[ $1 =~ ^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/[^[:space:]#]*)?$ ]]
}

valid_hoster_domain() {
  [[ $1 =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]
}

# Prompt for ContactInfo, offering the CIISS v3 builder first. Sets
# CONTACT_INFO and CONTACT_INFO_URL.
collect_contact_info() {
  local current=${1:-}
  local choice
  local email=""
  local url=""
  local hoster=""

  CONTACT_INFO_URL=""
  info "ContactInfo is public. Tor expects a working email address; the CIISS v3 format also makes it machine-readable."
  choose_menu choice "ContactInfo format" "1" \
    "1" "Guided CIISS v3 string" "email:you[]example.org ... ciissversion:3" \
    "2" "Free-form text" "Enter any contact string yourself"

  if [[ "$choice" == "2" ]]; then
    while true; do
      CONTACT_INFO=$(prompt_line "ContactInfo string" "$current")
      if valid_contact_info "$CONTACT_INFO"; then
        return 0
      fi
      warn "ContactInfo must be non-empty, under 250 characters, and cannot contain '#'."
    done
  fi

  while true; do
    email=$(prompt_line "Operator email address (published with @ written as [])")
    valid_contact_email "$email" && break
    warn "Enter an email address such as tor-ops@example.org."
  done

  while true; do
    url=$(prompt_line "Operator website (https://..., blank to skip)")
    [[ -z "$url" ]] && break
    valid_contact_url "$url" && break
    warn "Enter an https:// URL without spaces, or leave it blank."
  done

  while true; do
    hoster=$(prompt_line "Hosting provider domain, e.g. hetzner.com (blank to skip)")
    [[ -z "$hoster" ]] && break
    valid_hoster_domain "$hoster" && break
    warn "Enter a bare domain without https:// or a path, or leave it blank."
  done

  CONTACT_INFO=$(build_ciiss_contact "$email" "$url" "$hoster")
  CONTACT_INFO_URL=$url
  success "ContactInfo: ${CONTACT_INFO}"
  if [[ -n "$url" ]]; then
    warn "Publish your relay FamilyId at https://$(url_domain "$url")/.well-known/tor-relay/ed25519-family-id.txt so the url: field can be verified."
  fi
}

url_domain() {
  local domain=${1#https://}
  printf '%s' "${domain%%/*}"
}

collect_relay_identity() {
  section "Relay Identity"
  info "Your nickname and ContactInfo will be public in Tor relay directories."

  while true; do
    RELAY_NICKNAME=$(prompt_line "Relay nickname (1-19 letters/numbers)")
    if valid_nickname "$RELAY_NICKNAME"; then
      break
    fi
    warn "Use 1 to 19 characters, letters and numbers only."
  done

  collect_contact_info ""

  while true; do
    OR_PORT=$(prompt_line "ORPort for incoming Tor connections" "9001")
    if valid_port "$OR_PORT"; then
      break
    fi
    warn "Enter a TCP port from 1 through 65535."
  done

  if ((10#$OR_PORT < 1024)); then
    warn "Ports below 1024 can require extra privileges. The official guide often recommends 443 when it is available, but 9001 is common and simpler."
  fi
}

collect_ipv6() {
  section "IPv6"
  info "Tor encourages IPv6 on relays, but only when IPv6 connectivity actually works."

  if ! ask_yes_no "Configure an additional IPv6 ORPort?" "no"; then
    ENABLE_IPV6=0
    return 0
  fi

  local candidates
  local candidate
  local default_ipv6=""
  candidates=$(list_ipv6_candidates)
  if [[ -n "$candidates" ]]; then
    default_ipv6=$(printf '%s\n' "$candidates" | head -n 1)
    printf '%s\n' "Detected global IPv6 candidates:"
    while IFS= read -r candidate; do
      printf '  - %s\n' "$candidate"
    done <<< "$candidates"
    info "Press Enter at the IPv6 prompt to use ${default_ipv6}; type '-' to skip IPv6."
  else
    warn "No global IPv6 address was auto-detected. You can still enter one manually."
  fi

  while true; do
    if [[ -n "$default_ipv6" ]]; then
      IPV6_ADDRESS=$(prompt_line "IPv6 address to advertise (without brackets, '-' to skip)" "$default_ipv6")
    else
      IPV6_ADDRESS=$(prompt_line "IPv6 address to advertise (without brackets, blank to skip)")
    fi
    if [[ -z "$IPV6_ADDRESS" ]]; then
      ENABLE_IPV6=0
      return 0
    fi
    if [[ "$IPV6_ADDRESS" == "-" || "${IPV6_ADDRESS,,}" == "skip" ]]; then
      ENABLE_IPV6=0
      IPV6_ADDRESS=""
      return 0
    fi
    if valid_ipv6_address "$IPV6_ADDRESS"; then
      ENABLE_IPV6=1
      break
    fi
    warn "Enter a plain global IPv6 address, without brackets or CIDR suffix."
  done

  info "This early IPv6 check is outbound-only; inbound ORPort reachability is checked after the firewall rule and Tor restart."
  if ask_yes_no "Run the Tor-recommended outbound IPv6 connectivity check now?" "yes"; then
    info "Pinging Tor directory authority IPv6 addresses. This does not require TCP ${OR_PORT} to be open."
    if check_ipv6_connectivity; then
      success "Outbound IPv6 connectivity check passed."
    else
      warn "Outbound IPv6 connectivity check failed or could not complete."
      warn "This test is ICMPv6/ping-based. It can fail even when inbound IPv6 ORPort reachability looks fine."
      warn "Tor still warns that enabling IPv6 without working IPv6 connectivity can leave the relay unused."
      if ask_yes_no "Keep IPv6 ORPort anyway because you verified IPv6 manually?" "no"; then
        IPV6_MANUAL_OVERRIDE=1
        warn "Keeping IPv6 ORPort enabled by explicit operator override."
      else
        ENABLE_IPV6=0
        IPV6_ADDRESS=""
        IPV6_MANUAL_OVERRIDE=0
      fi
    fi
  else
    warn "Skipped outbound IPv6 connectivity check. Only keep IPv6 enabled if you know it works."
    IPV6_MANUAL_OVERRIDE=1
  fi
}

collect_exit_options() {
  [[ "$RELAY_MODE" == "exit" ]] || return 0

  section "Exit Relay Options"
  info "Exit relay setup follows Tor's exit relay guidance: choose an exit policy and provide reliable local DNS resolution."
  info "A dedicated server, provider permission, clear abuse contact handling, and useful reverse DNS/WHOIS notes are recommended for exit operators."

  if ! ask_yes_no "Have you confirmed this provider allows Tor exit traffic and that abuse handling is planned?" "no"; then
    die "Exit relay setup aborted. Confirm provider permission and abuse handling first, or re-run and choose Guard/middle mode."
  fi
  if ! ask_yes_no "Have you prepared a public exit notice or abuse-contact explanation for complaints?" "no"; then
    die "Exit relay setup aborted. Prepare exit operator contact/notice handling before publishing an exit relay."
  fi

  if ask_yes_no "Use Tor's ReducedExitPolicy for a first exit relay?" "yes"; then
    EXIT_POLICY_MODE="reduced"
  else
    EXIT_POLICY_MODE="default"
    warn "Tor's default exit policy is broader than ReducedExitPolicy. Make sure it matches your provider and operations plan."
  fi

  if ((ENABLE_IPV6)); then
    if ask_yes_no "Allow IPv6 exit traffic with IPv6Exit 1?" "yes"; then
      EXIT_ALLOW_IPV6=1
    else
      EXIT_ALLOW_IPV6=0
    fi
  else
    EXIT_ALLOW_IPV6=0
  fi

  info "Exit relays perform DNS resolution for Tor clients."
  info "Tor recommends a local caching, DNSSEC-validating resolver such as Unbound, without public DNS forwarders."
  if ask_yes_no "Install Unbound and use it as the local resolver for exit DNS?" "yes"; then
    CONFIGURE_UNBOUND=1
    if ask_yes_no "Lock /etc/resolv.conf with chattr +i after switching to Unbound?" "no"; then
      LOCK_RESOLV_CONF=1
    else
      LOCK_RESOLV_CONF=0
    fi
  else
    CONFIGURE_UNBOUND=0
    warn "You chose not to configure Unbound. Make sure DNS resolution is reliable and not using a large public resolver."
  fi
}

collect_relay_family() {
  local choice
  local path

  section "Relay Family"
  info "Relays run by the same operator must declare one family, so clients never use two of them in one circuit."
  info "Since Tor 0.4.9 a family is a shared key (FamilyId). Every relay in the family gets a copy of the same key file."

  FAMILY_MODE="none"
  FAMILY_ID=""
  FAMILY_KEY_NAME="relay-family"
  FAMILY_IMPORT_KEY_PATH=""
  INITIAL_MYFAMILY_AFTER_SETUP=0

  choose_menu choice "Relay family" "1" \
    "1" "This is my only relay" "No family needed; add one later from the operator console" \
    "2" "Create a new family key" "First relay of a new family" \
    "3" "Import an existing family key" "Copy <name>.secret_family_key from one of your relays first"

  case "$choice" in
    2)
      FAMILY_MODE="generate"
      while true; do
        FAMILY_KEY_NAME=$(prompt_line "Family key name" "relay-family")
        valid_family_key_name "$FAMILY_KEY_NAME" && break
        warn "Use letters, numbers, dots, dashes or underscores (max 64 characters)."
      done
      info "The key is generated with 'tor --keygen-family' after Tor is installed."
      ;;
    3)
      FAMILY_MODE="import"
      while true; do
        path=$(prompt_line "Path to the .secret_family_key file on this server")
        if family_key_file_valid "$path"; then
          break
        fi
        warn "Expected a 96-byte Tor family key file ending in .secret_family_key."
      done
      FAMILY_IMPORT_KEY_PATH=$path
      FAMILY_KEY_NAME=$(basename "$path" .secret_family_key)
      if ! FAMILY_ID=$(family_id_for_key_file "$path"); then
        while true; do
          FAMILY_ID=$(prompt_line "FamilyId shown on the relay that created the key")
          valid_family_id "$FAMILY_ID" && break
          warn "A FamilyId is 43 base64 characters, as printed by 'tor --keygen-family'."
        done
      fi
      success "Family ${FAMILY_KEY_NAME}: FamilyId ${FAMILY_ID}"
      ;;
    *) ;;
  esac

  if [[ "$FAMILY_MODE" != "none" ]]; then
    info "Tor 0.4.8 is end-of-life, so current clients only need FamilyId. A legacy MyFamily list is optional."
    if ask_yes_no "Also maintain a legacy MyFamily fingerprint list after setup?" "no"; then
      INITIAL_MYFAMILY_AFTER_SETUP=1
    fi
  fi
}

available_kib_for_path() {
  local path=$1
  df -Pk "$path" 2> /dev/null | awk 'NR == 2 { print $4 }'
}

available_inodes_for_path() {
  local path=$1
  df -Pi "$path" 2> /dev/null | awk 'NR == 2 { print $4 }'
}

check_path_capacity() {
  local path=$1
  local min_kib=$2
  local min_inodes=$3
  local available_kib
  local available_inodes

  [[ -e "$path" ]] || return 0

  available_kib=$(available_kib_for_path "$path")
  available_inodes=$(available_inodes_for_path "$path")

  if [[ -n "$available_kib" && "$available_kib" =~ ^[0-9]+$ ]]; then
    if ((available_kib < min_kib)); then
      die "Not enough free disk space for apt under ${path}. Need at least $((min_kib / 1024)) MiB free; found $((available_kib / 1024)) MiB. Run: df -h"
    fi
  else
    warn "Could not read free disk space for ${path}; continuing."
  fi

  if [[ -n "$available_inodes" && "$available_inodes" =~ ^[0-9]+$ ]]; then
    if ((available_inodes < min_inodes)); then
      die "Not enough free inodes for apt under ${path}. Need at least ${min_inodes}; found ${available_inodes}. Run: df -ih"
    fi
  else
    warn "Could not read free inodes for ${path}; continuing."
  fi
}

check_apt_capacity() {
  section "Preflight"

  if ((DRY_RUN)); then
    info "Dry run: skipping apt disk-space preflight."
    return 0
  fi

  command_exists df || die "df is required for the apt disk-space preflight."

  check_path_capacity /var/lib/apt/lists 512000 2048
  check_path_capacity /var/cache/apt/archives 512000 2048
  check_path_capacity /var 512000 2048
  check_path_capacity /tmp 65536 512
  success "apt has enough free disk space and inodes for package operations."
}

reset_bandwidth_config() {
  CONFIGURE_RELAY_BANDWIDTH=0
  RELAY_BANDWIDTH_RATE_VALUE=""
  RELAY_BANDWIDTH_RATE_UNIT="MBits"
  RELAY_BANDWIDTH_BURST_VALUE=""
  RELAY_BANDWIDTH_BURST_UNIT="MBits"
  CONFIGURE_ACCOUNTING=0
  ACCOUNTING_MAX_GBYTES=""
  ACCOUNTING_RULE="max"
  BANDWIDTH_MODE="none"
  MONTHLY_TRAFFIC_INPUT=""
  MONTHLY_TRAFFIC_GBYTES=""
  MONTHLY_TRAFFIC_USABLE_GBYTES=""
  MONTHLY_TRAFFIC_HEADROOM_PERCENT=10
  MONTHLY_TRAFFIC_BILLING_RULE="sum"
  STEADY_PER_DIRECTION_GBYTES=""
}

collect_traffic_budget() {
  local prompt=${1:-"Maximum monthly traffic budget"}
  local parsed

  while true; do
    MONTHLY_TRAFFIC_INPUT=$(prompt_line "$prompt (examples: 10TB, 5000GB)")
    if parsed=$(parse_traffic_to_gbytes "$MONTHLY_TRAFFIC_INPUT"); then
      MONTHLY_TRAFFIC_GBYTES=$parsed
      break
    fi
    warn "Enter a traffic amount with units, for example 10TB, 2.5TB, or 5000GB."
  done
}

collect_traffic_headroom() {
  while true; do
    MONTHLY_TRAFFIC_HEADROOM_PERCENT=$(prompt_line "Safety headroom percentage for provider overhead" "10")
    if valid_percent "$MONTHLY_TRAFFIC_HEADROOM_PERCENT"; then
      break
    fi
    warn "Enter a whole percentage from 0 to 50."
  done

  MONTHLY_TRAFFIC_USABLE_GBYTES=$((10#$MONTHLY_TRAFFIC_GBYTES * (100 - 10#$MONTHLY_TRAFFIC_HEADROOM_PERCENT) / 100))
  if ((MONTHLY_TRAFFIC_USABLE_GBYTES < 1)); then
    die "The usable traffic budget is below 1 GByte after headroom."
  fi
}

collect_traffic_billing_rule() {
  local choice

  choose_menu choice "How does your provider count the monthly traffic quota?" "1" \
    "1" "Combined inbound + outbound" "Conservative default" \
    "2" "Outbound traffic only" "Common for some VPS providers" \
    "3" "Per-direction max(in,out)" "Matches Tor's default accounting rule"

  case "$choice" in
    1)
      MONTHLY_TRAFFIC_BILLING_RULE="sum"
      ACCOUNTING_RULE="sum"
      ;;
    2)
      MONTHLY_TRAFFIC_BILLING_RULE="out"
      ACCOUNTING_RULE="out"
      ;;
    3)
      MONTHLY_TRAFFIC_BILLING_RULE="max"
      ACCOUNTING_RULE="max"
      ;;
  esac
}

calculate_steady_monthly_limits() {
  local per_direction_gbytes
  local rate_kbytes
  local burst_kbytes

  case "$MONTHLY_TRAFFIC_BILLING_RULE" in
    sum)
      per_direction_gbytes=$((10#$MONTHLY_TRAFFIC_USABLE_GBYTES / 2))
      ;;
    out | max)
      per_direction_gbytes=$((10#$MONTHLY_TRAFFIC_USABLE_GBYTES))
      ;;
    *)
      die "Unknown traffic billing rule: ${MONTHLY_TRAFFIC_BILLING_RULE}"
      ;;
  esac

  if ((per_direction_gbytes < 1)); then
    die "The monthly budget is too small after headroom and accounting style."
  fi

  # Pace over the longest possible month (31 days) so long months cannot
  # exhaust the quota early and trigger AccountingMax hibernation.
  rate_kbytes=$((per_direction_gbytes * 1024 * 1024 / (31 * 86400)))
  if ((rate_kbytes < 75)); then
    warn "That budget calculates to ${rate_kbytes} KBytes/s, below Tor's relay minimum of 75 KBytes/s."
    return 1
  fi

  if ((rate_kbytes < 1221)); then
    warn "That budget calculates to ~$(format_mbits_from_kbytes "$rate_kbytes") Mbit/s, below Tor's practical 10 Mbit/s relay guidance."
    return 1
  fi
  if ((rate_kbytes < 1954)); then
    warn "That budget calculates to ~$(format_mbits_from_kbytes "$rate_kbytes") Mbit/s. Tor recommends 16 Mbit/s or more when possible."
  fi

  burst_kbytes=$((rate_kbytes * 5))

  CONFIGURE_RELAY_BANDWIDTH=1
  RELAY_BANDWIDTH_RATE_VALUE=$rate_kbytes
  RELAY_BANDWIDTH_RATE_UNIT="KBytes"
  RELAY_BANDWIDTH_BURST_VALUE=$burst_kbytes
  RELAY_BANDWIDTH_BURST_UNIT="KBytes"
  CONFIGURE_ACCOUNTING=1
  ACCOUNTING_MAX_GBYTES=$MONTHLY_TRAFFIC_USABLE_GBYTES
  STEADY_PER_DIRECTION_GBYTES=$per_direction_gbytes
}

collect_steady_monthly_bandwidth() {
  BANDWIDTH_MODE="steady"

  while true; do
    collect_traffic_budget "Maximum monthly traffic allowed by your provider"
    collect_traffic_headroom
    collect_traffic_billing_rule
    if calculate_steady_monthly_limits; then
      break
    fi
    if ! ask_yes_no "Enter a larger monthly budget?" "yes"; then
      die "Monthly budget is too small for a steady public Tor relay."
    fi
  done

  success "Calculated steady rate: ${RELAY_BANDWIDTH_RATE_VALUE} ${RELAY_BANDWIDTH_RATE_UNIT}/s (~$(format_mbits_from_kbytes "$RELAY_BANDWIDTH_RATE_VALUE") Mbit/s)."
  success "Calculated burst: ${RELAY_BANDWIDTH_BURST_VALUE} ${RELAY_BANDWIDTH_BURST_UNIT}/s."
  info "AccountingMax is kept as a safety fuse at ${ACCOUNTING_MAX_GBYTES} GBytes with AccountingRule ${ACCOUNTING_RULE}."
}

collect_manual_relay_bandwidth() {
  local default_burst

  BANDWIDTH_MODE="manual"
  CONFIGURE_RELAY_BANDWIDTH=1
  RELAY_BANDWIDTH_RATE_UNIT="MBits"
  RELAY_BANDWIDTH_BURST_UNIT="MBits"

  while true; do
    RELAY_BANDWIDTH_RATE_VALUE=$(prompt_line "Average relay bandwidth in Mbit/s" "16")
    if valid_integer "$RELAY_BANDWIDTH_RATE_VALUE" && ((10#$RELAY_BANDWIDTH_RATE_VALUE >= 1)); then
      break
    fi
    warn "Enter a positive whole number."
  done

  if ((10#$RELAY_BANDWIDTH_RATE_VALUE < 10)); then
    warn "Tor relay requirements say 10 Mbit/s is the practical minimum; 16 Mbit/s or more is recommended."
    if ! ask_yes_no "Continue with ${RELAY_BANDWIDTH_RATE_VALUE} Mbit/s anyway?" "no"; then
      reset_bandwidth_config
      collect_bandwidth
      return 0
    fi
  elif ((10#$RELAY_BANDWIDTH_RATE_VALUE < 16)); then
    warn "16 Mbit/s or more is recommended when available."
  fi

  default_burst=$((10#$RELAY_BANDWIDTH_RATE_VALUE * 2))
  while true; do
    RELAY_BANDWIDTH_BURST_VALUE=$(prompt_line "Burst bandwidth in Mbit/s" "$default_burst")
    if valid_integer "$RELAY_BANDWIDTH_BURST_VALUE" && ((10#$RELAY_BANDWIDTH_BURST_VALUE >= 10#$RELAY_BANDWIDTH_RATE_VALUE)); then
      break
    fi
    warn "Enter a whole number greater than or equal to the average rate."
  done
}

collect_hard_accounting_cap() {
  BANDWIDTH_MODE="accounting"
  CONFIGURE_ACCOUNTING=1

  collect_traffic_budget "Monthly AccountingMax traffic cap"
  collect_traffic_headroom
  collect_traffic_billing_rule
  ACCOUNTING_MAX_GBYTES=$MONTHLY_TRAFFIC_USABLE_GBYTES

  warn "AccountingMax is a hard cap. Tor may hibernate after the cap is reached."
}

collect_bandwidth() {
  section "Bandwidth and Traffic"
  reset_bandwidth_config

  info "Tor AccountingMax is a hard quota and can hibernate the relay when exhausted."
  info "Steady monthly mode calculates RelayBandwidthRate and RelayBandwidthBurst from your VPS traffic budget."

  local choice
  choose_menu choice "Choose a bandwidth mode" "1" \
    "1" "Steady monthly budget" "Recommended for VPS traffic caps" \
    "2" "Manual rate and burst" "Set RelayBandwidthRate/Burst yourself" \
    "3" "Hard monthly AccountingMax only" "May hibernate when exhausted" \
    "4" "No relay-specific cap" "Let Tor use available bandwidth"

  case "$choice" in
    1)
      collect_steady_monthly_bandwidth
      ;;
    2)
      collect_manual_relay_bandwidth
      ;;
    3)
      collect_hard_accounting_cap
      ;;
    4)
      BANDWIDTH_MODE="none"
      info "No relay-specific bandwidth cap will be written."
      ;;
  esac
}

collect_maintenance_options() {
  section "Maintenance Options"

  info "Automatic security updates are strongly recommended for relay operators."
  if ask_yes_no "Configure unattended upgrades for security and Tor packages?" "yes"; then
    ENABLE_AUTO_UPDATES=1
  else
    ENABLE_AUTO_UPDATES=0
    warn "You chose not to configure automatic updates. Keep Tor and the OS updated manually."
  fi

  info "Nyx is the Tor terminal monitor. It is handy for relay operators, but not required."
  if ask_yes_no "Install Nyx for terminal relay monitoring?" "yes"; then
    INSTALL_NYX=1
  else
    INSTALL_NYX=0
  fi

  info "Tor's MetricsPort serves Prometheus metrics (overload, DNS errors, traffic) for monitoring."
  if ask_yes_no "Enable MetricsPort on ${METRICS_PORT_ADDRESS}, reachable from this server only?" "no"; then
    CONFIGURE_METRICS_PORT=1
  else
    CONFIGURE_METRICS_PORT=0
  fi

  collect_firewall_options

  info "SafeLogging stays enabled. The optional Tor syscall sandbox adds Linux hardening."
  if ask_yes_no "Enable Tor's syscall Sandbox option?" "yes"; then
    ENABLE_TOR_SANDBOX=1
  else
    ENABLE_TOR_SANDBOX=0
  fi
}

build_torrc() {
  local output=$1
  {
    printf '# Generated by %s on %s UTC.\n' "$SCRIPT_NAME" "$(date -u '+%Y-%m-%d %H:%M:%S')"
    printf '# Tor relay configuration.\n'
    printf '# Review Tor Project relay documentation before making manual changes.\n'
    printf '\n'
    printf 'Nickname %s\n' "$RELAY_NICKNAME"
    printf 'ContactInfo %s\n' "$(torrc_quote "$CONTACT_INFO")"
    if valid_family_id "$FAMILY_ID"; then
      printf '\n'
      printf '# Managed relay family (Tor 0.4.9 FamilyId). Every relay in the family shares the key.\n'
      printf 'FamilyId %s\n' "$FAMILY_ID"
    elif [[ "$FAMILY_MODE" == "generate" ]]; then
      printf '\n'
      printf '# FamilyId <generated with tor --keygen-family during apply>\n'
    fi
    printf '\n'
    printf 'ORPort %s\n' "$OR_PORT"
    if ((ENABLE_IPV6)); then
      printf 'ORPort [%s]:%s\n' "$IPV6_ADDRESS" "$OR_PORT"
    fi
    printf '\n'
    printf '# Disable local SOCKS listener on this relay-only server.\n'
    printf 'SocksPort 0\n'
    printf '\n'
    if [[ "$RELAY_MODE" == "exit" ]]; then
      printf '# Exit relay mode.\n'
      printf 'ExitRelay 1\n'
      if [[ "$EXIT_POLICY_MODE" == "reduced" ]]; then
        printf 'ReducedExitPolicy 1\n'
      fi
      if ((EXIT_ALLOW_IPV6)); then
        printf 'IPv6Exit 1\n'
      fi
    else
      printf '# Guard / middle relay mode.\n'
      printf 'ExitRelay 0\n'
    fi
    printf '\n'
    printf '# Keep potentially sensitive log details scrubbed.\n'
    printf 'SafeLogging 1\n'
    if ((ENABLE_TOR_SANDBOX)); then
      printf 'Sandbox 1\n'
    fi
    if ((CONFIGURE_METRICS_PORT)); then
      printf '\n'
      printf '# Local-only Prometheus metrics. Never expose this port publicly.\n'
      printf 'MetricsPort %s\n' "$METRICS_PORT_ADDRESS"
      printf 'MetricsPortPolicy accept 127.0.0.1\n'
    fi
    if ((CONFIGURE_RELAY_BANDWIDTH)); then
      printf '\n'
      printf '# Relay-specific bandwidth limits. Tor applies these per second.\n'
      printf 'RelayBandwidthRate %s %s\n' "$RELAY_BANDWIDTH_RATE_VALUE" "$RELAY_BANDWIDTH_RATE_UNIT"
      printf 'RelayBandwidthBurst %s %s\n' "$RELAY_BANDWIDTH_BURST_VALUE" "$RELAY_BANDWIDTH_BURST_UNIT"
    fi
    if ((CONFIGURE_ACCOUNTING)); then
      printf '\n'
      printf '# Monthly accounting safety cap. Tor hibernates if this is exhausted.\n'
      printf 'AccountingStart month 1 00:00\n'
      if [[ "$ACCOUNTING_RULE" != "max" ]]; then
        printf 'AccountingRule %s\n' "$ACCOUNTING_RULE"
      fi
      printf 'AccountingMax %s GBytes\n' "$ACCOUNTING_MAX_GBYTES"
    fi
  } > "$output"
}

build_tor_sources() {
  local output=$1
  {
    printf 'Types: deb deb-src\n'
    printf 'URIs: %s/\n' "$TOR_APT_BASE_URL"
    printf 'Suites: %s\n' "$OS_CODENAME"
    printf 'Components: main\n'
    printf 'Signed-By: %s\n' "$TOR_KEYRING_PATH"
  } > "$output"
}

build_unattended_tor_config() {
  local output=$1
  {
    printf '// Managed by %s. Enables unattended upgrades for Tor Project packages.\n' "$SCRIPT_NAME"
    # Single quotes are intentional: ${distro_*} are unattended-upgrades macros.
    # shellcheck disable=SC2016
    if [[ "$OS_ID" == "debian" ]]; then
      # Since bullseye the Debian security suite is "<codename>-security".
      printf 'Unattended-Upgrade::Origins-Pattern {\n'
      printf '    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";\n'
      printf '    "origin=TorProject";\n'
      printf '};\n'
    else
      printf 'Unattended-Upgrade::Allowed-Origins {\n'
      printf '    "${distro_id}:${distro_codename}-security";\n'
      printf '    "TorProject:${distro_codename}";\n'
      printf '};\n'
    fi
  } > "$output"
}

build_auto_upgrades_config() {
  local output=$1
  {
    printf 'APT::Periodic::Update-Package-Lists "1";\n'
    printf 'APT::Periodic::AutocleanInterval "5";\n'
    printf 'APT::Periodic::Unattended-Upgrade "1";\n'
    printf 'APT::Periodic::Verbose "1";\n'
  } > "$output"
}

build_hosts_file() {
  local output=$1
  local hosts_entry=$NEW_HOSTNAME

  if [[ "$NEW_HOSTNAME" == *.* ]]; then
    hosts_entry="${NEW_HOSTNAME} ${NEW_HOSTNAME%%.*}"
  fi

  if [[ -r /etc/hosts ]]; then
    awk -v hosts_entry="$hosts_entry" '
      BEGIN { updated = 0 }
      $1 == "127.0.1.1" && updated == 0 {
        print "127.0.1.1\t" hosts_entry
        updated = 1
        next
      }
      $1 == "127.0.1.1" { next }
      { print }
      END {
        if (updated == 0) {
          print "127.0.1.1\t" hosts_entry
        }
      }
    ' /etc/hosts > "$output"
  else
    {
      printf '127.0.0.1\tlocalhost\n'
      printf '127.0.1.1\t%s\n' "$hosts_entry"
      printf '::1\tlocalhost ip6-localhost ip6-loopback\n'
    } > "$output"
  fi
}

build_resolv_conf() {
  local output=$1
  {
    printf '# Managed by %s for Tor exit relay DNS.\n' "$SCRIPT_NAME"
    printf 'nameserver 127.0.0.1\n'
  } > "$output"
}

backup_file() {
  local target=$1
  local backup
  local suffix=0

  LAST_BACKUP_PATH=""
  [[ -e "$target" || -L "$target" ]] || return 0

  backup="${target}.bak.${TIMESTAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}"
  while [[ -e "$backup" || -L "$backup" ]]; do
    suffix=$((suffix + 1))
    backup="${target}.bak.${TIMESTAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}.${suffix}"
  done
  if ((DRY_RUN)); then
    info "Would back up ${target} to ${backup}"
  else
    cp -a -- "$target" "$backup"
    LAST_BACKUP_PATH=$backup
    BACKUPS_CREATED+=("$backup")
    success "Backed up ${target} to ${backup}"
  fi
}

install_file_if_changed() {
  local source=$1
  local target=$2
  local mode=${3:-0644}
  local target_dir
  local target_base
  local temp_target

  if [[ -f "$target" ]] && cmp -s "$source" "$target"; then
    success "Already current: ${target}"
    return 0
  fi

  backup_file "$target"
  if ((DRY_RUN)); then
    info "Would install ${target}"
    print_command install -D -m "$mode" "$source" "$target"
  else
    target_dir=$(dirname "$target")
    target_base=$(basename "$target")
    install -d -m 0755 "$target_dir"
    temp_target=$(mktemp "${target_dir%/}/.${target_base}.tmp.XXXXXX")
    install -m "$mode" "$source" "$temp_target"
    mv -f -- "$temp_target" "$target"
    success "Installed ${target}"
  fi
}

torrc_exists() {
  [[ -s "$TORRC_PATH" ]]
}

tor_service_active() {
  command_exists systemctl && systemctl is-active --quiet "$TOR_SERVICE" 2> /dev/null
}

existing_tor_relay_detected() {
  if torrc_exists && awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*ORPort[[:space:]]+/ { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$TORRC_PATH"; then
    return 0
  fi

  if tor_service_active; then
    warn "${TOR_SERVICE} is active, but no ORPort was found in ${TORRC_PATH}; treating it as a Tor client or incomplete relay config."
  fi

  return 1
}

read_torrc_first_orport() {
  torrc_exists || return 1
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*ORPort[[:space:]]+/ {
      value = $2
      gsub(/.*\]:/, "", value)
      gsub(/.*:/, "", value)
      if (value ~ /^[0-9]+$/) {
        print value
        exit
      }
    }
  ' "$TORRC_PATH"
}

tor_datadirectory() {
  local value

  value=""
  if torrc_exists; then
    value=$(awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*DataDirectory[[:space:]]+/ {
        print $2
        exit
      }
    ' "$TORRC_PATH" || true)
  fi
  printf '%s' "${value:-/var/lib/tor}"
}

local_relay_fingerprint() {
  local data_dir
  local fingerprint_file

  data_dir=$(tor_datadirectory)
  fingerprint_file="${data_dir%/}/fingerprint"
  [[ -r "$fingerprint_file" ]] || return 1
  awk '{ print toupper($NF); exit }' "$fingerprint_file"
}

torrc_myfamily_fingerprints() {
  torrc_exists || return 0
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*MyFamily[[:space:]]+/ {
      $1 = ""
      gsub(/#.*$/, "")
      gsub(/,/, " ")
      for (i = 1; i <= NF; i++) {
        value = toupper($i)
        sub(/^\$/, "", value)
        if (value ~ /^[A-F0-9]{40}$/) {
          print value
        }
      }
    }
  ' "$TORRC_PATH"
}

append_unique_fingerprint() {
  local -n target_array=$1
  local fingerprint
  local existing

  fingerprint=$(normalize_fingerprint "$2")
  for existing in "${target_array[@]}"; do
    [[ "$existing" == "$fingerprint" ]] && return 0
  done
  target_array+=("$fingerprint")
}

fingerprint_in_array() {
  local needle
  local fingerprint
  local existing

  needle=$(normalize_fingerprint "$1")
  shift

  for existing in "$@"; do
    fingerprint=$(normalize_fingerprint "$existing")
    [[ "$fingerprint" == "$needle" ]] && return 0
  done

  return 1
}

fetch_url_to_file() {
  local url=$1
  local output=$2

  if command_exists curl; then
    curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$output"
  elif command_exists wget; then
    wget -qO "$output" "$url"
  else
    die "curl or wget is required for Tor Metrics relay lookup."
  fi
}

lookup_relay_candidates() {
  local query=$1
  local output=$2
  local json_file="$TMP_DIR/onionoo-summary.json"
  local url
  local python_bin

  if valid_fingerprint "$query"; then
    query=$(normalize_fingerprint "$query")
    printf '1\t%s\t%s\t%s\t%s\n' "$query" "manual fingerprint" "unknown" "manual entry" > "$output"
    return 0
  fi

  if ! valid_nickname "$query"; then
    warn "Relay lookups by nickname use Tor nickname syntax: 1-19 letters/numbers."
    return 1
  fi

  python_bin=$(python_command) || die "python3 or python is required for safe Onionoo JSON parsing. Install python3 or enter a full relay fingerprint."

  url="${ONIONOO_BASE_URL}/summary?type=relay&search=${query}&limit=20"
  info "Looking up '${query}' with Tor Metrics Onionoo."
  fetch_url_to_file "$url" "$json_file"

  "$python_bin" - "$json_file" "$query" > "$output" << 'PY'
import json
import sys

path, query = sys.argv[1], sys.argv[2].lower()
with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)

relays = document.get("relays", [])
relays.sort(key=lambda relay: (
    relay.get("n", "").lower() != query,
    not relay.get("r", False),
    relay.get("n", "").lower(),
    relay.get("f", ""),
))

for index, relay in enumerate(relays, 1):
    nickname = relay.get("n", "")
    fingerprint = relay.get("f", "")
    running = "yes" if relay.get("r", False) else "no"
    addresses = ",".join(relay.get("a", [])[:3])
    print(f"{index}\t{fingerprint}\t{nickname}\t{running}\t{addresses}")
PY
}

select_relay_fingerprint() {
  local query=$1
  local candidates_file="$TMP_DIR/onionoo-candidates.tsv"
  local selection_hint=""
  local selection
  local -a selections=()
  local row_count=0
  local index
  local fingerprint
  local nickname
  local running
  local addresses

  SELECTED_RELAY_FINGERPRINTS=()

  if [[ "$query" =~ ^(.+)[[:space:]]+#?([0-9]+)$ ]]; then
    query=$(trim "${BASH_REMATCH[1]}")
    selection_hint=${BASH_REMATCH[2]}
  fi

  lookup_relay_candidates "$query" "$candidates_file" || return 1

  row_count=$(awk 'END { print NR + 0 }' "$candidates_file")
  if ((row_count == 0)); then
    warn "No relay candidates were found for '${query}'. Try a full fingerprint or wait until the relay appears in Relay Search."
    return 1
  fi

  if [[ -n "$selection_hint" ]]; then
    selections=("$selection_hint")
  elif tui_available; then
    local -a candidate_options=()
    while IFS=$'\t' read -r index fingerprint nickname running addresses; do
      candidate_options+=(
        "$index"
        "$fingerprint"
        "nickname:${nickname}  running:${running}  ${addresses:-no addresses shown}"
        "candidate"
      )
    done < "$candidates_file"
    if ! choose_checklist selections "Select relay fingerprint(s) to add" "${candidate_options[@]}"; then
      warn "No relay candidate was selected."
      return 1
    fi
  else
    printf '\n'
    step_prefix
    printf '%s\n' "Relay candidates:"
    while IFS=$'\t' read -r index fingerprint nickname running addresses; do
      step_prefix
      printf '  %s) %s  %s  running:%s  %s\n' "$index" "$nickname" "$fingerprint" "$running" "${addresses:-no addresses shown}"
    done < "$candidates_file"
    selection=$(prompt_line "Select the correct relay number, or blank to skip")
    [[ -n "$selection" ]] || return 1
    selections=("$selection")
  fi

  for selection in "${selections[@]}"; do
    if ! valid_integer "$selection" || ((10#$selection < 1 || 10#$selection > row_count)); then
      warn "Invalid relay selection: ${selection}"
      continue
    fi

    fingerprint=$(awk -F '\t' -v wanted="$selection" '$1 == wanted { print $2; exit }' "$candidates_file")
    nickname=$(awk -F '\t' -v wanted="$selection" '$1 == wanted { print $3; exit }' "$candidates_file")
    running=$(awk -F '\t' -v wanted="$selection" '$1 == wanted { print $4; exit }' "$candidates_file")
    step_prefix
    printf 'Selected: %s  %s  running:%s\n' "$nickname" "$fingerprint" "$running"
    SELECTED_RELAY_FINGERPRINTS+=("$fingerprint")
  done

  ((${#SELECTED_RELAY_FINGERPRINTS[@]})) || return 1

  if ask_yes_no "Add selected fingerprint(s) to MyFamily?" "yes"; then
    return 0
  fi

  SELECTED_RELAY_FINGERPRINTS=()
  return 1
}

write_myfamily_to_torrc() {
  local family_csv=$1
  local temp_torrc="$TMP_DIR/torrc.myfamily"

  torrc_exists || die "${TORRC_PATH} does not exist yet."

  awk -v family_line="MyFamily ${family_csv}" '
    /^[[:space:]]*#[[:space:]]*Managed MyFamily/ { next }
    /^[[:space:]]*MyFamily[[:space:]]+/ { next }
    {
      print
      if (!inserted && $0 ~ /^[[:space:]]*ContactInfo[[:space:]]+/) {
        print ""
        print "# Managed MyFamily: relays controlled by this operator. Keep synced on every family member."
        print family_line
        inserted = 1
      }
    }
    END {
      if (!inserted) {
        print ""
        print "# Managed MyFamily: relays controlled by this operator. Keep synced on every family member."
        print family_line
      }
    }
  ' "$TORRC_PATH" > "$temp_torrc"

  verify_tor_config_file "$temp_torrc"
  install_file_if_changed "$temp_torrc" "$TORRC_PATH" "0644"
}

lookup_family_status() {
  local -a fingerprints=("$@")
  local lookup
  local json_file="$TMP_DIR/onionoo-family-status.json"
  local report_file="$TMP_DIR/onionoo-family-status.txt"
  local count
  local python_bin

  ((${#fingerprints[@]})) || return 0
  python_bin=$(python_command) || {
    warn "python3/python is unavailable; skipping Onionoo MyFamily status lookup."
    return 0
  }

  lookup=$(
    IFS=,
    printf '%s' "${fingerprints[*]}"
  )
  fetch_url_to_file "${ONIONOO_BASE_URL}/summary?type=relay&lookup=${lookup}" "$json_file" || {
    warn "Could not fetch Onionoo family status."
    return 0
  }

  count=$(
    "$python_bin" - "$json_file" << 'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    document = json.load(handle)

for relay in document.get("relays", []):
    nickname = relay.get("n", "")
    fingerprint = relay.get("f", "")
    running = "yes" if relay.get("r", False) else "no"
    addresses = ",".join(relay.get("a", [])[:2])
    print(f"{nickname}\t{fingerprint}\trunning:{running}\t{addresses}")
PY
  )

  if [[ -z "$count" ]]; then
    warn "Onionoo did not return status for the configured MyFamily fingerprints yet."
    return 0
  fi

  {
    printf '%s\n' "Published relay status for configured MyFamily fingerprints:"
    while IFS=$'\t' read -r nickname fingerprint running addresses; do
      printf '  %s  %s  %s  %s\n' "$nickname" "$fingerprint" "$running" "${addresses:-no addresses shown}"
    done <<< "$count"
  } > "$report_file"

  if tui_available; then
    show_file_panel "MyFamily Published Status" "$report_file"
  else
    while IFS= read -r line; do
      step_prefix
      printf '%s\n' "$line"
    done < "$report_file"
  fi
}

print_myfamily_editor_list() {
  local -n family_array=$1
  local local_fp=$2
  local index=1
  local fingerprint
  local marker

  if ((${#family_array[@]} == 0)); then
    info "MyFamily editor is empty."
    return 0
  fi

  step_prefix
  printf '%s\n' "Current MyFamily editor:"
  for fingerprint in "${family_array[@]}"; do
    marker=""
    if [[ -n "$local_fp" && "$fingerprint" == "$local_fp" ]]; then
      marker="  (this relay, pinned)"
    fi
    step_prefix
    printf '  %s) %s%s\n' "$index" "$fingerprint" "$marker"
    index=$((index + 1))
  done
}

show_myfamily_editor_panel() {
  local array_name=$1
  local -n family_array=$array_name
  local local_fp=$2
  local report_file="$TMP_DIR/myfamily-editor.txt"
  local index=1
  local fingerprint

  {
    printf 'Current MyFamily editor\n\n'
    if ((${#family_array[@]} == 0)); then
      printf '(empty)\n'
    fi
    for fingerprint in "${family_array[@]}"; do
      if [[ -n "$local_fp" && "$fingerprint" == "$local_fp" ]]; then
        printf '%2d. %s  (this relay, pinned)\n' "$index" "$fingerprint"
      else
        printf '%2d. %s\n' "$index" "$fingerprint"
      fi
      index=$((index + 1))
    done
  } > "$report_file"

  show_file_panel "Current MyFamily Editor" "$report_file"
}

add_myfamily_member() {
  local array_name=$1
  local -n family_array=$array_name
  local entry
  local resolved_fp
  local added_count=0

  entry=$(prompt_line "Relay nickname or fingerprint to add (leading '$' is accepted)")
  [[ -n "$entry" ]] || return 0

  if select_relay_fingerprint "$entry"; then
    for resolved_fp in "${SELECTED_RELAY_FINGERPRINTS[@]}"; do
      if fingerprint_in_array "$resolved_fp" "${family_array[@]}"; then
        success "${resolved_fp} is already in MyFamily."
      else
        append_unique_fingerprint "$array_name" "$resolved_fp"
        success "Added ${resolved_fp}."
        added_count=$((added_count + 1))
      fi
    done
    if ((added_count > 1)); then
      success "Added ${added_count} fingerprints."
    fi
  else
    warn "No fingerprint was added for '${entry}'."
  fi
}

remove_myfamily_member() {
  local array_name=$1
  # shellcheck disable=SC2178
  local -n family_array=$array_name
  local local_fp=$2
  local selection
  local -a selections=()
  local -a selected_for_removal=()
  local -a remove_options=()
  local index
  local removed
  local removed_count=0
  local delete_title="MyFamily fingerprints: type numbers to delete"

  if ((${#family_array[@]} == 0)); then
    warn "There are no fingerprints to remove."
    return 0
  fi

  for ((index = 0; index < ${#family_array[@]}; index++)); do
    removed=${family_array[$index]}
    if [[ -n "$local_fp" && "$removed" == "$local_fp" ]]; then
      remove_options+=("$((index + 1))" "$removed" "this relay; pinned and protected" "PINNED")
    else
      remove_options+=("$((index + 1))" "$removed" "configured MyFamily member" "removable")
    fi
  done

  if tui_available; then
    delete_title="MyFamily fingerprints: Space marks, d reviews deletion(s)"
  fi

  if ! choose_checklist selections "$delete_title" --delete "${remove_options[@]}"; then
    warn "No fingerprints selected for deletion."
    return 0
  fi

  for selection in "${selections[@]}"; do
    if ! valid_integer "$selection" || ((10#$selection < 1 || 10#$selection > ${#family_array[@]})); then
      warn "Invalid MyFamily selection: ${selection}"
      continue
    fi

    index=$((10#$selection - 1))
    removed=${family_array[$index]}
    if [[ -n "$local_fp" && "$removed" == "$local_fp" ]]; then
      warn "The local relay fingerprint is pinned and will stay in MyFamily."
      continue
    fi
    selected_for_removal+=("$index")
  done

  ((${#selected_for_removal[@]})) || return 0

  if ! ask_yes_no "Delete ${#selected_for_removal[@]} selected fingerprint(s) from MyFamily?" "no"; then
    warn "No MyFamily fingerprints were deleted."
    return 0
  fi

  for index in "${selected_for_removal[@]}"; do
    if [[ -n "${family_array[$index]+set}" ]]; then
      removed=${family_array[$index]}
      unset 'family_array[index]'
      success "Removed ${removed}."
      removed_count=$((removed_count + 1))
    fi
  done
  family_array=("${family_array[@]}")
  if ((removed_count > 1)); then
    success "Removed ${removed_count} fingerprints."
  fi
}

format_myfamily_csv() {
  local first=1
  local fingerprint

  for fingerprint in "$@"; do
    if ((first)); then
      first=0
    else
      printf ','
    fi
    printf '$%s' "$(normalize_fingerprint "$fingerprint")"
  done
}

save_myfamily_changes() {
  local array_name=$1
  local -n family_array=$array_name
  local local_fp=$2
  local family_csv
  local current_orport

  if [[ -n "$local_fp" ]]; then
    append_unique_fingerprint "$array_name" "$local_fp"
  fi

  ((${#family_array[@]})) || die "No MyFamily fingerprints selected."

  if [[ -n "$local_fp" && ${#family_array[@]} -eq 1 ]]; then
    warn "Only this relay is selected. MyFamily is useful once you add at least one other relay you control."
    if ! ask_yes_no "Write a one-relay MyFamily anyway?" "no"; then
      return 0
    fi
  fi

  family_csv=$(format_myfamily_csv "${family_array[@]}")
  printf '\n'
  info "Tor's documented MyFamily syntax writes each relay fingerprint with a leading '$'."
  step_prefix
  printf '%s\n' "Proposed MyFamily line:"
  step_prefix
  printf '  MyFamily %s\n' "$family_csv"
  warn "Apply this same MyFamily value on every relay controlled by you. One-sided family entries are incomplete until other relays publish matching configs."

  if ! ask_yes_no "Write this MyFamily line to ${TORRC_PATH}?" "no"; then
    warn "MyFamily changes were not written."
    return 0
  fi

  TIMESTAMP=${TIMESTAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}
  write_myfamily_to_torrc "$family_csv"
  verify_tor_config

  current_orport=$(read_torrc_first_orport || true)
  OR_PORT=${current_orport:-$OR_PORT}
  if ask_yes_no "Restart Tor now to apply MyFamily?" "yes"; then
    restart_and_verify_tor
  else
    warn "MyFamily will not be active until Tor reloads or restarts."
  fi
}

manage_myfamily() {
  local local_fp=""
  local -a family_fingerprints=()
  local fingerprint
  local choice

  section "MyFamily Manager"
  torrc_exists || die "${TORRC_PATH} does not exist yet. Run the guided setup first."

  info "Tor clients use MyFamily fingerprints to avoid choosing multiple relays controlled by the same operator in one circuit."
  info "Nicknames are not unique. This tool resolves nicknames through Tor Metrics and asks you to confirm the exact fingerprint."
  info "The saved torrc line will prefix each fingerprint with '$', which is Tor's documented MyFamily format."

  if local_fp=$(local_relay_fingerprint); then
    local_fp=$(normalize_fingerprint "$local_fp")
    if valid_fingerprint "$local_fp"; then
      success "Local relay fingerprint: ${local_fp}"
    else
      warn "Local relay fingerprint file did not contain a valid 40-character fingerprint; it will not be pinned."
      local_fp=""
    fi
  else
    warn "Could not read the local relay fingerprint. Start Tor first or check $(tor_datadirectory)/fingerprint."
  fi

  while IFS= read -r fingerprint; do
    append_unique_fingerprint family_fingerprints "$fingerprint"
  done < <(torrc_myfamily_fingerprints)

  if [[ -n "$local_fp" ]]; then
    if fingerprint_in_array "$local_fp" "${family_fingerprints[@]}"; then
      success "Local relay fingerprint is already included and pinned."
    else
      append_unique_fingerprint family_fingerprints "$local_fp"
      success "Automatically added this relay's fingerprint to MyFamily."
    fi
  fi

  while true; do
    if ! tui_available; then
      print_myfamily_editor_list family_fingerprints "$local_fp"
    fi
    choose_menu choice "MyFamily editor: ${#family_fingerprints[@]} fingerprint(s)" "a" \
      "a" "Add relay(s)" "Nickname lookup or 40-char fingerprint" \
      "v" "View current list" "Show pending fingerprints and pinned local relay" \
      "d" "Review deletions" "Search list, Space marks rows, d reviews selected deletion(s)" \
      "c" "Check published status" "Query Tor Metrics Onionoo" \
      "s" "Save and apply" "Write torrc and optionally restart Tor" \
      "q" "Discard and go back" "Leave torrc unchanged"

    case "$choice" in
      a)
        add_myfamily_member family_fingerprints
        ;;
      v)
        show_myfamily_editor_panel family_fingerprints "$local_fp"
        ;;
      d)
        remove_myfamily_member family_fingerprints "$local_fp"
        ;;
      c)
        lookup_family_status "${family_fingerprints[@]}"
        ;;
      s)
        save_myfamily_changes family_fingerprints "$local_fp"
        return 0
        ;;
      q)
        warn "Discarded unsaved MyFamily changes."
        return 0
        ;;
    esac
  done
}

show_myfamily_status() {
  local -a fingerprints=()
  local fingerprint
  local report_file="$TMP_DIR/configured-myfamily.txt"

  section "MyFamily Status"
  while IFS= read -r fingerprint; do
    append_unique_fingerprint fingerprints "$fingerprint"
  done < <(torrc_myfamily_fingerprints)

  if ((${#fingerprints[@]} == 0)); then
    warn "No MyFamily line is configured in ${TORRC_PATH}."
    return 0
  fi

  {
    printf '%s\n' "Configured MyFamily fingerprints:"
    for fingerprint in "${fingerprints[@]}"; do
      printf '  %s\n' "$fingerprint"
    done
  } > "$report_file"

  if tui_available; then
    show_file_panel "Configured MyFamily" "$report_file"
  else
    while IFS= read -r fingerprint; do
      step_prefix
      printf '%s\n' "$fingerprint"
    done < "$report_file"
  fi
  lookup_family_status "${fingerprints[@]}"
  info "Published family changes can take hours to show up in consensus and Relay Search."
}

# --- Relay families (Happy Families, proposal 321, Tor 0.4.9+) -------------
#
# `tor --keygen-family NAME` writes NAME.secret_family_key (a 96-byte file that
# starts with FAMILY_KEY_HEADER) and NAME.public_family_id into the current
# directory and prints "FamilyId <id>". Every relay in the family needs the
# same secret key in its KeyDirectory plus a matching "FamilyId <id>" line.
# `tor --verify-config` does not check that the key exists, so this script
# does. See https://community.torproject.org/relay/setup/post-install/family-ids/

valid_family_id() {
  [[ $1 =~ ^[A-Za-z0-9+/]{43}$ ]]
}

valid_family_key_name() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

family_key_file_valid() {
  local path=$1
  local header

  [[ -f "$path" && ! -L "$path" && "$path" == *.secret_family_key ]] || return 1
  [[ "$(wc -c < "$path")" -eq 96 ]] || return 1
  header=$(head -c "${#FAMILY_KEY_HEADER}" "$path")
  [[ "$header" == "$FAMILY_KEY_HEADER" ]]
}

# Print the FamilyId stored next to a secret key (NAME.public_family_id).
family_id_for_key_file() {
  local key_file=$1
  local id_file="${key_file%.secret_family_key}.public_family_id"
  local id

  [[ -r "$id_file" ]] || return 1
  id=$(tr -d '[:space:]' < "$id_file")
  valid_family_id "$id" || return 1
  printf '%s' "$id"
}

tor_family_key_directory() {
  local dir

  dir=$(read_torrc_directive FamilyKeyDirectory || true)
  [[ -n "$dir" ]] || dir=$(read_torrc_directive KeyDirectory || true)
  [[ -n "$dir" ]] || dir="$(tor_datadirectory)/keys"
  printf '%s' "${dir%/}"
}

tor_run_user() {
  if id -u debian-tor > /dev/null 2>&1; then
    printf 'debian-tor'
  else
    printf 'root'
  fi
}

torrc_family_ids() {
  torrc_exists || return 0
  awk '
    /^[[:space:]]*#/ { next }
    tolower($1) == "familyid" && NF >= 2 { print $2 }
  ' "$TORRC_PATH"
}

# Succeeds when a key for this FamilyId is installed in the key directory.
family_key_installed_for_id() {
  local id=$1
  local keys_dir
  local key_file

  keys_dir=$(tor_family_key_directory)
  for key_file in "${keys_dir}"/*.secret_family_key; do
    [[ -e "$key_file" ]] || continue
    if [[ "$id" == "*" || "$(family_id_for_key_file "$key_file" || true)" == "$id" ]]; then
      return 0
    fi
  done
  return 1
}

# Install a secret family key (and its public ID) into Tor's key directory,
# owned by the Tor user. Existing keys are never overwritten.
install_family_key() {
  local source=$1
  local name=$2
  local id=$3
  local keys_dir
  local user
  local target
  local id_file
  local -a owner=()

  keys_dir=$(tor_family_key_directory)
  target="${keys_dir}/${name}.secret_family_key"
  id_file="${TMP_DIR}/${name}.public_family_id"
  user=$(tor_run_user)
  # A dry run before tor is installed has no debian-tor user yet.
  ((DRY_RUN)) && [[ "$user" == "root" ]] && user="debian-tor"
  # Only root can hand files to the Tor user (tests run unprivileged).
  ((EUID == 0 || DRY_RUN)) && owner=(-o "$user" -g "$user")

  if [[ -e "$target" ]]; then
    if cmp -s "$source" "$target"; then
      success "Family key already installed: ${target}"
      return 0
    fi
    die "A different family key already exists at ${target}. Choose another key name; existing keys are never overwritten."
  fi

  printf '%s\n' "$id" > "$id_file"
  if ((DRY_RUN)); then
    info "Would install the family key into ${keys_dir}"
    print_command install -d -m 0700 "${owner[@]}" "$keys_dir"
    print_command install -m 0600 "${owner[@]}" "$source" "$target"
    return 0
  fi

  [[ -d "$keys_dir" ]] || install -d -m 0700 "${owner[@]}" "$keys_dir"
  install -m 0600 "${owner[@]}" "$source" "$target"
  install -m 0600 "${owner[@]}" "$id_file" "${keys_dir}/${name}.public_family_id"
  success "Installed family key ${target}"
}

# Generate a new family key with tor itself and install it. Sets FAMILY_ID.
generate_family_key() {
  local name=$1
  local work_dir
  local empty_torrc

  if ((DRY_RUN)); then
    info "Would generate a new family key named ${name}"
    print_command tor --keygen-family "$name"
    install_family_key "${name}.secret_family_key" "$name" "$FAMILY_ID"
    return 0
  fi

  work_dir=$(mktemp -d "${TMP_DIR%/}/family.XXXXXX")
  empty_torrc="${work_dir}/empty.torrc"
  : > "$empty_torrc"
  # keygen-family writes into the working directory; empty config files keep
  # the live torrc (and its Sandbox setting) out of the way.
  run_cmd "Generating family key ${name}" \
    env -C "$work_dir" tor --defaults-torrc "$empty_torrc" -f "$empty_torrc" --keygen-family "$name"

  family_key_file_valid "${work_dir}/${name}.secret_family_key" \
    || die "tor --keygen-family did not produce a valid ${name}.secret_family_key."
  FAMILY_ID=$(family_id_for_key_file "${work_dir}/${name}.secret_family_key") \
    || die "tor --keygen-family did not produce a readable ${name}.public_family_id."
  install_family_key "${work_dir}/${name}.secret_family_key" "$name" "$FAMILY_ID"
  success "New FamilyId: ${FAMILY_ID}"
}

# Apply the family choice made during guided setup (after tor is installed).
setup_relay_family() {
  case "$FAMILY_MODE" in
    generate)
      generate_family_key "$FAMILY_KEY_NAME"
      ;;
    import)
      install_family_key "$FAMILY_IMPORT_KEY_PATH" "$FAMILY_KEY_NAME" "$FAMILY_ID"
      ;;
    *) ;;
  esac
}

# Replace every FamilyId line in the live torrc with the given IDs.
write_family_ids_to_torrc() {
  local output=$1
  shift
  local ids
  ids=$(printf '%s\n' "$@")

  torrc_exists || die "${TORRC_PATH} does not exist yet."
  awk -v ids="$ids" '
    function emit_family(   count, parts, i) {
      if (ids == "") return
      print ""
      print "# Managed relay family (Tor 0.4.9 FamilyId). Every relay in the family shares the key."
      count = split(ids, parts, "\n")
      for (i = 1; i <= count; i++) {
        if (parts[i] != "") print "FamilyId " parts[i]
      }
    }
    /^[[:space:]]*#[[:space:]]*Managed relay family/ { next }
    !/^[[:space:]]*#/ && tolower($1) == "familyid" { next }
    {
      print
      if (!inserted && $0 ~ /^[[:space:]]*ContactInfo[[:space:]]+/) {
        emit_family()
        inserted = 1
      }
    }
    END {
      if (!inserted) emit_family()
    }
  ' "$TORRC_PATH" > "$output"
}

show_relay_family_status() {
  local report_file="${TMP_DIR}/relay-family.txt"
  local keys_dir
  local id
  local key_file
  local -a ids=()
  local legacy_count

  keys_dir=$(tor_family_key_directory)
  mapfile -t ids < <(torrc_family_ids)
  legacy_count=$(torrc_myfamily_fingerprints | awk 'END { print NR + 0 }')

  {
    printf 'Relay family status\n\n'
    printf 'Family key directory: %s\n\n' "$keys_dir"
    if ((${#ids[@]} == 0)); then
      printf 'No FamilyId is configured in %s.\n' "$TORRC_PATH"
    fi
    for id in "${ids[@]}"; do
      if family_key_installed_for_id "$id"; then
        printf 'FamilyId %s  key: installed\n' "$id"
      else
        printf 'FamilyId %s  key: NOT FOUND (Tor cannot prove membership)\n' "$id"
      fi
    done
    printf '\nInstalled family keys:\n'
    for key_file in "${keys_dir}"/*.secret_family_key; do
      [[ -e "$key_file" ]] || continue
      printf '  %s  FamilyId %s\n' "$key_file" "$(family_id_for_key_file "$key_file" || printf 'unknown')"
    done
    printf '\nLegacy MyFamily fingerprints: %s\n' "$legacy_count"
  } > "$report_file"

  show_file_panel "Relay Family" "$report_file"
}

show_family_share_instructions() {
  local keys_dir
  local key_file
  local report_file="${TMP_DIR}/relay-family-share.txt"

  keys_dir=$(tor_family_key_directory)
  {
    printf 'Add another relay to this family\n\n'
    printf '1. Copy the secret key and its public ID to the new relay, for example:\n\n'
    for key_file in "${keys_dir}"/*.secret_family_key; do
      [[ -e "$key_file" ]] || continue
      printf '   scp %q %q root@NEW-RELAY:/root/\n' "$key_file" "${key_file%.secret_family_key}.public_family_id"
    done
    printf '\n2. On the new relay, run this script and choose "Import an existing family key"\n'
    printf '   (guided setup) or "Relay family" > "Import family key" (operator console).\n\n'
    printf '3. Delete the copies from /root on the new relay afterwards.\n\n'
    printf 'The secret key proves family membership. Treat it like a relay identity key:\n'
    printf 'transfer it only over SSH and keep it out of backups you share.\n'
  } > "$report_file"
  show_file_panel "Share Family Key" "$report_file"
}

apply_family_ids() {
  local candidate
  candidate=$(mktemp_in_workspace)

  write_family_ids_to_torrc "$candidate" "$@"
  ensure_timestamp
  verify_tor_config_file "$candidate"
  install_file_if_changed "$candidate" "$TORRC_PATH" "0644"
  # With Sandbox 1, Tor cannot open new family key files after start-up, so
  # family changes need a restart rather than a reload.
  if ask_yes_no "Restart Tor now to apply the family change?" "yes"; then
    OR_PORT=$(read_torrc_first_orport || printf '%s' "$OR_PORT")
    restart_and_verify_tor
  else
    warn "The family change is written but inactive until Tor restarts."
  fi
}

manage_relay_family() {
  local choice
  local path
  local name
  local id
  local -a ids=()
  local -a kept=()

  section "Relay Family"
  torrc_exists || die "${TORRC_PATH} does not exist yet. Run the guided setup first."
  info "Tor 0.4.9 families use a shared key (FamilyId). MyFamily fingerprint lists are the legacy method."

  while true; do
    mapfile -t ids < <(torrc_family_ids)
    choose_menu choice "Relay family: ${#ids[@]} FamilyId line(s)" "s" \
      "s" "Show family status" "FamilyId lines, installed keys, legacy MyFamily" \
      "g" "Create a new family key" "Start a family, or rotate to a new key" \
      "i" "Import family key" "Join a family using a key copied from another relay" \
      "e" "Share with another relay" "How to copy this family's key safely" \
      "r" "Remove a FamilyId" "Leave a family (key files stay on disk)" \
      "m" "Legacy MyFamily editor" "Fingerprint lists for pre-0.4.9 clients" \
      "q" "Back" "Return to operator console"

    case "$choice" in
      s)
        show_relay_family_status
        ;;
      g | i)
        if [[ "$choice" == "g" ]]; then
          while true; do
            name=$(prompt_line "Family key name" "relay-family")
            valid_family_key_name "$name" && break
            warn "Use letters, numbers, dots, dashes or underscores (max 64 characters)."
          done
          FAMILY_ID=""
          generate_family_key "$name"
          id=$FAMILY_ID
        else
          path=$(prompt_line "Path to the .secret_family_key file")
          if ! family_key_file_valid "$path"; then
            warn "Expected a 96-byte Tor family key file ending in .secret_family_key."
            continue
          fi
          if ! id=$(family_id_for_key_file "$path"); then
            id=$(prompt_line "FamilyId shown on the relay that created the key")
            valid_family_id "$id" || {
              warn "A FamilyId is 43 base64 characters."
              continue
            }
          fi
          install_family_key "$path" "$(basename "$path" .secret_family_key)" "$id"
        fi
        if ((DRY_RUN)); then
          info "Would add FamilyId ${id:-<generated id>} to ${TORRC_PATH} and restart Tor."
          continue
        fi
        kept=("$id")
        if ((${#ids[@]})) && ask_yes_no "Keep the existing FamilyId line(s) as well (key rotation or multiple families)?" "yes"; then
          kept=("${ids[@]}" "$id")
        fi
        apply_family_ids "${kept[@]}"
        ;;
      e)
        show_family_share_instructions
        ;;
      r)
        if ((${#ids[@]} == 0)); then
          warn "No FamilyId is configured."
          continue
        fi
        local -a remove_options=()
        local -a picked=()
        local index
        for index in "${!ids[@]}"; do
          remove_options+=("$((index + 1))" "${ids[$index]}" "FamilyId line" "removable")
        done
        choose_checklist picked "FamilyId lines to remove" --delete "${remove_options[@]}" || continue
        kept=()
        for index in "${!ids[@]}"; do
          selection_contains "$((index + 1))" "${picked[@]}" || kept+=("${ids[$index]}")
        done
        if ask_yes_no "Remove ${#picked[@]} FamilyId line(s)? Key files are kept." "no"; then
          apply_family_ids "${kept[@]}"
        fi
        ;;
      m)
        manage_myfamily
        ;;
      q | "")
        return 0
        ;;
    esac
  done
}

# Warn about family problems Tor logged since the given time.
check_family_logs() {
  local since_time=$1
  local warnings

  [[ -n "$(torrc_family_ids)" ]] || return 0
  command_exists journalctl || return 0
  warnings=$(journalctl -u "$TOR_SERVICE" --since "$since_time" -p warning --no-pager -o cat 2> /dev/null | grep -i 'family' || true)
  if [[ -n "$warnings" ]]; then
    warn "Tor logged family warnings after the restart:"
    printf '%s\n' "$warnings" | head -n 5 >&2
  else
    success "No family key warnings were logged."
  fi
}

ensure_timestamp() {
  TIMESTAMP=${TIMESTAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}
}

mark_script_installed_fzf() {
  if ((DRY_RUN)); then
    info "Would record that this script installed fzf."
    return 0
  fi

  install -d -m 0700 "$STATE_DIR"
  {
    printf 'installed_fzf=1\n'
    printf 'installed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'script=%s\n' "$SCRIPT_NAME"
  } > "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
}

script_installed_fzf() {
  [[ -r "$STATE_FILE" ]] && grep -Fxq 'installed_fzf=1' "$STATE_FILE"
}

selection_contains() {
  local needle=$1
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

strip_torrc_quotes() {
  local value=$1
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value=${value#\"}
    value=${value%\"}
    value=${value//\\\"/\"}
    value=${value//\\\\/\\}
  fi
  printf '%s' "$value"
}

read_torrc_directive() {
  local directive=$1
  torrc_exists || return 1
  awk -v wanted="${directive,,}" '
    /^[[:space:]]*#/ { next }
    tolower($1) == wanted {
      $1 = ""
      sub(/^[[:space:]]+/, "")
      print
      exit
    }
  ' "$TORRC_PATH"
}

write_torrc_set_directive() {
  local output=$1
  local directive=$2
  local directive_line=$3

  torrc_exists || die "${TORRC_PATH} does not exist yet."
  awk -v wanted="${directive,,}" -v replacement="$directive_line" '
    BEGIN { replaced = 0 }
    /^[[:space:]]*#/ { print; next }
    tolower($1) == wanted {
      if (!replaced) {
        print replacement
        replaced = 1
      }
      next
    }
    { print }
    END {
      if (!replaced) {
        print replacement
      }
    }
  ' "$TORRC_PATH" > "$output"
}

write_torrc_bandwidth() {
  local output=$1

  torrc_exists || die "${TORRC_PATH} does not exist yet."
  awk '
    /^[[:space:]]*#/ { print; next }
    tolower($1) == "relaybandwidthrate" { next }
    tolower($1) == "relaybandwidthburst" { next }
    tolower($1) == "accountingstart" { next }
    tolower($1) == "accountingrule" { next }
    tolower($1) == "accountingmax" { next }
    { print }
  ' "$TORRC_PATH" > "$output"

  {
    printf '\n'
    printf '# Managed bandwidth and traffic settings.\n'
    if ((CONFIGURE_RELAY_BANDWIDTH)); then
      printf 'RelayBandwidthRate %s %s\n' "$RELAY_BANDWIDTH_RATE_VALUE" "$RELAY_BANDWIDTH_RATE_UNIT"
      printf 'RelayBandwidthBurst %s %s\n' "$RELAY_BANDWIDTH_BURST_VALUE" "$RELAY_BANDWIDTH_BURST_UNIT"
    fi
    if ((CONFIGURE_ACCOUNTING)); then
      printf 'AccountingStart month 1 00:00\n'
      if [[ "$ACCOUNTING_RULE" != "max" ]]; then
        printf 'AccountingRule %s\n' "$ACCOUNTING_RULE"
      fi
      printf 'AccountingMax %s GBytes\n' "$ACCOUNTING_MAX_GBYTES"
    fi
  } >> "$output"
}

reload_or_restart_tor() {
  if ((DRY_RUN)); then
    info "Would reload ${TOR_SERVICE}, falling back to restart if reload is unavailable."
    print_command systemctl reload "$TOR_SERVICE"
    return 0
  fi

  if run_cmd "Reloading ${TOR_SERVICE}" systemctl reload "$TOR_SERVICE"; then
    success "Reloaded ${TOR_SERVICE}."
  else
    warn "Reload failed or is unsupported; restarting ${TOR_SERVICE} instead."
    restart_and_verify_tor
  fi
}

# apply_existing_torrc_change CANDIDATE DESCRIPTION [reload|restart]
apply_existing_torrc_change() {
  local candidate=$1
  local description=$2
  local activation=${3:-reload}

  ensure_timestamp
  verify_tor_config_file "$candidate"
  install_file_if_changed "$candidate" "$TORRC_PATH" "0644"
  if [[ "$activation" == "restart" ]]; then
    if ask_yes_no "Restart Tor now to apply ${description}?" "yes"; then
      OR_PORT=$(read_torrc_first_orport || printf '%s' "$OR_PORT")
      restart_and_verify_tor
    else
      warn "Change is written but will not be active until Tor restarts."
    fi
  elif ask_yes_no "Reload Tor now to apply ${description}?" "yes"; then
    reload_or_restart_tor
  else
    warn "Change is written but will not be active until Tor reloads or restarts."
  fi
}

# Rewrite the live torrc without MetricsPort lines, then add the local-only
# MetricsPort block when ENABLE is 1.
write_torrc_metrics_port() {
  local output=$1
  local enable=$2

  torrc_exists || die "${TORRC_PATH} does not exist yet."
  awk '
    /^[[:space:]]*#[[:space:]]*Local-only Prometheus metrics/ { next }
    !/^[[:space:]]*#/ && (tolower($1) == "metricsport" || tolower($1) == "metricsportpolicy") { next }
    { print }
  ' "$TORRC_PATH" > "$output"
  if ((enable)); then
    {
      printf '\n# Local-only Prometheus metrics. Never expose this port publicly.\n'
      printf 'MetricsPort %s\n' "$METRICS_PORT_ADDRESS"
      printf 'MetricsPortPolicy accept 127.0.0.1\n'
    } >> "$output"
  fi
}

configure_common_torrc_menu() {
  local choice
  local current
  local candidate

  while true; do
    section "Configuration Editor"
    choose_menu choice "Common relay settings" "1" \
      "1" "Relay nickname" "Change Nickname safely" \
      "2" "ContactInfo" "Change public operator contact string" \
      "3" "Bandwidth and traffic" "Recalculate relay bandwidth/accounting limits" \
      "4" "Sandbox" "Toggle Tor syscall Sandbox option" \
      "5" "Disable SOCKS listener" "Write SocksPort 0 for relay-only servers" \
      "7" "MetricsPort" "Toggle local-only Prometheus metrics on ${METRICS_PORT_ADDRESS}" \
      "6" "Back" "Return to operator console"

    case "$choice" in
      1)
        current=$(read_torrc_directive Nickname || true)
        while true; do
          current=$(prompt_line "Relay nickname" "${current:-RelayName}")
          if valid_nickname "$current"; then
            break
          fi
          warn "Use 1 to 19 characters, letters and numbers only."
        done
        candidate=$(mktemp_in_workspace)
        write_torrc_set_directive "$candidate" Nickname "Nickname ${current}"
        apply_existing_torrc_change "$candidate" "nickname change"
        ;;
      2)
        current=$(strip_torrc_quotes "$(read_torrc_directive ContactInfo || true)")
        info "Current ContactInfo: ${current:-none}"
        collect_contact_info "$current"
        candidate=$(mktemp_in_workspace)
        write_torrc_set_directive "$candidate" ContactInfo "ContactInfo $(torrc_quote "$CONTACT_INFO")"
        apply_existing_torrc_change "$candidate" "ContactInfo change"
        ;;
      3)
        collect_bandwidth
        candidate=$(mktemp_in_workspace)
        write_torrc_bandwidth "$candidate"
        apply_existing_torrc_change "$candidate" "bandwidth change"
        ;;
      4)
        if ask_yes_no "Enable Tor Sandbox 1?" "yes"; then
          current="Sandbox 1"
        else
          current="Sandbox 0"
        fi
        candidate=$(mktemp_in_workspace)
        write_torrc_set_directive "$candidate" Sandbox "$current"
        # Tor refuses to change Sandbox on reload; it needs a restart.
        apply_existing_torrc_change "$candidate" "Sandbox change" restart
        ;;
      5)
        candidate=$(mktemp_in_workspace)
        write_torrc_set_directive "$candidate" SocksPort "SocksPort 0"
        apply_existing_torrc_change "$candidate" "SOCKS listener change"
        ;;
      7)
        candidate=$(mktemp_in_workspace)
        if ask_yes_no "Enable MetricsPort on ${METRICS_PORT_ADDRESS} (local access only)?" "yes"; then
          write_torrc_metrics_port "$candidate" 1
        else
          write_torrc_metrics_port "$candidate" 0
        fi
        apply_existing_torrc_change "$candidate" "MetricsPort change"
        ;;
      6 | "")
        return 0
        ;;
    esac
  done
}

show_relay_directory_status() {
  local local_fp
  local json_file="$TMP_DIR/onionoo-details.json"
  local report_file="$TMP_DIR/relay-directory-status.txt"
  local python_bin

  section "Relay Directory Status"

  if ! local_fp=$(local_relay_fingerprint); then
    warn "Local relay fingerprint is not readable yet. Start Tor once, then retry."
    return 0
  fi
  local_fp=$(normalize_fingerprint "$local_fp")
  success "Local relay fingerprint: ${local_fp}"
  printf 'Relay Search: https://metrics.torproject.org/rs.html#details/%s\n' "$local_fp" > "$report_file"

  python_bin=$(python_command) || {
    warn "python3/python is unavailable; cannot parse Onionoo details."
    show_file_panel "Relay Directory Status" "$report_file"
    return 0
  }

  fetch_url_to_file "${ONIONOO_BASE_URL}/details?lookup=${local_fp}" "$json_file" || {
    warn "Could not fetch Tor Metrics Onionoo details."
    show_file_panel "Relay Directory Status" "$report_file"
    return 0
  }

  "$python_bin" - "$json_file" >> "$report_file" << 'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    document = json.load(handle)

relays = document.get("relays", [])
if not relays:
    print("Onionoo has not published this relay yet. New relays can take about 3 hours to appear.")
    raise SystemExit

relay = relays[0]
fields = [
    ("Nickname", relay.get("nickname", "")),
    ("Running", "yes" if relay.get("running") else "no"),
    ("Flags", ", ".join(relay.get("flags", []))),
    ("First seen", relay.get("first_seen", "")),
    ("Last seen", relay.get("last_seen", "")),
    ("Advertised bandwidth", relay.get("advertised_bandwidth", "")),
    ("Observed bandwidth", relay.get("observed_bandwidth", "")),
    ("Consensus weight", relay.get("consensus_weight", "")),
    ("Platform", relay.get("platform", "")),
    ("Family IDs", ", ".join(relay.get("family_ids", []) or [])),
    ("Contact", relay.get("contact", "")),
]
for key, value in fields:
    if value != "":
        print(f"{key}: {value}")

addresses = relay.get("or_addresses", [])
if addresses:
    print("OR addresses:")
    for address in addresses:
        print(f"  {address}")
PY
  show_file_panel "Relay Directory Status" "$report_file"
}

service_control_menu() {
  local choice

  while true; do
    section "Service Controls"
    choose_menu choice "Manage ${TOR_SERVICE}" "1" \
      "1" "Status" "Show systemd service status" \
      "2" "Start" "Start and enable Tor" \
      "3" "Reload" "Reload torrc without a full restart when possible" \
      "4" "Restart" "Restart and verify Tor" \
      "5" "Stop" "Stop Tor after confirmation" \
      "6" "Disable" "Disable Tor autostart after confirmation" \
      "7" "Back" "Return to operator console"

    case "$choice" in
      1)
        if command_exists systemctl; then
          capture_command_panel "${TOR_SERVICE} status" systemctl status "$TOR_SERVICE" --no-pager || true
        else
          warn "systemctl is unavailable."
        fi
        ;;
      2)
        run_cmd "Enabling ${TOR_SERVICE}" systemctl enable "$TOR_SERVICE"
        run_cmd "Starting ${TOR_SERVICE}" systemctl start "$TOR_SERVICE"
        ;;
      3)
        verify_tor_config
        reload_or_restart_tor
        ;;
      4)
        restart_and_verify_tor
        ;;
      5)
        if ask_yes_no "Stop Tor now? This relay will go offline." "no"; then
          run_cmd "Stopping ${TOR_SERVICE}" systemctl stop "$TOR_SERVICE"
        fi
        ;;
      6)
        if ask_yes_no "Disable Tor autostart? The relay will not start after reboot." "no"; then
          run_cmd "Disabling ${TOR_SERVICE}" systemctl disable "$TOR_SERVICE"
        fi
        ;;
      7 | "")
        return 0
        ;;
    esac
  done
}

logs_menu() {
  local choice

  while true; do
    section "Logs and Signals"
    choose_menu choice "Tor logs" "1" \
      "1" "Recent Tor logs" "Show last 120 journal lines" \
      "2" "Follow Tor logs" "Live journalctl follow until Ctrl+C" \
      "3" "ORPort self-test" "Look for Tor reachability messages" \
      "4" "Back" "Return to operator console"

    case "$choice" in
      1)
        if command_exists journalctl; then
          capture_command_panel "Recent Tor logs" journalctl -u "$TOR_SERVICE" -n 120 --no-pager || true
        else
          warn "journalctl is unavailable."
        fi
        ;;
      2)
        if command_exists journalctl; then
          follow_command_panel "Live Tor logs" journalctl -u "$TOR_SERVICE" -f
        else
          warn "journalctl is unavailable."
        fi
        ;;
      3)
        check_tor_orport_self_test "1 hour ago" 0
        ;;
      4 | "")
        return 0
        ;;
    esac
  done
}

collect_torrc_backups() {
  local -n output_ref=$1
  local backup
  output_ref=()

  for backup in "${TORRC_PATH}".bak.*; do
    [[ -e "$backup" ]] || continue
    output_ref+=("$backup")
  done
}

choose_torrc_backup() {
  local result_name=$1
  local -n result_ref=$result_name
  local -a backups=()
  local -a options=()
  local choice
  local index

  result_ref=""
  collect_torrc_backups backups
  ((${#backups[@]})) || {
    warn "No ${TORRC_PATH}.bak.* backups were found."
    return 1
  }

  for ((index = 0; index < ${#backups[@]}; index++)); do
    options+=("$((index + 1))" "${backups[$index]}" "restore this torrc backup")
  done

  choose_menu choice "Choose a torrc backup" "1" "${options[@]}"
  [[ -n "$choice" ]] || return 1
  result_ref=${backups[$((10#$choice - 1))]}
}

backup_identity_keys() {
  local data_dir
  local keys_dir
  local archive
  local backup_timestamp
  local suffix=0

  section "Identity Key Backup"
  data_dir=$(tor_datadirectory)
  keys_dir="${data_dir%/}/keys"
  [[ -d "$keys_dir" ]] || die "Tor keys directory not found: ${keys_dir}"

  warn "The archive holds the relay identity keys and any family keys. Store it somewhere secure and private."
  if ! ask_yes_no "Create a root-only archive of ${keys_dir}?" "yes"; then
    return 0
  fi

  backup_timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  archive="/root/tor-relay-identity-keys.${backup_timestamp}.tar.gz"
  while [[ -e "$archive" ]]; do
    suffix=$((suffix + 1))
    archive="/root/tor-relay-identity-keys.${backup_timestamp}.${suffix}.tar.gz"
  done
  if ((DRY_RUN)); then
    info "Would create ${archive}"
    print_command tar -C "$data_dir" -czf "$archive" keys
    print_command chmod 600 "$archive"
  else
    tar -C "$data_dir" -czf "$archive" keys
    chmod 600 "$archive"
    success "Created ${archive}"
  fi
}

backups_menu() {
  local choice
  local backup

  while true; do
    section "Backups"
    choose_menu choice "Backup and restore" "1" \
      "1" "Back up torrc" "Create a timestamped ${TORRC_PATH} backup" \
      "2" "Back up identity keys" "Create a sensitive root-only archive" \
      "3" "List backups" "Show torrc and identity-key archives" \
      "4" "Restore torrc backup" "Restore a selected torrc backup and verify" \
      "5" "Back" "Return to operator console"

    case "$choice" in
      1)
        ensure_timestamp
        backup_file "$TORRC_PATH"
        ;;
      2)
        backup_identity_keys
        ;;
      3)
        section "Available Backups"
        local backups_report="$TMP_DIR/backups-list.txt"
        {
          printf '%s\n' "torrc backups:"
          for backup in "${TORRC_PATH}".bak.*; do
            [[ -e "$backup" ]] || continue
            printf '  %s\n' "$backup"
          done
          printf '\n%s\n' "identity key archives:"
          for backup in /root/tor-relay-identity-keys.*.tar.gz; do
            [[ -e "$backup" ]] || continue
            printf '  %s\n' "$backup"
          done
        } > "$backups_report"
        show_file_panel "Available Backups" "$backups_report"
        ;;
      4)
        if choose_torrc_backup backup; then
          if ask_yes_no "Restore ${backup} to ${TORRC_PATH}?" "no"; then
            ensure_timestamp
            verify_tor_config_file "$backup"
            install_file_if_changed "$backup" "$TORRC_PATH" "0644"
            verify_tor_config
            if ask_yes_no "Reload Tor after restoring torrc?" "yes"; then
              reload_or_restart_tor
            fi
          fi
        fi
        ;;
      5 | "")
        return 0
        ;;
    esac
  done
}

package_tools_menu() {
  local choice

  while true; do
    section "Packages and Tools"
    choose_menu choice "Package maintenance" "1" \
      "1" "Update Tor" "Refresh apt and upgrade Tor packages" \
      "2" "Repair Tor apt repo" "Reinstall prerequisites, keyring file, and source" \
      "3" "Configure automatic updates" "Install unattended-upgrades config" \
      "4" "Install Nyx" "Terminal relay monitor" \
      "5" "Install fzf" "Searchable selector dependency" \
      "6" "Back" "Return to operator console"

    case "$choice" in
      1)
        check_apt_capacity
        install_tor_package
        ;;
      2)
        check_apt_capacity
        install_repository_prerequisites
        configure_tor_repository
        ;;
      3)
        check_apt_capacity
        configure_unattended_upgrades
        ;;
      4)
        check_apt_capacity
        INSTALL_NYX=1
        install_nyx_package
        ;;
      5)
        local fzf_was_installed=0
        if apt_package_installed fzf; then
          fzf_was_installed=1
        fi
        check_apt_capacity
        run_cmd "Installing fzf" env DEBIAN_FRONTEND=noninteractive apt-get install -y fzf
        if ((DRY_RUN)); then
          info "Would record that this script installed fzf."
        elif command_exists fzf && ((fzf_was_installed == 0)); then
          mark_script_installed_fzf
          if ! ((PLAIN_TUI)); then
            USE_FZF=1
            success "Polished selector mode enabled with fzf for this session."
          fi
        elif command_exists fzf; then
          success "fzf is installed; not marking it as script-installed because it was already present."
        fi
        ;;
      6 | "")
        return 0
        ;;
    esac
  done
}

command_logs_menu() {
  local choice
  local list_file
  local output_file
  local -a fzf_lines=()
  local log_file

  section "Command Logs"
  ensure_command_log_dir

  if ! find "$COMMAND_LOG_DIR" -type f -name '*.log' -print -quit 2> /dev/null | grep -q .; then
    warn "No command logs are available in this run yet."
    return 0
  fi

  if tui_available; then
    list_file=$(mktemp_in_workspace)
    output_file=$(mktemp_in_workspace)
    while IFS= read -r log_file; do
      printf '%s\t%s\t%s\n' "$log_file" "$(basename "$log_file")" "Command output captured during this run" >> "$list_file"
    done < <(find "$COMMAND_LOG_DIR" -type f -name '*.log' -printf '%T@ %p\n' 2> /dev/null | sort -nr | awk '{ $1=""; sub(/^ /, ""); print }')

    if env FZF_DEFAULT_OPTS= fzf \
      --height=90% \
      --reverse \
      --border \
      --margin=1,2 \
      --delimiter=$'\t' \
      --with-nth=2,3 \
      --prompt="logs> " \
      --pointer=">" \
      --header="Select a command log. Enter opens it; Esc returns." \
      --preview='sed -n "1,240p" {1}' \
      --preview-window=down:70%:wrap \
      --color="$FZF_COLORS" \
      < "$list_file" > "$output_file"; then
      mapfile -t fzf_lines < "$output_file"
      choice=${fzf_lines[0]%%$'\t'*}
      [[ -n "$choice" ]] && show_file_panel "Command Log: $(basename "$choice")" "$choice"
    fi
    rm -f -- "$list_file" "$output_file"
  else
    while IFS= read -r log_file; do
      printf '  %s\n' "$log_file"
    done < <(find "$COMMAND_LOG_DIR" -type f -name '*.log' -print | sort)
  fi
}

script_realpath() {
  local source_path=${BASH_SOURCE[0]:-$0}
  case "$source_path" in
    bash | sh | dash | bash.exe | sh.exe | dash.exe | -bash | -sh)
      return 1
      ;;
  esac

  [[ -e "$source_path" ]] || return 1
  if command_exists readlink; then
    readlink -f "$source_path" 2> /dev/null && return 0
  fi

  (cd "$(dirname "$source_path")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$source_path")")
}

script_repo_root() {
  local path=$1
  local dir
  dir=$(dirname "$path")
  command_exists git || return 1
  git -C "$dir" rev-parse --show-toplevel 2> /dev/null
}

repo_looks_like_this_project() {
  local repo_root=$1
  [[ -d "$repo_root/.git" ]] || return 1
  git -C "$repo_root" remote -v 2> /dev/null | grep -Eq 'github\.com[:/]ljkx/tor-relay-setup(\.git)?'
}

repo_clean_for_deletion() {
  local repo_root=$1
  [[ -z "$(git -C "$repo_root" status --porcelain 2> /dev/null)" ]]
}

safe_remove_script_path() {
  local target=$1
  [[ -n "$target" && -e "$target" ]] || return 0
  case "$target" in
    / | /root | /home | /etc | /usr | /var | /tmp)
      die "Refusing to remove unsafe path: ${target}"
      ;;
  esac

  if ((DRY_RUN)); then
    info "Would remove ${target}"
    print_command rm -rf -- "$target"
  else
    rm -rf -- "$target"
    success "Removed ${target}"
  fi
}

remove_tmp_operator_reports() {
  local report
  for report in /tmp/tor-relay-report.*.txt; do
    [[ -e "$report" ]] || continue
    if ! head -n 1 "$report" 2> /dev/null | grep -Fxq "Tor Relay Operator Report"; then
      warn "Skipping ${report}; it does not have this tool's report header."
      continue
    fi
    if ((DRY_RUN)); then
      info "Would remove ${report}"
    else
      rm -f -- "$report"
      success "Removed ${report}"
    fi
  done
}

cleanup_script_traces() {
  local script_path=""
  local repo_root=""
  local choice
  local -a cleanup_options=()
  local -a selections=()
  local token

  section "Clean Script Traces"
  warn "This removes traces of this installer/tool only. It will not remove Tor, torrc, relay keys, logs, firewall rules, or the running relay."

  script_path=$(script_realpath || true)
  if [[ -n "$script_path" ]]; then
    repo_root=$(script_repo_root "$script_path" || true)
  fi

  cleanup_options+=("state" "$STATE_DIR" "script state/manifest only" "safe")
  cleanup_options+=("reports" "/tmp/tor-relay-report.*.txt" "operator reports created by this tool" "safe")

  if script_installed_fzf; then
    cleanup_options+=("fzf" "fzf package" "optional removal because this script recorded installing it" "optional")
  fi

  if [[ -n "$repo_root" ]] && repo_looks_like_this_project "$repo_root"; then
    if ! repo_clean_for_deletion "$repo_root"; then
      warn "Repo checkout has local changes or untracked files, so it will not be offered for deletion: ${repo_root}"
    else
      cleanup_options+=("repo" "$repo_root" "delete this clean cloned tor-relay-setup checkout" "destructive")
    fi
  fi

  if [[ -z "$repo_root" || ! -d "$repo_root/.git" ]]; then
    if [[ -n "$script_path" ]]; then
      cleanup_options+=("script" "$script_path" "delete this downloaded script file" "destructive")
    else
      warn "Could not identify a standalone script path. If you used curl | bash, there is no downloaded script file to remove."
    fi
  elif [[ -n "$repo_root" ]] && ! repo_looks_like_this_project "$repo_root" && [[ -n "$script_path" ]]; then
    cleanup_options+=("script" "$script_path" "delete this downloaded script file" "destructive")
  fi

  if ! choose_checklist selections "Select script traces to remove" --delete "${cleanup_options[@]}"; then
    warn "No script traces selected for cleanup."
    return 0
  fi

  printf '\n%s\n' "Selected cleanup actions:"
  for choice in "${selections[@]}"; do
    case "$choice" in
      state) printf '  - Remove %s\n' "$STATE_DIR" ;;
      reports) printf '  - Remove /tmp/tor-relay-report.*.txt\n' ;;
      fzf) printf '  - Purge fzf package if apt installed it\n' ;;
      repo) printf '  - Delete repo checkout: %s\n' "$repo_root" ;;
      script) printf '  - Delete script file: %s\n' "$script_path" ;;
    esac
  done

  warn "Tor itself is intentionally out of scope for this cleanup."
  if ! ask_yes_no "Apply selected script-trace cleanup actions?" "no"; then
    warn "Cleanup cancelled."
    return 0
  fi

  if selection_contains repo "${selections[@]}" || selection_contains script "${selections[@]}"; then
    token=$(prompt_line "Type DELETE SCRIPT TRACES to confirm removing script files")
    if [[ "$token" != "DELETE SCRIPT TRACES" ]]; then
      warn "Script file/repo deletion skipped."
      # Filter whole entries; pattern substitution would also mangle "reports".
      local -a kept=()
      for choice in "${selections[@]}"; do
        [[ "$choice" == "repo" || "$choice" == "script" ]] || kept+=("$choice")
      done
      selections=("${kept[@]}")
    fi
  fi

  if selection_contains reports "${selections[@]}"; then
    remove_tmp_operator_reports
  fi

  if selection_contains fzf "${selections[@]}"; then
    if ask_yes_no "Purge fzf now? Skip this if you use fzf for anything else." "no"; then
      run_cmd "Purging fzf" env DEBIAN_FRONTEND=noninteractive apt-get purge -y fzf
    fi
  fi

  if selection_contains state "${selections[@]}"; then
    safe_remove_script_path "$STATE_DIR"
  fi

  if selection_contains script "${selections[@]}"; then
    safe_remove_script_path "$script_path"
  fi

  if selection_contains repo "${selections[@]}"; then
    safe_remove_script_path "$repo_root"
  fi

  success "Script-trace cleanup finished. Tor relay state was left untouched."
}

operator_report() {
  local report=""
  local local_fp=""
  local current_orport=""

  section "Operator Report"
  if ((DRY_RUN)); then
    info "Would write a root-readable operator report with service, torrc, and recent warning context."
    return 0
  fi

  local_fp=$(local_relay_fingerprint || true)
  current_orport=$(read_torrc_first_orport || true)
  report=$(umask 077 && mktemp /tmp/tor-relay-report.XXXXXX.txt)

  {
    printf 'Tor Relay Operator Report\n'
    printf 'Generated: %s UTC\n\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
    printf 'System: %s (%s, %s)\n' "$OS_PRETTY_NAME" "$OS_CODENAME" "$ARCHITECTURE"
    printf 'Service: %s\n' "$TOR_SERVICE"
    printf 'Fingerprint: %s\n' "${local_fp:-unavailable}"
    printf 'ORPort: %s\n' "${current_orport:-unavailable}"
    printf '\nTor version:\n'
    tor --version 2> /dev/null || true
    printf '\nService status:\n'
    systemctl is-active "$TOR_SERVICE" 2> /dev/null || true
    printf '\nConfigured relay directives:\n'
    if torrc_exists; then
      awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $1 ~ /^(Nickname|ContactInfo|ORPort|ExitRelay|ReducedExitPolicy|IPv6Exit|SocksPort|RelayBandwidthRate|RelayBandwidthBurst|AccountingMax|AccountingRule|FamilyId|MyFamily|SafeLogging|Sandbox|MetricsPort|MetricsPortPolicy)$/ {
          print
        }
      ' "$TORRC_PATH"
    fi
    printf '\nRecent Tor warnings/errors:\n'
    journalctl -u "$TOR_SERVICE" -n 120 --no-pager 2> /dev/null | grep -Ei 'warn|error|failed|reachable' || true
  } > "$report"

  success "Wrote ${report}"
  warn "Review before sharing; ContactInfo and relay fingerprint are public, but logs can still contain local operational context."
}

run_relay_health_check() {
  local current_orport
  local local_fp

  section "Relay Health Check"

  local version
  if version=$(tor_installed_version); then
    if version_at_least "$version" "$MIN_TOR_VERSION"; then
      success "tor ${version} is a supported release series."
    else
      warn "tor ${version} is older than ${MIN_TOR_VERSION}; the directory authorities reject it. Use Packages and tools > Update Tor."
    fi
  else
    warn "Could not read the installed tor version."
  fi

  if torrc_exists; then
    success "Found ${TORRC_PATH}."
  else
    warn "${TORRC_PATH} does not exist."
  fi

  if local_fp=$(local_relay_fingerprint); then
    success "Local relay fingerprint: ${local_fp}"
  else
    warn "Local relay fingerprint is not readable yet. New relays may need Tor to start once."
  fi

  if tor_service_active; then
    success "${TOR_SERVICE} is active."
  else
    warn "${TOR_SERVICE} is not active."
  fi

  if ! verify_tor_config; then
    warn "Tor configuration syntax check failed."
  fi

  current_orport=$(read_torrc_first_orport || true)
  OR_PORT=${current_orport:-$OR_PORT}
  if [[ -n "$current_orport" ]]; then
    success "Configured ORPort: ${OR_PORT}"
    if command_exists ss; then
      if ss -H -ltn | awk '{ print $4 }' | grep -Eq "(^|:|\\])${OR_PORT}$"; then
        success "A TCP listener is present on ${OR_PORT}."
      else
        warn "No TCP listener was found on ${OR_PORT}."
      fi
    else
      warn "ss command not found; skipped listener check."
    fi
  else
    warn "No ORPort was found in ${TORRC_PATH}."
  fi

  check_tor_orport_self_test "1 hour ago" 0

  local id
  local -a family_ids=()
  mapfile -t family_ids < <(torrc_family_ids)
  for id in "${family_ids[@]}"; do
    if family_key_installed_for_id "$id"; then
      success "FamilyId ${id}: key installed."
    else
      warn "FamilyId ${id}: no matching key in $(tor_family_key_directory). Import it via Relay family."
    fi
  done
  if ((${#family_ids[@]} == 0)) && [[ -n "$(torrc_myfamily_fingerprints)" ]]; then
    warn "Only a legacy MyFamily list is configured. Tor 0.4.9 families use FamilyId keys; see Relay family."
  fi
  if [[ -n "$(torrc_myfamily_fingerprints)" ]]; then
    show_myfamily_status
  fi
}

repair_menu() {
  local choice
  local current_orport

  while true; do
    section "Repair Tools"
    choose_menu choice "Choose a repair action" "6" \
      "1" "Verify torrc syntax" "Run tor --verify-config" \
      "2" "Restart Tor" "Enable/restart ${TOR_SERVICE} and verify" \
      "3" "Show recent Tor logs" "Last 80 journal lines" \
      "4" "Check ORPort self-test" "Inspect recent reachability logs" \
      "5" "Configure or repair firewall" "UFW/firewalld/nftables path" \
      "6" "Back" "Return to existing relay tools"

    case "$choice" in
      1)
        if ! verify_tor_config; then
          warn "Tor configuration syntax check failed."
        fi
        ;;
      2)
        current_orport=$(read_torrc_first_orport || true)
        OR_PORT=${current_orport:-$OR_PORT}
        restart_and_verify_tor
        ;;
      3)
        if command_exists journalctl; then
          capture_command_panel "Recent Tor logs" journalctl -u "$TOR_SERVICE" -n 80 --no-pager || true
        else
          warn "journalctl is not available."
        fi
        ;;
      4)
        check_tor_orport_self_test "1 hour ago" 0
        ;;
      5)
        current_orport=$(read_torrc_first_orport || true)
        OR_PORT=${current_orport:-$OR_PORT}
        collect_firewall_options
        if ((ENABLE_FIREWALL)); then
          configure_firewall
        fi
        ;;
      6 | "")
        return 0
        ;;
    esac
  done
}

existing_relay_menu() {
  local choice

  existing_tor_relay_detected || return 1

  while true; do
    section "Relay Operator Console"
    info "An existing Tor relay configuration or active Tor service was detected."
    choose_menu choice "What would you like to do?" "1" \
      "1" "Relay family" "FamilyId keys: create, import, share; legacy MyFamily" \
      "2" "Run relay health check" "Version, service, config, ORPort, family" \
      "3" "Directory status" "Fetch published relay status from Tor Metrics" \
      "4" "Service controls" "Start, reload, restart, stop, enable, disable" \
      "5" "Logs and signals" "Recent logs, follow logs, ORPort self-test" \
      "6" "Configuration editor" "Common safe torrc changes" \
      "7" "Backups" "torrc and identity-key backup/restore tools" \
      "8" "Packages and tools" "Tor repo, updates, Nyx, fzf" \
      "9" "Repair tools" "Config, restart, logs, firewall" \
      "l" "Command logs" "View command output captured in this run" \
      "o" "Operator report" "Write a local troubleshooting report under /tmp" \
      "c" "Clean script traces" "Remove this installer/repo traces, not Tor" \
      "r" "Run full guided setup again" "Reconfigure this relay" \
      "x" "Exit" "Make no changes"

    case "$choice" in
      1)
        manage_relay_family
        ;;
      2)
        run_relay_health_check
        ;;
      3)
        show_relay_directory_status
        ;;
      4)
        service_control_menu
        ;;
      5)
        logs_menu
        ;;
      6)
        configure_common_torrc_menu
        ;;
      7)
        backups_menu
        ;;
      8)
        package_tools_menu
        ;;
      9)
        repair_menu
        ;;
      l)
        command_logs_menu
        ;;
      o)
        operator_report
        ;;
      c)
        cleanup_script_traces
        ;;
      r)
        return 1
        ;;
      x | "")
        exit 0
        ;;
    esac
  done
}

show_summary_body() {
  local torrc_preview="$TMP_DIR/torrc.preview"
  build_torrc "$torrc_preview"

  section "Review Before Applying"
  printf '%bTarget%b: %s (%s, %s)\n' "$BOLD" "$RESET" "$OS_PRETTY_NAME" "$OS_CODENAME" "$ARCHITECTURE"
  if ((CHANGE_HOSTNAME)); then
    printf '%bSystem hostname%b: %s -> %s\n' "$BOLD" "$RESET" "$CURRENT_HOSTNAME" "$NEW_HOSTNAME"
  else
    printf '%bSystem hostname%b: unchanged (%s)\n' "$BOLD" "$RESET" "$CURRENT_HOSTNAME"
  fi
  if [[ "$RELAY_MODE" == "exit" ]]; then
    printf '%bRelay mode%b: Exit\n' "$BOLD" "$RESET"
    printf '%bExit policy%b: %s\n' "$BOLD" "$RESET" "$EXIT_POLICY_MODE"
    printf '%bIPv6 exit traffic%b: %s\n' "$BOLD" "$RESET" "$([[ $EXIT_ALLOW_IPV6 -eq 1 ]] && printf yes || printf no)"
    printf '%bLocal Unbound resolver%b: %s\n' "$BOLD" "$RESET" "$([[ $CONFIGURE_UNBOUND -eq 1 ]] && printf yes || printf no)"
    if ((CONFIGURE_UNBOUND)); then
      printf '%bLock %s%b: %s\n' "$BOLD" "$RESOLV_CONF_PATH" "$RESET" "$([[ $LOCK_RESOLV_CONF -eq 1 ]] && printf yes || printf no)"
    fi
  else
    printf '%bRelay mode%b: Guard / middle\n' "$BOLD" "$RESET"
  fi
  printf '%bRelay%b: %s on ORPort %s\n' "$BOLD" "$RESET" "$RELAY_NICKNAME" "$OR_PORT"
  printf '%bContactInfo%b: %s\n' "$BOLD" "$RESET" "$CONTACT_INFO"
  if ((ENABLE_IPV6)); then
    printf '%bIPv6 ORPort%b: [%s]:%s\n' "$BOLD" "$RESET" "$IPV6_ADDRESS" "$OR_PORT"
    if ((IPV6_MANUAL_OVERRIDE)); then
      printf '%bIPv6 verification%b: manual override; post-start status will be reported as unverified until Tor confirms reachability\n' "$BOLD" "$RESET"
    fi
  else
    printf '%bIPv6 ORPort%b: disabled\n' "$BOLD" "$RESET"
  fi
  case "$FAMILY_MODE" in
    generate) printf '%bRelay family%b: new family key "%s" (FamilyId generated during apply)\n' "$BOLD" "$RESET" "$FAMILY_KEY_NAME" ;;
    import) printf '%bRelay family%b: import "%s", FamilyId %s\n' "$BOLD" "$RESET" "$FAMILY_KEY_NAME" "$FAMILY_ID" ;;
    *) printf '%bRelay family%b: none (single relay)\n' "$BOLD" "$RESET" ;;
  esac
  if ((INITIAL_MYFAMILY_AFTER_SETUP)); then
    printf '%bLegacy MyFamily editor%b: opens after setup\n' "$BOLD" "$RESET"
  fi
  if ((CONFIGURE_RELAY_BANDWIDTH)); then
    printf '%bBandwidth%b: %s %s/s average, %s %s/s burst\n' "$BOLD" "$RESET" "$RELAY_BANDWIDTH_RATE_VALUE" "$RELAY_BANDWIDTH_RATE_UNIT" "$RELAY_BANDWIDTH_BURST_VALUE" "$RELAY_BANDWIDTH_BURST_UNIT"
    if [[ "$BANDWIDTH_MODE" == "steady" ]]; then
      printf '%bEstimated average%b: ~%s Mbit/s, based on %s usable GBytes/month per relay direction\n' "$BOLD" "$RESET" "$(format_mbits_from_kbytes "$RELAY_BANDWIDTH_RATE_VALUE")" "$STEADY_PER_DIRECTION_GBYTES"
    fi
  else
    printf '%bBandwidth%b: no relay-specific cap\n' "$BOLD" "$RESET"
  fi
  if ((CONFIGURE_ACCOUNTING)); then
    printf '%bAccountingMax%b: %s GBytes, monthly reset, AccountingRule %s\n' "$BOLD" "$RESET" "$ACCOUNTING_MAX_GBYTES" "$ACCOUNTING_RULE"
    if [[ "$BANDWIDTH_MODE" == "steady" || "$BANDWIDTH_MODE" == "accounting" ]]; then
      printf '%bTraffic budget%b: %s raw, %s%% headroom\n' "$BOLD" "$RESET" "$MONTHLY_TRAFFIC_INPUT" "$MONTHLY_TRAFFIC_HEADROOM_PERCENT"
    fi
  else
    printf '%bAccountingMax%b: not configured\n' "$BOLD" "$RESET"
  fi
  printf '%bAutomatic updates%b: %s\n' "$BOLD" "$RESET" "$([[ $ENABLE_AUTO_UPDATES -eq 1 ]] && printf yes || printf no)"
  printf '%bInstall Nyx%b: %s\n' "$BOLD" "$RESET" "$([[ $INSTALL_NYX -eq 1 ]] && printf yes || printf no)"
  if tui_available; then
    printf '%bfzf interface%b: active\n' "$BOLD" "$RESET"
  elif ((PLAIN_TUI)) && command_exists fzf; then
    printf '%bfzf interface%b: installed, disabled by --plain\n' "$BOLD" "$RESET"
  elif command_exists fzf; then
    printf '%bfzf interface%b: installed, unavailable without a readable terminal\n' "$BOLD" "$RESET"
  else
    printf '%bfzf interface%b: not installed; plain line mode\n' "$BOLD" "$RESET"
  fi
  printf '%bFirewall change%b: %s (%s)\n' "$BOLD" "$RESET" "$([[ $ENABLE_FIREWALL -eq 1 ]] && printf yes || printf no)" "$FIREWALL_KIND"
  if ((INSTALL_UFW)); then
    printf '%bInstall UFW%b: yes\n' "$BOLD" "$RESET"
  fi
  if ((ENABLE_UFW_AFTER_RULES)); then
    printf '%bEnable UFW%b: yes, after allowing SSH TCP %s and ORPort TCP %s\n' "$BOLD" "$RESET" "$SSH_PORTS_FOR_UFW" "$OR_PORT"
  fi
  printf '%bTor Sandbox%b: %s\n' "$BOLD" "$RESET" "$([[ $ENABLE_TOR_SANDBOX -eq 1 ]] && printf yes || printf no)"
  printf '%bMetricsPort%b: %s\n' "$BOLD" "$RESET" "$([[ $CONFIGURE_METRICS_PORT -eq 1 ]] && printf '%s (local only)' "$METRICS_PORT_ADDRESS" || printf no)"

  printf '\n%s\n' "torrc preview:"
  while IFS= read -r line; do
    printf '    %s\n' "$line"
  done < "$torrc_preview"

  printf '\n%s\n' "Planned privileged changes:"
  if ((CHANGE_HOSTNAME)); then
    printf '  - Set the system hostname to %s and update /etc/hosts.\n' "$NEW_HOSTNAME"
  fi
  printf '  - Configure the official Tor Project apt repository for %s.\n' "$OS_CODENAME"
  printf '  - Install tor from apt.\n'
  printf '  - Install deb.torproject.org-keyring if apt publishes it for %s.\n' "$OS_CODENAME"
  if ((INSTALL_NYX)); then
    printf '  - Install nyx for terminal relay monitoring.\n'
  fi
  if [[ "$RELAY_MODE" == "exit" && "$CONFIGURE_UNBOUND" -eq 1 ]]; then
    printf '  - Install Unbound and switch %s to the local resolver.\n' "$RESOLV_CONF_PATH"
    if ((LOCK_RESOLV_CONF)); then
      printf '  - Lock %s with chattr +i.\n' "$RESOLV_CONF_PATH"
    fi
  fi
  case "$FAMILY_MODE" in
    generate) printf '  - Generate a family key with tor --keygen-family and install it in the Tor key directory.\n' ;;
    import) printf '  - Install family key %s in the Tor key directory.\n' "$FAMILY_IMPORT_KEY_PATH" ;;
    *) ;;
  esac
  printf '  - Back up and update %s.\n' "$TORRC_PATH"
  if ((ENABLE_AUTO_UPDATES)); then
    printf '  - Configure unattended upgrades for security and Tor packages.\n'
  fi
  if ((ENABLE_FIREWALL)); then
    if ((INSTALL_UFW)); then
      printf '  - Install ufw.\n'
    fi
    if [[ "$FIREWALL_KIND" == "ufw" ]]; then
      printf '  - Allow SSH TCP %s and Tor ORPort TCP %s using ufw.\n' "$SSH_PORTS_FOR_UFW" "$OR_PORT"
      if ((ENABLE_UFW_AFTER_RULES)); then
        printf '  - Enable ufw after SSH and ORPort rules are present.\n'
      fi
    else
      printf '  - Add a TCP %s allow rule using %s.\n' "$OR_PORT" "$FIREWALL_KIND"
    fi
  fi
  printf '  - Enable and restart %s.\n' "$TOR_SERVICE"
}

show_summary() {
  local summary_file

  if tui_available; then
    summary_file=$(mktemp_in_workspace)
    show_summary_body > "$summary_file" 2>&1
    show_file_panel "Review Before Applying" "$summary_file"
  else
    show_summary_body
  fi
}

confirm_apply() {
  printf '\n'
  if ! ask_yes_no "Apply these changes now?" "no"; then
    die "Aborted before making changes."
  fi
}

install_repository_prerequisites() {
  run_cmd "Updating apt package lists" env DEBIAN_FRONTEND=noninteractive apt-get update
  run_cmd "Installing apt repository prerequisites" \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates gnupg wget
}

configure_tor_repository() {
  local source_file="$TMP_DIR/tor.sources"
  local ascii_key="$TMP_DIR/torproject.asc"
  local binary_key="$TMP_DIR/deb.torproject.org-keyring.gpg"

  check_tor_project_suite required
  build_tor_sources "$source_file"

  if ((DRY_RUN)); then
    info "Would fetch and install the Tor Project package signing key"
    print_command wget -qO- "${TOR_APT_BASE_URL}/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc"
    print_command gpg --dearmor --output "$TOR_KEYRING_PATH"
  else
    run_cmd "Fetching Tor Project package signing key" \
      wget -qO "$ascii_key" "${TOR_APT_BASE_URL}/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc"
    verify_tor_signing_key_file "$ascii_key"
    run_cmd "Building Tor Project apt keyring" gpg --dearmor --yes --output "$binary_key" "$ascii_key"
  fi

  install_file_if_changed "$binary_key" "$TOR_KEYRING_PATH" "0644"
  install_file_if_changed "$source_file" "$TOR_SOURCES_PATH" "0644"

  if [[ -e /etc/apt/sources.list.d/tor.list ]]; then
    warn "Existing /etc/apt/sources.list.d/tor.list was found. Review it later to avoid duplicate Tor repositories."
  fi
}

install_tor_package() {
  run_cmd "Updating apt package lists" env DEBIAN_FRONTEND=noninteractive apt-get update

  if ((DRY_RUN)); then
    info "Would verify apt candidate for tor comes from ${TOR_APT_BASE_URL}."
    info "Would install tor and deb.torproject.org-keyring when available."
    return 0
  fi

  if ! apt_package_available tor; then
    die "The tor package is not available from apt after adding the Tor Project repository."
  fi

  if ! tor_candidate_from_tor_project; then
    die "The selected apt candidate for tor does not appear to come from ${TOR_APT_BASE_URL}. Check apt-cache policy tor before continuing."
  fi

  run_cmd "Installing Tor from apt" env DEBIAN_FRONTEND=noninteractive apt-get install -y tor

  if apt_package_available deb.torproject.org-keyring; then
    run_cmd "Installing Tor Project keyring package" \
      env DEBIAN_FRONTEND=noninteractive apt-get install -y deb.torproject.org-keyring
  else
    warn "deb.torproject.org-keyring is not available for '${OS_CODENAME}' yet."
    warn "Continuing because the Tor Project signing key was already installed at ${TOR_KEYRING_PATH}."
  fi

  require_supported_tor_version
}

# Print the installed tor version, e.g. 0.4.9.13 (from "Tor version 0.4.9.13.").
tor_installed_version() {
  command_exists tor || return 1
  tor --version 2> /dev/null | awk 'NR == 1 && $1 == "Tor" && $2 == "version" { v = $3; sub(/\.$/, "", v); print v; found = 1 } END { exit found ? 0 : 1 }'
}

# version_at_least CURRENT MINIMUM
version_at_least() {
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

require_supported_tor_version() {
  local version

  version=$(tor_installed_version) || die "Could not read the installed tor version."
  if ! version_at_least "$version" "$MIN_TOR_VERSION"; then
    die "tor ${version} is installed, but the Tor network rejects relays older than ${MIN_TOR_VERSION}. Check apt-cache policy tor."
  fi
  success "tor ${version} meets the ${MIN_TOR_VERSION} minimum."
}

# Warn about hosts below the Tor Project's documented relay RAM minimums
# (https://community.torproject.org/relay/relays-requirements/).
check_relay_resources() {
  local mem_kib
  local min_mib=512

  [[ "$RELAY_MODE" == "exit" ]] && min_mib=1536
  mem_kib=$(awk '$1 == "MemTotal:" { print $2; exit }' /proc/meminfo 2> /dev/null || true)
  [[ "$mem_kib" =~ ^[0-9]+$ ]] || return 0

  if ((mem_kib / 1024 < min_mib)); then
    warn "This server has $((mem_kib / 1024)) MiB RAM; Tor recommends at least ${min_mib} MiB for this relay type."
  else
    success "Memory: $((mem_kib / 1024)) MiB (recommended minimum ${min_mib} MiB)."
  fi
}

install_nyx_package() {
  ((INSTALL_NYX)) || return 0

  run_cmd "Installing Nyx relay monitor" env DEBIAN_FRONTEND=noninteractive apt-get install -y nyx
}

install_fzf_package() {
  local fzf_was_installed=0

  ((INSTALL_FZF)) || return 0
  if apt_package_installed fzf; then
    fzf_was_installed=1
  fi

  run_cmd "Installing fzf searchable selector" env DEBIAN_FRONTEND=noninteractive apt-get install -y fzf
  if ((DRY_RUN)); then
    info "Would record that this script installed fzf."
  elif command_exists fzf && ((fzf_was_installed == 0)); then
    mark_script_installed_fzf
    if ! ((PLAIN_TUI)); then
      USE_FZF=1
    fi
  elif command_exists fzf; then
    success "fzf is installed; not marking it as script-installed because it was already present."
  fi
}

configure_exit_dns() {
  local resolv_file="$TMP_DIR/resolv.conf"
  local resolv_backup=""

  [[ "$RELAY_MODE" == "exit" && "$CONFIGURE_UNBOUND" -eq 1 ]] || return 0

  build_resolv_conf "$resolv_file"

  if command_exists lsattr && lsattr -d "$RESOLV_CONF_PATH" 2> /dev/null | awk '{ print $1 }' | grep -q 'i'; then
    die "${RESOLV_CONF_PATH} is immutable. Unlock it first with: chattr -i ${RESOLV_CONF_PATH}"
  fi

  if [[ -L "$RESOLV_CONF_PATH" ]] && command_exists systemctl && systemctl is-active --quiet systemd-resolved 2> /dev/null; then
    warn "${RESOLV_CONF_PATH} is managed through a symlink while systemd-resolved is active."
    warn "This script will replace it only because exit relay DNS needs a local caching resolver."
  fi

  run_cmd "Installing Unbound local resolver" env DEBIAN_FRONTEND=noninteractive apt-get install -y unbound
  if command_exists unbound-checkconf; then
    run_cmd "Checking Unbound configuration" unbound-checkconf
  fi
  run_cmd "Enabling and starting Unbound" systemctl enable --now unbound

  if ((DRY_RUN)); then
    info "Would verify Unbound service state and switch ${RESOLV_CONF_PATH} to nameserver 127.0.0.1"
    return 0
  fi

  if systemctl is-active --quiet unbound; then
    success "Unbound is active."
  else
    die "Unbound is not active. Check: journalctl -u unbound -n 100 --no-pager"
  fi

  install_file_if_changed "$resolv_file" "$RESOLV_CONF_PATH" "0644"
  resolv_backup=$LAST_BACKUP_PATH
  success "Configured ${RESOLV_CONF_PATH} to use local Unbound."

  if getent hosts deb.torproject.org > /dev/null 2>&1; then
    success "DNS resolution works through local resolver."
  else
    warn "DNS resolution failed after switching to local Unbound."
    if [[ -n "$resolv_backup" && (-e "$resolv_backup" || -L "$resolv_backup") ]]; then
      rm -f -- "$RESOLV_CONF_PATH"
      cp -a -- "$resolv_backup" "$RESOLV_CONF_PATH"
      warn "Restored ${RESOLV_CONF_PATH} from ${resolv_backup}."
    fi
    die "Fix Unbound/DNS before running an exit relay."
  fi

  if ((LOCK_RESOLV_CONF)); then
    if command_exists chattr; then
      run_cmd "Locking ${RESOLV_CONF_PATH} with chattr +i" chattr +i "$RESOLV_CONF_PATH"
    else
      warn "chattr is not available; ${RESOLV_CONF_PATH} was not locked."
    fi
  fi
}

configure_unattended_upgrades() {
  local unattended_file="$TMP_DIR/52tor-relay-unattended-upgrades"
  local auto_file="$TMP_DIR/20auto-upgrades"

  build_unattended_tor_config "$unattended_file"
  build_auto_upgrades_config "$auto_file"

  run_cmd "Installing unattended-upgrades packages" \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades apt-listchanges

  install_file_if_changed "$unattended_file" "$UNATTENDED_TOR_PATH" "0644"
  install_file_if_changed "$auto_file" "$AUTO_UPGRADES_PATH" "0644"
}

configure_torrc() {
  local torrc_file="$TMP_DIR/torrc"
  build_torrc "$torrc_file"
  verify_tor_config_file "$torrc_file"
  install_file_if_changed "$torrc_file" "$TORRC_PATH" "0644"
}

configure_hostname() {
  local hosts_file="$TMP_DIR/hosts"

  ((CHANGE_HOSTNAME)) || return 0

  build_hosts_file "$hosts_file"
  backup_file /etc/hostname
  run_cmd "Setting system hostname to ${NEW_HOSTNAME}" hostnamectl set-hostname "$NEW_HOSTNAME"
  install_file_if_changed "$hosts_file" /etc/hosts "0644"
  success "System hostname configured. New SSH sessions should show ${NEW_HOSTNAME}."
}

nft_rule_exists() {
  nft list chain inet filter input 2> /dev/null | grep -Fq "Tor relay ORPort ${OR_PORT}"
}

configure_ufw_firewall() {
  local ssh_port

  if ((INSTALL_UFW)); then
    run_cmd "Updating apt package lists before installing UFW" env DEBIAN_FRONTEND=noninteractive apt-get update
    run_cmd "Installing UFW" env DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
  fi

  ((DRY_RUN)) || command_exists ufw || die "ufw is not installed."

  if [[ "$FIREWALL_STATE" != "active" ]]; then
    for ssh_port in $SSH_PORTS_FOR_UFW; do
      run_cmd "Allowing SSH TCP ${ssh_port} through UFW" ufw allow "${ssh_port}/tcp" comment "SSH"
    done
  fi
  run_cmd "Allowing TCP ${OR_PORT} through UFW" ufw allow "${OR_PORT}/tcp" comment "Tor relay ORPort"

  if ((ENABLE_UFW_AFTER_RULES)); then
    run_cmd "Enabling UFW" ufw --force enable
  elif [[ "$FIREWALL_STATE" != "active" ]]; then
    warn "UFW rules were added, but UFW is inactive."
  fi
}

configure_firewall() {
  ((ENABLE_FIREWALL)) || return 0

  case "$FIREWALL_KIND" in
    ufw)
      configure_ufw_firewall
      ;;
    firewalld)
      if [[ "$FIREWALL_STATE" != "active" ]]; then
        warn "firewalld is inactive. Skipping firewall change."
        return 0
      fi
      run_cmd "Allowing TCP ${OR_PORT} through firewalld" firewall-cmd --permanent --add-port="${OR_PORT}/tcp"
      run_cmd "Reloading firewalld" firewall-cmd --reload
      ;;
    nftables)
      if ! nft list chain inet filter input > /dev/null 2>&1; then
        warn "nftables chain inet filter input is not available. Skipping firewall change."
        return 0
      fi
      if ((DRY_RUN)); then
        info "Would add nftables allow rule for TCP ${OR_PORT}"
        print_command nft add rule inet filter input tcp dport "$OR_PORT" accept comment "Tor relay ORPort ${OR_PORT}"
      elif nft_rule_exists; then
        success "nftables rule already present for TCP ${OR_PORT}"
      else
        run_cmd "Allowing TCP ${OR_PORT} through nftables" \
          nft add rule inet filter input tcp dport "$OR_PORT" accept comment "Tor relay ORPort ${OR_PORT}"
      fi
      ;;
    *)
      warn "No supported firewall manager selected. Skipping firewall change."
      ;;
  esac
}

verify_tor_config_file() {
  local config_file=$1

  if command_exists tor; then
    # Mirror the ExecStartPre check of Debian's tor@default.service so the
    # candidate is validated with the same defaults (User, DataDirectory, ...).
    if [[ -r "$TOR_SERVICE_DEFAULTS_TORRC" ]]; then
      run_cmd "Verifying Tor configuration" \
        tor --defaults-torrc "$TOR_SERVICE_DEFAULTS_TORRC" -f "$config_file" --RunAsDaemon 0 --verify-config
    else
      run_cmd "Verifying Tor configuration" tor -f "$config_file" --verify-config
    fi
  elif ((DRY_RUN)); then
    info "Would verify the torrc with tor --verify-config once tor is installed."
  else
    warn "tor command not found yet; cannot verify torrc syntax."
  fi
}

verify_tor_config() {
  verify_tor_config_file "$TORRC_PATH"
}

# Tor 0.4.5+ includes the tested address in these notices, for example
# "Self-testing indicates your ORPort 203.0.113.5:9001 is reachable from the
# outside. Excellent." (src/feature/relay/selftest.c). Older releases omitted
# the address, so both shapes are accepted. Pass "ipv6" to match only the
# bracketed IPv6 ORPort notice.
orport_self_test_succeeded() {
  local family=${1:-any}
  local address_pattern='([^ ]+ )?'

  if [[ "$family" == "ipv6" ]]; then
    address_pattern='\[[0-9A-Fa-f:.]+\]:[0-9]+ '
  fi
  grep -Eq "Self-testing indicates your ORPort ${address_pattern}is reachable from the outside\\. Excellent\\."
}

# Current wording lives in src/feature/relay/relay_periodic.c; the older
# "confirm that its ORPort is reachable" wording is kept for old relays.
orport_self_test_failed() {
  grep -Eq "Your server has not managed to confirm (reachability for its ORPort|that its ORPort is reachable)"
}

check_tor_orport_self_test() {
  local deadline
  local log_output
  local since_time
  local wait_seconds
  local require_success

  since_time=${1:-"5 minutes ago"}
  wait_seconds=${2:-90}
  require_success=${3:-0}

  command_exists journalctl || {
    warn "journalctl not found; skipped Tor ORPort self-test log check."
    return "$require_success"
  }

  if ((wait_seconds > 0)); then
    info "Checking Tor ORPort reachability self-test logs for up to ${wait_seconds} seconds."
  else
    info "Checking recent Tor ORPort reachability self-test logs."
  fi
  deadline=$((SECONDS + wait_seconds))

  while true; do
    log_output=$(journalctl -u "$TOR_SERVICE" --since "$since_time" --no-pager 2> /dev/null || true)

    if orport_self_test_succeeded <<< "$log_output"; then
      success "Tor reports the ORPort is reachable from outside."
      if orport_self_test_succeeded ipv6 <<< "$log_output"; then
        success "Tor also reports the IPv6 ORPort is reachable from outside."
      fi
      return 0
    fi

    if orport_self_test_failed <<< "$log_output"; then
      warn "Tor has not confirmed external ORPort reachability yet."
      warn "Check local/cloud firewall rules for TCP ${OR_PORT}, then watch: journalctl -u ${TOR_SERVICE} -f"
      return "$require_success"
    fi

    ((wait_seconds > 0 && SECONDS < deadline)) || break
    sleep 5
  done

  if ((wait_seconds > 0)); then
    warn "Tor did not report ORPort self-test success within ${wait_seconds} seconds."
    warn "This can take longer. Watch logs with: journalctl -u ${TOR_SERVICE} -f"
  else
    warn "No recent ORPort self-test result was found in the selected log window."
  fi
  return "$require_success"
}

restart_and_verify_tor() {
  local restart_since

  verify_tor_config

  restart_since=$(date '+%Y-%m-%d %H:%M:%S')
  run_cmd "Enabling ${TOR_SERVICE}" systemctl enable "$TOR_SERVICE"
  run_cmd "Restarting ${TOR_SERVICE}" systemctl restart "$TOR_SERVICE"

  if ((DRY_RUN)); then
    info "Would verify ${TOR_SERVICE} status, ORPort listener, and Tor ORPort self-test logs."
    return 0
  fi

  if systemctl is-active --quiet "$TOR_SERVICE"; then
    success "${TOR_SERVICE} is active."
  else
    die "${TOR_SERVICE} is not active. Check: journalctl -u ${TOR_SERVICE} -n 100 --no-pager"
  fi
  check_family_logs "$restart_since"

  if command_exists ss; then
    if ss -H -ltn | awk '{ print $4 }' | grep -Eq "(^|:|\\])${OR_PORT}$"; then
      success "Tor appears to be listening on TCP ${OR_PORT}."
    else
      warn "Could not confirm a listener on TCP ${OR_PORT}. Check firewall/NAT and Tor logs."
    fi
  else
    warn "ss command not found; skipped listener verification."
  fi

  if check_tor_orport_self_test "$restart_since" 90 1; then
    success "Final verification reached Tor's ORPort self-test success signal."
  else
    warn "Setup applied, but Tor's external ORPort reachability is not verified yet."
    warn "This is usually firewall, provider firewall, IPv6, NAT, or descriptor timing. The relay may not be usable until Tor confirms reachability."
  fi

  if ((ENABLE_IPV6)); then
    if command_exists ss; then
      if ss -H -ltn | awk '{ print $4 }' | grep -Fq "[${IPV6_ADDRESS}]:${OR_PORT}"; then
        success "Tor appears to be listening on IPv6 [${IPV6_ADDRESS}]:${OR_PORT}."
      else
        warn "Could not confirm a listener on IPv6 [${IPV6_ADDRESS}]:${OR_PORT}."
      fi
    fi
    if ((IPV6_MANUAL_OVERRIDE)); then
      warn "IPv6 ORPort was kept by manual override. Treat IPv6 as unverified until Relay Search shows the IPv6 OR address."
    fi
  fi
}

apply_changes() {
  section "Applying Changes"
  TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')

  check_apt_capacity
  configure_hostname
  install_repository_prerequisites
  configure_tor_repository
  install_tor_package
  install_nyx_package
  install_fzf_package
  configure_exit_dns

  if ((ENABLE_AUTO_UPDATES)); then
    configure_unattended_upgrades
  fi

  setup_relay_family
  configure_torrc
  configure_firewall
  restart_and_verify_tor
}

print_next_steps() {
  section "Next Steps"

  if ((DRY_RUN)); then
    printf '%s\n' "Dry run complete. Re-run without --dry-run to apply these changes:"
    printf '  sudo ./%s\n' "$SCRIPT_NAME"
    return 0
  fi

  success "Relay setup commands completed."
  printf '\n%s\n' "Useful checks:"
  printf '  systemctl status %s --no-pager\n' "$TOR_SERVICE"
  printf '  journalctl -u %s -f\n' "$TOR_SERVICE"
  printf '  journalctl -u %s --since "1 hour ago" | grep -F "Self-testing indicates"\n' "$TOR_SERVICE"
  printf '  ss -ltn | grep ":%s"\n' "$OR_PORT"
  if ((INSTALL_NYX)); then
    printf '  sudo -u debian-tor nyx\n'
  fi
  if [[ "$RELAY_MODE" == "exit" && "$CONFIGURE_UNBOUND" -eq 1 ]]; then
    printf '  systemctl status unbound --no-pager\n'
    printf '  getent hosts deb.torproject.org\n'
  fi
  if ((CONFIGURE_METRICS_PORT)); then
    printf '  curl -s http://%s/metrics | grep -E "^tor_relay_load"\n' "$METRICS_PORT_ADDRESS"
  fi
  printf '\n%s\n' "Relay Search usually shows a new relay after about 3 hours:"
  printf '  https://metrics.torproject.org/rs.html#search/%s\n' "$RELAY_NICKNAME"
  printf '\n%s\n' "Remember:"
  printf '  - Keep inbound TCP %s open in any VPS provider/cloud firewall.\n' "$OR_PORT"
  printf '  - New relays ramp up gradually; Guard usage can take time and stable uptime.\n'
  if valid_family_id "$FAMILY_ID"; then
    printf '  - FamilyId %s: copy the family key to each of your relays (operator console > Relay family > Share).\n' "$FAMILY_ID"
  else
    printf '  - If you add more relays later, create a family key from the operator console.\n'
  fi
  if [[ -n "$CONTACT_INFO_URL" ]]; then
    printf '  - Publish your FamilyId at https://%s/.well-known/tor-relay/ed25519-family-id.txt for the CIISS url proof.\n' \
      "$(url_domain "$CONTACT_INFO_URL")"
  fi
  printf '  - Back up %s after the relay is running (identity and family keys).\n' "$(tor_family_key_directory)"
  if [[ "$RELAY_MODE" == "exit" ]]; then
    printf '  - Keep provider, reverse DNS/WHOIS, and abuse-contact handling aligned with exit operation.\n'
  fi

  if ((${#BACKUPS_CREATED[@]})); then
    printf '\n%s\n' "Backups created:"
    local backup
    for backup in "${BACKUPS_CREATED[@]}"; do
      printf '  %s\n' "$backup"
    done
  fi
}

main() {
  parse_args "$@"
  TMP_DIR=$(mktemp -d)
  COMMAND_LOG_DIR="${TMP_DIR%/}/command-logs"

  banner
  if ((CLEANUP_MODE)); then
    if ! ((PLAIN_TUI)) && command_exists fzf; then
      USE_FZF=1
    fi
    acquire_run_lock
    cleanup_script_traces
    exit 0
  fi
  require_supported_system
  acquire_run_lock
  bootstrap_tui
  if existing_relay_menu; then
    exit 0
  fi
  collect_system_hostname
  collect_relay_mode
  collect_relay_identity
  collect_ipv6
  collect_exit_options
  collect_relay_family
  collect_bandwidth
  collect_maintenance_options
  show_summary
  confirm_apply
  apply_changes
  if ((INITIAL_MYFAMILY_AFTER_SETUP)); then
    manage_myfamily
  fi
  print_next_steps
}

if [[ "${TOR_RELAY_SETUP_SOURCE_ONLY:-0}" != "1" ]]; then
  install_traps
  main "$@"
fi
