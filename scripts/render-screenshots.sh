#!/usr/bin/env bash
# Re-render the README screenshots from a scripted --dry-run --plain session.
#
# systemctl, hostnamectl, and ufw are stubbed so the prompts (and therefore
# docs/assets/screenshot-answers.txt) are the same on every machine.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ANSWERS="${ROOT_DIR}/docs/assets/screenshot-answers.txt"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

printf '#!/bin/sh\nexit 3\n' > "${work_dir}/systemctl"
printf '#!/bin/sh\necho relay-01\n' > "${work_dir}/hostnamectl"
printf '#!/bin/sh\necho "Status: inactive"\n' > "${work_dir}/ufw"
chmod +x "${work_dir}/systemctl" "${work_dir}/hostnamectl" "${work_dir}/ufw"

PATH="${work_dir}:${PATH}" NO_COLOR=1 "${ROOT_DIR}/setup-tor-guard-relay.sh" --dry-run --plain \
  < "$ANSWERS" > "${work_dir}/transcript.txt" 2>&1

python3 "${ROOT_DIR}/scripts/render-readme-screenshots.py" "${work_dir}/transcript.txt" \
  --answers "$ANSWERS" --out-dir "${ROOT_DIR}/docs/assets"
printf 'Rendered docs/assets/tor-relay-setup-first-run.svg and tor-relay-setup-review.svg\n'
