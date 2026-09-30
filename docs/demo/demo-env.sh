# shellcheck shell=bash
# Sourced (hidden) at the start of docs/demo/*.tape recordings.
#
# Stubs systemctl, hostnamectl, and ufw so the dry run asks the same questions
# on every machine, puts the pinned fzf from .tools/bin on PATH, and sets a
# short prompt. Nothing here touches the system.

demo_bin=$(mktemp -d)
printf '#!/bin/sh\nexit 3\n' > "${demo_bin}/systemctl"
printf '#!/bin/sh\necho relay-01\n' > "${demo_bin}/hostnamectl"
printf '#!/bin/sh\necho "Status: inactive"\n' > "${demo_bin}/ufw"
chmod +x "${demo_bin}/systemctl" "${demo_bin}/hostnamectl" "${demo_bin}/ufw"

export PATH="${demo_bin}:${PWD}/.tools/bin:${PATH}"
export TERM=xterm-256color
unset NO_COLOR FZF_DEFAULT_OPTS
PS1='\[\e[38;5;141m\]operator@relay-01\[\e[0m\]:\[\e[38;5;81m\]~\[\e[0m\]$ '
clear
