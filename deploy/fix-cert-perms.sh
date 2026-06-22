#!/usr/bin/env sh
# Normalize scanner mTLS certificate ownership so the unprivileged containers can
# read their private keys.
#
# Usage: deploy/fix-cert-perms.sh [cert-dir]   (default: deploy/scanner-certs)
#
# Why this is needed (Linux only): the `app` and `scanner-agent` services run with
# `cap_drop: ALL` (the agent keeps only NET_RAW). Dropping every capability removes
# CAP_DAC_OVERRIDE, so the in-container root can no longer bypass file-permission
# bits. A bind mount preserves the operator's ownership, so the 0600 private keys
# are unreadable to the containers: the agent crashes on boot with
#   read server key ... open /certs/agent.key: permission denied
# and the app logs "scanner dispatch disabled". macOS / Docker Desktop hides this
# because its file-sharing layer does not enforce the bits. See ADR 0025 and
# docs/SCANNER_AGENT.md ("Certificate file ownership on Linux").
#
# The fix is to give each private key to the uid that reads it, still mode 0600:
#   agent.key -> root (0:0)   the agent container runs as root (for nmap + NET_RAW)
#   app.key   -> 100:101      the app container's pinned `lightipam` user (Dockerfile)
# Public certs (*.crt) stay 0644 and are already readable by both.
#
# This runs automatically as the one-shot `cert-perms` service in compose.yaml on
# every `docker compose up`, so it self-heals after a cert regeneration too. It can
# also be run by hand; outside a container it self-elevates with sudo.
set -eu

CERT_DIR="${1:-$(dirname -- "$0")/scanner-certs}"
# Keep these in sync with the `lightipam` user pinned in the app Dockerfile.
APP_UID="${APP_CERT_UID:-100}"
APP_GID="${APP_CERT_GID:-101}"

priv() { # run a privileged command directly when root, else via sudo
	if [ "$(id -u)" = "0" ]; then
		"$@"
	else
		sudo "$@"
	fi
}

own() { # own <filename> <owner>   — no-op when the file is absent
	f="$CERT_DIR/$1"
	[ -e "$f" ] || return 0
	priv chown "$2" "$f"
	priv chmod 600 "$f"
}

own agent.key "0:0"
own app.key "${APP_UID}:${APP_GID}"

echo "cert-perms: normalized ownership in ${CERT_DIR} (agent.key=root, app.key=${APP_UID}:${APP_GID})"
