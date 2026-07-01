#!/bin/bash
# Starts the operator API (Python, internal port 8080 → gateway /manage/v1/*).

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [operator] $*"
}

if [ "${NESSUS_MANAGE_API:-1}" != "1" ]; then
    log "Operator API disabled (NESSUS_MANAGE_API=0)"
    exit 0
fi

bind="${NESSUS_MANAGE_BIND:-0.0.0.0}"
port="${NESSUS_MANAGE_PORT:-8080}"

log "Starting operator API on ${bind}:${port} (/manage/v1/)"
exec python3 /usr/local/bin/manage-api.py
