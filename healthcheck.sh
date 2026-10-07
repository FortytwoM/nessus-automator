#!/bin/bash
# Docker healthcheck: Nessus responds + operator API (if enabled).
# Strict mode (default) requires completed bootstrap and pluginData=true.
# shellcheck shell=bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

check_nessus_alive() {
    local status engine_state plugin_data

    status=$(curl -sf -k --connect-timeout 3 --max-time 15 \
        "${NESSUS_API_BASE}/server/status" 2>/dev/null) || return 1

    if [ "${NESSUS_HEALTH_STRICT:-1}" = "1" ]; then
        [ -f "${NESSUS_BOOTSTRAP_READY_FILE:-/tmp/nessus_bootstrap_ready}" ] || return 1
        engine_state=$(printf '%s' "$status" \
            | /usr/local/bin/nessus-status.py --field engine_status 2>/dev/null) || return 1
        plugin_data=$(printf '%s' "$status" \
            | /usr/local/bin/nessus-status.py --field plugin_data 2>/dev/null) || return 1
        [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]
    fi
}

check_operator_api() {
    local port="${NESSUS_MANAGE_PORT:-8080}"

    if [ "${NESSUS_MANAGE_API:-1}" != "1" ]; then
        return 0
    fi

    curl -sf --connect-timeout 3 --max-time 10 \
        "http://127.0.0.1:${port}/manage/v1/health" >/dev/null 2>&1
}

check_nessus_alive && check_operator_api
