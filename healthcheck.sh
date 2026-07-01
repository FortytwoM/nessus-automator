#!/bin/bash
# Docker healthcheck: Nessus engine ready + operator API (if enabled).
# shellcheck shell=bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

check_nessus_ready() {
    local status engine_state plugin_data

    status=$(curl -sf -k --connect-timeout 3 --max-time 15 \
        https://localhost:8834/server/status 2>/dev/null) || return 1

    engine_state=$(echo "$status" | grep -o '"engine_status":{[^}]*}' \
        | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    plugin_data=$(echo "$status" | sed -n \
        's/.*"pluginData"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -1)

    [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]
}

check_operator_api() {
    local port="${NESSUS_MANAGE_PORT:-8080}"

    if [ "${NESSUS_MANAGE_API:-1}" != "1" ]; then
        return 0
    fi

    curl -sf --connect-timeout 3 --max-time 10 \
        "http://127.0.0.1:${port}/manage/v1/health" >/dev/null 2>&1
}

check_nessus_ready && check_operator_api
