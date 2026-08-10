# Shared Nessus REST helpers (scan-aware updates). Sourced by update.sh and entrypoint.
# shellcheck shell=bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

NESSUS_API_BASE="${NESSUS_API_BASE:-https://127.0.0.1:${NESSUS_BACKEND_PORT:-8835}}"
_NESSUS_CACHED_TOKEN=""
_NESSUS_CACHED_TOKEN_AT=0
_NESSUS_LAST_SCAN_LOG_AT=-999
_NESSUS_LAST_SCAN_COUNT=-1

nessus_api_token_fresh() {
    local user pass response token payload

    nessus_load_api_credentials
    user="${NESSUS_API_USERNAME:-admin}"
    pass="${NESSUS_API_PASSWORD:-admin}"

    command -v jq >/dev/null 2>&1 || return 1
    payload=$(jq -n --arg username "$user" --arg password "$pass" \
        '{username: $username, password: $password}') || return 1

    response=$(curl -s -k --connect-timeout 5 --max-time 15 \
        -X POST "${NESSUS_API_BASE}/session" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null) || return 1

    token=$(echo "$response" | jq -r '.token // empty' 2>/dev/null)

    [ -n "$token" ] && [ "$token" != "null" ] || return 1
    printf '%s' "$token"
}

nessus_api_token() {
    local now token_ttl=300

    now=$(date +%s)
    if [ -n "$_NESSUS_CACHED_TOKEN" ] \
        && [ $((now - _NESSUS_CACHED_TOKEN_AT)) -lt "$token_ttl" ]; then
        printf '%s' "$_NESSUS_CACHED_TOKEN"
        return 0
    fi

    token=$(nessus_api_token_fresh) || return 1
    _NESSUS_CACHED_TOKEN="$token"
    _NESSUS_CACHED_TOKEN_AT=$now
    printf '%s' "$token"
}

nessus_api_invalidate_token() {
    _NESSUS_CACHED_TOKEN=""
    _NESSUS_CACHED_TOKEN_AT=0
}

nessus_api_get_scans_json() {
    local token="$1"
    curl -s -k --connect-timeout 5 --max-time 20 \
        -H "X-Cookie: token=${token}" \
        "${NESSUS_API_BASE}/scans" 2>/dev/null
}

nessus_active_scans_report() {
    local token scans_json

    token=$(nessus_api_token) || return 1
    scans_json=$(nessus_api_get_scans_json "$token") || return 1

    if [ -z "$scans_json" ] || echo "$scans_json" | grep -qi '"error"'; then
        nessus_api_invalidate_token
        token=$(nessus_api_token) || return 1
        scans_json=$(nessus_api_get_scans_json "$token") || return 1
    fi

    [ -n "$scans_json" ] || return 1

    if command -v jq >/dev/null 2>&1; then
        echo "$scans_json" | jq -r --arg statuses "$NESSUS_ACTIVE_SCAN_STATUSES" '
            (.scans // [])[]
            | select(.status as $s | ($statuses | split(" ") | index($s)) != null)
            | "\(.id)\t\(.name // "unnamed")\t\(.status)"
        ' 2>/dev/null
        return 0
    fi

    echo "$scans_json" | tr ',' '\n' | grep -E '"status":"(running|pending|resuming|canceling|pausing|paused|stopping|initializing)"' || true
}

nessus_active_scan_count() {
    local report count

    report=$(nessus_active_scans_report) || return 1
    count=$(printf '%s\n' "$report" | sed '/^$/d' | wc -l)
    printf '%s' "$count"
}

# Scan states that must finish before plugin updates (nessuscli update stops the engine).
NESSUS_ACTIVE_SCAN_STATUSES='running pending resuming canceling pausing paused stopping initializing'

nessus_update_hold_active() {
    [ -f "$NESSUS_UPDATE_HOLD_FILE" ]
}

nessus_update_hold_reason() {
    if [ -f "$NESSUS_UPDATE_HOLD_FILE" ]; then
        head -1 "$NESSUS_UPDATE_HOLD_FILE" 2>/dev/null | tr -d '\r'
    fi
}

nessus_log_scan_wait() {
    local log_fn="$1"
    local scan_count="$2"
    local scan_report="$3"
    local waited="$4"
    local poll="$5"
    local now should_log=0

    now=$(date +%s)
    if [ "$scan_count" != "$_NESSUS_LAST_SCAN_COUNT" ]; then
        should_log=1
    elif [ $((now - _NESSUS_LAST_SCAN_LOG_AT)) -ge 60 ]; then
        should_log=1
    elif [ "$waited" -eq 0 ]; then
        should_log=1
    fi

    [ "$should_log" -eq 1 ] || return 0

    _NESSUS_LAST_SCAN_COUNT="$scan_count"
    _NESSUS_LAST_SCAN_LOG_AT=$now
    $log_fn "Active scans (${scan_count}), polling every ${poll}s..."
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        $log_fn "  scan: $line"
    done <<EOF
$scan_report
EOF
}

# Wait until no active scans and no external hold file.
# Returns: 0 ready, 2 deferred (timeout or fail-fast), 1 on API/auth errors when check is required.
nessus_wait_for_update_clearance() {
    local force="${1:-0}"
    local log_fn="${2:-echo}"
    local max_wait poll grace waited=0
    local hold_reason scan_report scan_count

    if [ "$force" = "1" ] || [ "${NESSUS_UPDATE_SKIP_SCAN_CHECK:-0}" = "1" ]; then
        if [ "$force" = "1" ]; then
            $log_fn "Scan check skipped (--force)"
        else
            $log_fn "Scan check disabled (NESSUS_UPDATE_SKIP_SCAN_CHECK=1)"
        fi
        return 0
    fi

    max_wait="${NESSUS_UPDATE_WAIT_FOR_SCANS:-14400}"
    poll="${NESSUS_UPDATE_SCAN_POLL_INTERVAL:-10}"
    grace="${NESSUS_UPDATE_SCAN_GRACE_SEC:-3}"
    _NESSUS_LAST_SCAN_LOG_AT=-999
    _NESSUS_LAST_SCAN_COUNT=-1

    $log_fn "Scan gate: poll every ${poll}s, grace ${grace}s (max wait ${max_wait}s)"

    while true; do
        hold_reason=""
        scan_report=""
        scan_count=0

        if nessus_update_hold_active; then
            hold_reason=$(nessus_update_hold_reason)
            $log_fn "Update blocked by hold file ${NESSUS_UPDATE_HOLD_FILE}${hold_reason:+: ${hold_reason}}"
        else
            scan_report=$(nessus_active_scans_report) || {
                $log_fn "Error: Could not query Nessus scan status (API login failed)"
                return 1
            }
            scan_count=$(printf '%s\n' "$scan_report" | sed '/^$/d' | wc -l)
            if [ "$scan_count" -gt 0 ]; then
                nessus_log_scan_wait "$log_fn" "$scan_count" "$scan_report" "$waited" "$poll"
            fi
        fi

        if ! nessus_update_hold_active && [ "$scan_count" -eq 0 ]; then
            sleep "$grace"
            if nessus_update_hold_active; then
                continue
            fi
            scan_report=$(nessus_active_scans_report) || return 1
            scan_count=$(printf '%s\n' "$scan_report" | sed '/^$/d' | wc -l)
            if [ "$scan_count" -eq 0 ]; then
                $log_fn "No active scans, proceeding with update"
                return 0
            fi
            $log_fn "Scan started during ${grace}s grace window, waiting again..."
        fi

        if [ "$max_wait" -eq 0 ]; then
            $log_fn "Error: Update blocked and NESSUS_UPDATE_WAIT_FOR_SCANS=0 (fail-fast)"
            return 2
        fi

        if [ "$waited" -ge "$max_wait" ]; then
            $log_fn "Error: Update deferred after ${max_wait}s (scans or hold file still active)"
            return 2
        fi

        sleep "$poll"
        waited=$((waited + poll))
    done
}
