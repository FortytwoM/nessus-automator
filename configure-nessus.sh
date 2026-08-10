#!/bin/bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

SOURCE_IP_STAMP="/opt/nessus/var/nessus/.source_ip_set"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [config] $*"
}

set_fix_with_retries() {
    local key="$1"
    local value="$2"
    local attempts="${3:-12}"
    local delay="${4:-2}"
    local n=0
    local output=""

    while [ $n -lt $attempts ]; do
        if output=$(/opt/nessus/sbin/nessuscli fix --set "${key}=${value}" 2>&1); then
            return 0
        fi
        n=$((n + 1))
        sleep "$delay"
    done
    log "Error: nessuscli could not set '${key}': ${output:-no error output}"
    return 1
}

delete_fix_with_retries() {
    local key="$1"
    local attempts="${2:-12}"
    local delay="${3:-2}"
    local n=0
    local output=""

    while [ $n -lt "$attempts" ]; do
        if output=$(/opt/nessus/sbin/nessuscli fix --delete "$key" 2>&1); then
            return 0
        fi
        n=$((n + 1))
        sleep "$delay"
    done
    log "Error: nessuscli could not delete '${key}': ${output:-no error output}"
    return 1
}

print_status() {
    local label="$1"
    local mark="$2"
    printf "  %-22s %s\n" "$label" "$mark"
}

stop_nessus_for_config() {
    pkill -f "nessus-service" 2>/dev/null || true
    pkill -f "nessusd" 2>/dev/null || true
    sleep 2

    if pgrep -f "nessus-service|nessusd" > /dev/null 2>&1; then
        pkill -9 -f "nessus-service" 2>/dev/null || true
        pkill -9 -f "nessusd" 2>/dev/null || true
        sleep 2
    fi
}

validate_source_ips() {
    local source_ips="${NESSUS_SOURCE_IP:-}"
    local ip available

    [ -z "$source_ips" ] && return 0

    available=$(ip -o addr show | awk '{sub(/\/.*/, "", $4); print $4}')
    while IFS= read -r ip; do
        ip=$(echo "$ip" | xargs)
        [ -z "$ip" ] && continue
        if ! printf '%s\n' "$available" | grep -Fxq "$ip"; then
            log "Error: scan source IP is not present on this host: ${ip}"
            log "Available interfaces:"
            ip -br addr show >&2
            return 1
        fi
    done < <(printf '%s' "$source_ips" | tr ',' '\n')
}

configure_network() {
    local failed=0
    local backend_port="${NESSUS_BACKEND_PORT:-8835}"

    log "Configuring host-network settings..."
    validate_source_ips || return 1
    case "$backend_port" in
        *[!0-9]*|"")
            log "Error: NESSUS_BACKEND_PORT must be a number"
            return 1
            ;;
    esac
    if [ "$backend_port" -lt 1 ] || [ "$backend_port" -gt 65535 ] || [ "$backend_port" -eq 8834 ]; then
        log "Error: NESSUS_BACKEND_PORT must be 1-65535 and cannot be gateway port 8834"
        return 1
    fi

    if set_fix_with_retries listen_address "${NESSUS_LISTEN_ADDRESS:-127.0.0.1}"; then
        print_status "Backend address" "${NESSUS_LISTEN_ADDRESS:-127.0.0.1} ✓"
    else
        print_status "Backend address" "✗"
        failed=1
    fi

    if set_fix_with_retries xmlrpc_listen_port "$backend_port"; then
        print_status "Backend port" "${backend_port} ✓"
    else
        print_status "Backend port" "✗"
        failed=1
    fi

    if [ -n "${NESSUS_SOURCE_IP:-}" ]; then
        if set_fix_with_retries source_ip "${NESSUS_SOURCE_IP}"; then
            print_status "Scan source IP" "${NESSUS_SOURCE_IP} ✓"
            printf '%s\n' "${NESSUS_SOURCE_IP}" > "$SOURCE_IP_STAMP"
        else
            print_status "Scan source IP" "✗"
            failed=1
        fi
    elif [ -f "$SOURCE_IP_STAMP" ]; then
        if delete_fix_with_retries source_ip; then
            print_status "Scan source IP" "OS routing ✓"
            rm -f "$SOURCE_IP_STAMP"
        else
            print_status "Scan source IP" "clear failed ✗"
            failed=1
        fi
    fi

    [ "$failed" -eq 0 ]
}

configure_preferences() {
    log "Configuring Nessus preferences..."

    if [ ! -f /opt/nessus/sbin/nessuscli ]; then
        log "Error: nessuscli not found at /opt/nessus/sbin/nessuscli"
        return 1
    fi

    local failed=0

    if set_fix_with_retries ui_theme dark; then
        print_status "Theme: Dark" "✓"
    else
        print_status "Theme: Dark" "✗"
        failed=1
    fi

    if set_fix_with_retries send_telemetry false; then
        print_status "Telemetry: Off" "✓"
    else
        print_status "Telemetry: Off" "✗"
        failed=1
    fi

    if set_fix_with_retries report_crashes false; then
        print_status "Crash Reports: Off" "✓"
    else
        print_status "Crash Reports: Off" "✗"
        failed=1
    fi

    if set_fix_with_retries auto_update false; then
        print_status "Auto-update: Off" "✓"
    else
        print_status "Auto-update: Off" "✗"
        failed=1
    fi

    if set_fix_with_retries auto_update_ui false; then
        print_status "Auto-update UI: Off" "✓"
    else
        print_status "Auto-update UI: Off" "✗"
        failed=1
    fi

    if set_fix_with_retries disable_core_updates true; then
        print_status "Core updates: Disabled" "✓"
    else
        print_status "Core updates: Disabled" "✗"
        failed=1
    fi

    if [ $failed -ne 0 ]; then
        log "Nessus preference configuration completed with errors"
        return 1
    fi

    log "Nessus preference configuration completed"
    return 0
}

configure_stopped() {
    configure_network || return 1

    if [ "$1" = "--force" ] || [ ! -f /opt/nessus/var/nessus/.nessus_configured ]; then
        configure_preferences || return 1
        touch /opt/nessus/var/nessus/.nessus_configured
        log "Nessus configuration applied successfully"
    else
        log "Nessus preferences already configured; network settings synchronized"
    fi
}

case "${1:-}" in
    --startup)
        configure_stopped
        ;;
    --force)
        stop_nessus_for_config
        configure_stopped --force
        ;;
    *)
        if [ ! -f /opt/nessus/var/nessus/.nessus_configured ]; then
            stop_nessus_for_config
            configure_stopped
        else
            log "Nessus already configured; use --force to reapply all settings"
        fi
        ;;
esac
