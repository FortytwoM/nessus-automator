#!/bin/bash

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [config] $*"
}

set_fix_with_retries() {
    local key="$1"
    local value="$2"
    local attempts="${3:-12}"
    local delay="${4:-2}"
    local n=0

    while [ $n -lt $attempts ]; do
        if /opt/nessus/sbin/nessuscli fix --set "${key}=${value}" >/dev/null 2>&1; then
            return 0
        fi
        n=$((n + 1))
        sleep "$delay"
    done
    return 1
}

print_status() {
    local label="$1"
    local mark="$2"
    printf "  %-22s %s\n" "$label" "$mark"
}

configure_nessus() {
    log "Configuring Nessus settings..."

    if [ ! -f /opt/nessus/sbin/nessuscli ]; then
        log "Error: nessuscli not found at /opt/nessus/sbin/nessuscli"
        return 1
    fi

    pkill -f "nessus-service" 2>/dev/null || true
    pkill -f "nessusd" 2>/dev/null || true
    sleep 2

    if pgrep -f "nessus-service|nessusd" > /dev/null 2>&1; then
        pkill -9 -f "nessus-service" 2>/dev/null || true
        pkill -9 -f "nessusd" 2>/dev/null || true
        sleep 2
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
        log "Nessus configuration completed with errors"
        return 1
    fi

    log "Nessus configuration completed"
    return 0
}

if [ "$1" = "--force" ] || [ ! -f /opt/nessus/var/nessus/.nessus_configured ]; then
    if configure_nessus; then
        touch /opt/nessus/var/nessus/.nessus_configured
        log "Nessus configuration applied successfully"
    else
        log "Warning: Nessus configuration failed; will retry on next start"
    fi
else
    log "Nessus already configured, skipping..."
fi
