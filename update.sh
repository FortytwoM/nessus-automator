#!/bin/bash
cd /tmp || exit 1

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-api.sh ] && . /usr/local/bin/nessus-api.sh

LOCK_FILE="/tmp/nessus_update.lock"
ARCHIVE_NAME="all-2.0.tar.gz"
DOWNLOAD_TMP="${ARCHIVE_NAME}.download"
UPDATE_DEFERRED=2
UPDATE_STAMP_FILE="${NESSUS_UPDATE_STAMP_FILE:-/opt/nessus/var/nessus/.update_feed_stamp}"
UPDATE_FLAG_FILE="${NESSUS_UPDATE_FLAG_FILE:-/opt/nessus/var/nessus/.update_completed}"
_CANCELLED=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [update] $*"
}

_update_cleanup() {
    if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$$" ]; then
        rm -f "$LOCK_FILE"
    fi
    if [ "$_CANCELLED" -eq 1 ]; then
        rm -f "$ARCHIVE_NAME" "$DOWNLOAD_TMP"
    fi
}

_update_on_signal() {
    _CANCELLED=1
    log "Update interrupted by signal"
    _update_cleanup
    exit 130
}

UPDATE_FORCE=0
PLUGIN_SET_CLI=""
UPDATE_MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --force)
            UPDATE_FORCE=1
            shift
            ;;
        --plugin-set)
            if [ -z "${2:-}" ]; then
                log "Error: --plugin-set requires a 12-digit feed id"
                exit 1
            fi
            if ! echo "$2" | grep -qE '^[0-9]{12}$'; then
                log "Error: --plugin-set must be a 12-digit feed id (YYYYMMDDHHMM)"
                exit 1
            fi
            PLUGIN_SET_CLI="$2"
            export NESSUS_PLUGIN_SET="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

is_local_path() {
    case "$1" in
        /*|./*|../*|file://*) return 0 ;;
        *) return 1 ;;
    esac
}

redact_url() {
    local value="$1"
    case "$value" in
        http://*|https://*)
            printf '%s' "$value" | sed -E 's/([?&](u|p|user|username|password|token|key)=)[^&]*/\1***/Ig'
            ;;
        *)
            printf '%s' "$value"
            ;;
    esac
}

INCOMING_DIR="/opt/nessus/var/nessus/incoming"

feed_magic_label() {
    local magic="$1"
    case "$magic" in
        23458917*) printf '%s' "tenable-feed" ;;
        1f8b*) printf '%s' "gzip" ;;
        *) printf '%s' "unknown" ;;
    esac
}

log_archive_diagnostics() {
    local file="$1"
    local http_code="${2:-}"
    local size magic label extra=""

    [ -f "$file" ] || {
        log "Diagnostics: file missing${http_code:+, HTTP=${http_code}}"
        return 0
    }

    size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    magic=$(head -c 4 "$file" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    label=$(feed_magic_label "$magic")
    [ -n "$http_code" ] && extra=", HTTP=${http_code}"
    log "Diagnostics: size=${size} bytes, magic=${magic} (${label})${extra}"
}

cleanup_incoming_uploads() {
    local path count=0

    [ -d "$INCOMING_DIR" ] || return 0
    for path in "$INCOMING_DIR"/*.tar.gz "$INCOMING_DIR"/*.tgz; do
        [ -f "$path" ] || continue
        rm -f "$path" && count=$((count + 1))
    done
    [ "$count" -gt 0 ] && log "Cleaned ${count} uploaded feed file(s) from ${INCOMING_DIR}"
}

mark_update_complete() {
    write_update_feed_stamp "$update_source" || log "Warning: Could not write feed stamp"
    cleanup_incoming_uploads
}

resolve_local_archive() {
    local candidate=""

    if [ -n "${NESSUS_UPDATE_FILE:-}" ] && [ -f "$NESSUS_UPDATE_FILE" ]; then
        candidate="$NESSUS_UPDATE_FILE"
    elif [ -f /mnt/nessus/"$ARCHIVE_NAME" ]; then
        candidate="/mnt/nessus/$ARCHIVE_NAME"
    fi

    if [ -n "$candidate" ]; then
        printf '%s' "$candidate"
        return 0
    fi

    return 1
}

resolve_planned_source() {
    local cli_arg="${1:-}"
    local local_archive="" path="" url=""

    if [ -n "$cli_arg" ] && is_local_path "$cli_arg"; then
        path="${cli_arg#file://}"
        if [ -f "$path" ]; then
            printf 'local:%s:%s' \
                "$(sha256sum "$path" 2>/dev/null | awk '{print $1}')" \
                "$(stat -c%s "$path" 2>/dev/null || echo 0)"
            return 0
        fi
        return 1
    fi

    if [ -z "$cli_arg" ]; then
        if local_archive=$(resolve_local_archive); then
            printf 'local:%s:%s' \
                "$(sha256sum "$local_archive" 2>/dev/null | awk '{print $1}')" \
                "$(stat -c%s "$local_archive" 2>/dev/null || echo 0)"
            return 0
        fi
    fi

    url="$cli_arg"
    [ -z "$url" ] && url="${NESSUS_UPDATE_URL:-}"
    if [ -n "$url" ]; then
        printf 'url:%s' "$(printf '%s' "$url" | sha256sum 2>/dev/null | awk '{print $1}')"
        return 0
    fi
    return 1
}

write_update_feed_stamp() {
    local cli_arg="${1:-}"
    local fingerprint=""

    fingerprint=$(resolve_planned_source "$cli_arg") || return 1
    mkdir -p "$(dirname "$UPDATE_STAMP_FILE")"
    printf '%s\n' "$fingerprint" > "$UPDATE_STAMP_FILE"
    touch "$UPDATE_FLAG_FILE"
}

feed_changed() {
    local cli_arg="${1:-}"
    local planned="" stored=""

    [ ! -f "$UPDATE_FLAG_FILE" ] && return 0
    planned=$(resolve_planned_source "$cli_arg") || return 0
    if [ ! -f "$UPDATE_STAMP_FILE" ]; then
        return 0
    fi
    stored=$(head -1 "$UPDATE_STAMP_FILE" 2>/dev/null | tr -d '\r\n')
    [ "$planned" != "$stored" ]
}

prepare_archive() {
    local cli_arg="$1"
    local local_archive=""
    local path=""

    if [ -n "$cli_arg" ] && is_local_path "$cli_arg"; then
        path="${cli_arg#file://}"
        if [ ! -f "$path" ]; then
            log "Error: Local archive not found: $path"
            return 1
        fi
        log "Using local plugin archive: $path"
        UPDATE_MODE=offline
        if [ "$(readlink -f "$path")" = "$(readlink -f "/tmp/$ARCHIVE_NAME")" ]; then
            return 0
        fi
        cp -f "$path" "$ARCHIVE_NAME" || {
            log "Error: Could not copy local archive to /tmp/$ARCHIVE_NAME"
            return 1
        }
        return 0
    fi

    if [ -z "$cli_arg" ]; then
        if local_archive=$(resolve_local_archive); then
            log "Using local plugin archive: $local_archive"
            UPDATE_MODE=offline
            if [ "$(readlink -f "$local_archive")" = "$(readlink -f "/tmp/$ARCHIVE_NAME")" ]; then
                return 0
            fi
            cp -f "$local_archive" "$ARCHIVE_NAME" || {
                log "Error: Could not copy local archive to /tmp/$ARCHIVE_NAME"
                return 1
            }
            return 0
        fi
    fi

    local update_url="$cli_arg"
    [ -z "$update_url" ] && update_url="${NESSUS_UPDATE_URL:-}"
    if [ -z "$update_url" ]; then
        log "Error: No update source. Priority: archive arg > /mnt/nessus/all-2.0.tar.gz > NESSUS_UPDATE_URL"
        return 1
    fi

    log "No local archive; downloading from $(redact_url "$update_url")"
    UPDATE_MODE=online
    local http_code wget_log wget_rc
    rm -f "$DOWNLOAD_TMP"
    wget_log=$(wget -O "$DOWNLOAD_TMP" "$update_url" --no-check-certificate -q -S 2>&1)
    wget_rc=$?
    http_code=$(printf '%s\n' "$wget_log" | grep -i "HTTP/" | tail -1 | awk '{print $2}')

    if [ "$wget_rc" -ne 0 ] || [ ! -f "$DOWNLOAD_TMP" ]; then
        log "Error: Download failed (HTTP ${http_code:-unknown}, wget exit ${wget_rc})"
        [ -f "$DOWNLOAD_TMP" ] && log_archive_diagnostics "$DOWNLOAD_TMP" "${http_code:-}"
        rm -f "$DOWNLOAD_TMP"
        return 1
    fi

    mv -f "$DOWNLOAD_TMP" "$ARCHIVE_NAME" || {
        log "Error: Could not move downloaded archive into place"
        rm -f "$DOWNLOAD_TMP"
        return 1
    }
    log_archive_diagnostics "$ARCHIVE_NAME" "${http_code:-}"
}

if [ "${1:-}" = "--feed-changed" ]; then
    if feed_changed "${2:-}"; then
        exit 0
    fi
    exit 1
fi

if ! ( set -C; echo $$ > "$LOCK_FILE" ) 2>/dev/null; then
    existing_pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
    if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
        log "Update already in progress (pid $existing_pid)"
        exit 0
    fi
    log "Removing stale update lock"
    rm -f "$LOCK_FILE"
    if ! ( set -C; echo $$ > "$LOCK_FILE" ) 2>/dev/null; then
        log "Error: Could not acquire update lock"
        exit 1
    fi
fi
trap '_update_cleanup' EXIT
trap '_update_on_signal' TERM INT

update_source="${1:-}"

log "Checking scan activity before download..."
nessus_wait_for_update_clearance "$UPDATE_FORCE" log
rc=$?
if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 2 ]; then
        log "Update deferred; retry when scans finish or hold file is removed"
        exit "$UPDATE_DEFERRED"
    fi
    log "Error: Scan status check failed"
    exit 1
fi

if ! prepare_archive "$update_source"; then
    exit 1
fi

if [ "$UPDATE_MODE" = "offline" ]; then
    if [ -z "${NESSUS_PLUGIN_SET:-}" ]; then
        log "Error: offline update requires --plugin-set or NESSUS_PLUGIN_SET"
        exit 1
    fi
    export NESSUS_UPDATE_ONLINE=0
else
    export NESSUS_UPDATE_ONLINE=1
    unset NESSUS_PLUGIN_SET
fi

filesize=$(stat -c%s "$ARCHIVE_NAME" 2>/dev/null || echo 0)
log "Archive size: $(($filesize / 1024 / 1024))MB"

if [ "$filesize" -lt 10240 ]; then
    log "Error: File too small (${filesize} bytes)"
    log_archive_diagnostics "$ARCHIVE_NAME"
    rm -f "$ARCHIVE_NAME"
    exit 1
fi

nessus_feed_archive_valid() {
    local file="$1"
    local magic

    magic=$(head -c 4 "$file" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        23458917*)
            # Tenable plugin bundle (modern feed; .tar.gz name but not gzip)
            return 0
            ;;
        1f8b*)
            # Legacy gzip-compressed feed
            gzip -t "$file" 2>/dev/null
            return $?
            ;;
        *)
            log "Warning: Unknown feed header (${magic}), nessuscli will validate"
            return 0
            ;;
    esac
}

if ! nessus_feed_archive_valid "$ARCHIVE_NAME"; then
    log "Error: Legacy gzip feed failed integrity check"
    log_archive_diagnostics "$ARCHIVE_NAME"
    rm -f "$ARCHIVE_NAME"
    exit 1
fi

log_archive_diagnostics "$ARCHIVE_NAME"

pkill -f "nessus-service" > /dev/null 2>&1 || true
pkill -f "nessusd" > /dev/null 2>&1 || true
sleep 3

/usr/local/bin/patch.sh --feed-unlock
rm -f /opt/nessus/var/nessus/agent-activity.db 2>/dev/null

log "Installing plugins..."
update_output=$(/opt/nessus/sbin/nessuscli update "$ARCHIVE_NAME" 2>&1)
update_result=$?
echo "$update_output" | grep -v '^$' | while read -r line; do log "  $line"; done

if [ $update_result -ne 0 ]; then
    log "Error: Plugin installation failed (exit code $update_result)"
    log_archive_diagnostics "$ARCHIVE_NAME"
    rm -f "$ARCHIVE_NAME"
    exit 1
fi

nasl_count=$(find /opt/nessus/lib/nessus/plugins -maxdepth 1 -name "*.nasl" 2>/dev/null | wc -l)
log "Installed: $nasl_count plugins"

log "Applying patch..."
if ! /usr/local/bin/patch.sh; then
    log "Warning: Initial patch failed, retrying after brief wait..."
    sleep 5
    if ! /usr/local/bin/patch.sh; then
        log "Error: Plugin patch failed"
        rm -f "$ARCHIVE_NAME"
        exit 1
    fi
fi

rm -f "$ARCHIVE_NAME"

log "Starting Nessus..."
/opt/nessus/sbin/nessus-service -D > /dev/null 2>&1 &

log "Compiling plugins (timeout ${NESSUS_READY_TIMEOUT:-1800}s, this may take several minutes)..."
waited=0
max_wait="${NESSUS_READY_TIMEOUT:-1800}"
while [ $waited -lt $max_wait ]; do
    status=$(curl -sL -k https://localhost:8834/server/status 2>/dev/null)
    if [ -n "$status" ]; then
        engine_state=$(echo "$status" | grep -o '"engine_status":{[^}]*}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        plugin_data=$(echo "$status" | sed -n 's/.*"pluginData"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -1)
        engine_progress=$(echo "$status" | grep -o '"engine_status":{[^}]*}' | grep -o '"progress":[0-9]*' | cut -d: -f2)

        if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
            log "Compilation complete"
            mark_update_complete
            if [ -f /tmp/nessus_feed_immutable ]; then
                exit 0
            fi
            log "Re-applying patch after compile..."
            pkill -f "nessus-service" > /dev/null 2>&1 || true
            pkill -f "nessusd" > /dev/null 2>&1 || true
            sleep 3
            if ! /usr/local/bin/patch.sh; then
                log "Error: Post-compile patch failed"
                exit 1
            fi
            log "Starting Nessus after final patch..."
            /opt/nessus/sbin/nessus-service -D > /dev/null 2>&1 &
            waited2=0
            max_wait2="${NESSUS_READY_RETRY_TIMEOUT:-600}"
            while [ $waited2 -lt $max_wait2 ]; do
                status=$(curl -sL -k https://localhost:8834/server/status 2>/dev/null)
                if [ -n "$status" ]; then
                    engine_state=$(echo "$status" | grep -o '"engine_status":{[^}]*}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                    plugin_data=$(echo "$status" | sed -n 's/.*"pluginData"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -1)
                    if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
                        log "Nessus ready after update"
                        mark_update_complete
                        exit 0
                    fi
                fi
                sleep 10
                waited2=$((waited2 + 10))
            done
            log "Warning: Nessus did not report ready within ${max_wait2}s after final patch"
            exit 0
        fi

        if [ -n "$engine_progress" ] && [ $((waited % 30)) -eq 0 ]; then
            if [ "$engine_progress" = "100" ] && [ "$plugin_data" != "true" ]; then
                log "  Compiling: ${engine_progress}% (waiting for pluginData...)"
            else
                log "  Compiling: ${engine_progress}%"
            fi
        fi
    fi

    sleep 10
    waited=$((waited + 10))
done

log "Warning: Plugin compilation did not finish within ${max_wait}s"
mark_update_complete
exit 0
