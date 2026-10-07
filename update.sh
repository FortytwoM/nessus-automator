#!/bin/bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-api.sh ] && . /usr/local/bin/nessus-api.sh

DOWNLOAD_DIR="${NESSUS_DOWNLOAD_DIR:-/var/lib/nessus-downloads}"
mkdir -p "$DOWNLOAD_DIR" || exit 1
chmod 700 "$DOWNLOAD_DIR" || exit 1
cd "$DOWNLOAD_DIR" || exit 1

LOCK_FILE="/tmp/nessus_update.lock"
ARCHIVE_NAME="all-2.0.tar.gz"
ARCHIVE_SIG="${ARCHIVE_NAME}.sig"
ARCHIVE_SIG_FILE=""
DOWNLOAD_TMP="${ARCHIVE_NAME}.download"
SIG_DOWNLOAD_TMP="${ARCHIVE_SIG}.download"
UPDATE_DEFERRED=2
UPDATE_ALREADY_RUNNING=3
UPDATE_ROLLED_BACK=4
UPDATE_STAMP_FILE="${NESSUS_UPDATE_STAMP_FILE:-/opt/nessus/var/nessus/.update_feed_stamp}"
UPDATE_FLAG_FILE="${NESSUS_UPDATE_FLAG_FILE:-/opt/nessus/var/nessus/.update_completed}"
UPDATE_SUCCESS_FILE="${NESSUS_UPDATE_SUCCESS_FILE:-/opt/nessus/var/nessus/.update_success_epoch}"
SNAPSHOT_DIR="${NESSUS_UPDATE_SNAPSHOT_DIR:-/opt/nessus/var/nessus/update-snapshots}"
SNAPSHOT_FILE=""
_CANCELLED=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [update] $*"
}

status_field() {
    local status="$1" field="$2"
    printf '%s' "$status" | /usr/local/bin/nessus-status.py --field "$field" 2>/dev/null
}

validate_positive_integer() {
    case "$2" in
        ''|*[!0-9]*)
            log "Error: $1 must be a non-negative integer"
            return 1
            ;;
    esac
}

prune_update_snapshots() {
    local keep="${NESSUS_UPDATE_ROLLBACK_KEEP:-2}"

    validate_positive_integer NESSUS_UPDATE_ROLLBACK_KEEP "$keep" || return 1
    if [ "$keep" -lt 1 ]; then
        log "Error: NESSUS_UPDATE_ROLLBACK_KEEP must be at least 1"
        return 1
    fi
    python3 /usr/local/bin/update-snapshot.py prune \
        --directory "$SNAPSHOT_DIR" \
        --keep "$keep"
}

create_update_snapshot() {
    local max_bytes="${NESSUS_UPDATE_ROLLBACK_MAX_BYTES:-5368709120}"
    local timestamp partial size
    local -a paths=("lib/nessus/plugins")

    [ "${NESSUS_UPDATE_ROLLBACK:-1}" = "1" ] || return 0
    validate_positive_integer NESSUS_UPDATE_ROLLBACK_MAX_BYTES "$max_bytes" || return 1
    [ -d /opt/nessus/lib/nessus/plugins ] || {
        log "Error: Cannot snapshot missing plugin directory"
        return 1
    }
    if [ -z "$(find /opt/nessus/lib/nessus/plugins -type f -print -quit)" ]; then
        log "Skipping rollback snapshot because the plugin directory is empty"
        SNAPSHOT_FILE=""
        return 0
    fi
    [ -d /opt/nessus/var/nessus/templates ] && paths+=("var/nessus/templates")
    [ -f /opt/nessus/var/nessus/plugin_feed_info.inc ] \
        && paths+=("var/nessus/plugin_feed_info.inc")
    [ -f /opt/nessus/var/nessus/.plugin_feed_info.inc ] \
        && paths+=("var/nessus/.plugin_feed_info.inc")
    [ -f /opt/nessus/var/nessus/.plugin_set_last ] \
        && paths+=("var/nessus/.plugin_set_last")

    mkdir -p "$SNAPSHOT_DIR"
    timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
    SNAPSHOT_FILE="$SNAPSHOT_DIR/plugins-${timestamp}.tar.gz"
    partial="${SNAPSHOT_FILE}.partial"
    log "Creating pre-update plugin snapshot..."
    if ! tar --create --gzip --numeric-owner --one-file-system \
        --file "$partial" --directory /opt/nessus "${paths[@]}"; then
        rm -f "$partial"
        log "Error: Could not create plugin snapshot"
        return 1
    fi
    size=$(stat -c%s "$partial" 2>/dev/null || echo 0)
    if [ "$size" -le 0 ] || [ "$size" -gt "$max_bytes" ]; then
        rm -f "$partial"
        log "Error: Plugin snapshot size ${size} exceeds limit ${max_bytes}"
        return 1
    fi
    mv "$partial" "$SNAPSHOT_FILE"
    if ! (
        cd "$SNAPSHOT_DIR" \
            && sha256sum "$(basename "$SNAPSHOT_FILE")" \
                > "$(basename "$SNAPSHOT_FILE").sha256"
    ); then
        rm -f "$SNAPSHOT_FILE" "${SNAPSHOT_FILE}.sha256"
        log "Error: Could not checksum plugin snapshot"
        return 1
    fi
    log "Plugin snapshot created: $(basename "$SNAPSHOT_FILE") ($((size / 1024 / 1024))MB)"
    prune_update_snapshots
}

restore_update_snapshot() {
    local status engine_state plugin_data waited=0
    local wait_ready="${1:-1}"
    local timeout="${NESSUS_READY_RETRY_TIMEOUT:-600}"

    if [ -z "$SNAPSHOT_FILE" ] || [ ! -f "$SNAPSHOT_FILE" ] \
        || [ ! -f "${SNAPSHOT_FILE}.sha256" ]; then
        return 1
    fi
    if ! (
        cd "$SNAPSHOT_DIR" \
            && sha256sum -c "$(basename "$SNAPSHOT_FILE").sha256" >/dev/null
    ); then
        log "Error: Plugin snapshot checksum validation failed"
        return 1
    fi
    if ! python3 /usr/local/bin/update-snapshot.py validate \
        --archive "$SNAPSHOT_FILE"; then
        log "Error: Plugin snapshot failed safety validation"
        return 1
    fi
    log "Rolling back plugins from $(basename "$SNAPSHOT_FILE")..."
    pkill -f "nessus-service" >/dev/null 2>&1 || true
    pkill -f "nessusd" >/dev/null 2>&1 || true
    sleep 2
    /usr/local/bin/patch.sh --feed-unlock || return 1
    rm -rf /opt/nessus/lib/nessus/plugins /opt/nessus/var/nessus/templates
    rm -f /opt/nessus/var/nessus/plugin_feed_info.inc \
        /opt/nessus/var/nessus/.plugin_feed_info.inc \
        /opt/nessus/var/nessus/.plugin_set_last \
        /opt/nessus/var/nessus/agent-activity.db
    tar --extract --gzip --numeric-owner --same-owner \
        --file "$SNAPSHOT_FILE" --directory /opt/nessus || return 1
    /usr/local/bin/patch.sh --feed-lock || return 1
    /opt/nessus/sbin/nessus-service -D >/dev/null 2>&1 &
    if [ "$wait_ready" = "0" ]; then
        log "Plugin files restored; Nessus will finish compiling in the background"
        return 0
    fi

    while [ "$waited" -lt "$timeout" ]; do
        status=$(curl -sL -k "${NESSUS_API_BASE}/server/status" 2>/dev/null)
        if [ -n "$status" ]; then
            engine_state=$(status_field "$status" engine_status)
            plugin_data=$(status_field "$status" plugin_data)
            if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
                log "Plugin rollback completed successfully"
                return 0
            fi
        fi
        sleep 10
        waited=$((waited + 10))
    done
    log "Error: Nessus did not become ready after plugin rollback"
    return 1
}

fail_with_rollback() {
    local reason="$1"

    log "Error: $reason"
    if [ "${NESSUS_UPDATE_ROLLBACK:-1}" = "1" ] && restore_update_snapshot; then
        log "Update failed and previous plugin snapshot was restored"
        exit "$UPDATE_ROLLED_BACK"
    fi
    log "Error: Automatic plugin rollback failed or was unavailable"
    exit 1
}

# Called by EXIT/TERM/INT traps below.
# shellcheck disable=SC2329
_update_cleanup() {
    if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$$" ]; then
        rm -f "$LOCK_FILE"
    fi
    if [ "$_CANCELLED" -eq 1 ]; then
        rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG" "$DOWNLOAD_TMP" "$SIG_DOWNLOAD_TMP"
    fi
}

# shellcheck disable=SC2329
_restart_nessus_after_abort() {
    /usr/local/bin/patch.sh --feed-lock || true
    if ! pgrep -f "nessus-service" >/dev/null 2>&1; then
        /opt/nessus/sbin/nessus-service -D >/dev/null 2>&1 &
    fi
}

# shellcheck disable=SC2329
_update_on_signal() {
    trap - TERM INT
    _CANCELLED=1
    log "Update interrupted by signal"
    if [ -n "$SNAPSHOT_FILE" ] && [ -f "$SNAPSHOT_FILE" ]; then
        if restore_update_snapshot 0; then
            log "Update interrupted; previous plugins were restored"
            exit "$UPDATE_ROLLED_BACK"
        fi
        log "Error: Could not restore plugins after interrupt"
        _restart_nessus_after_abort
        exit 1
    fi
    _restart_nessus_after_abort
    exit 130
}

UPDATE_FORCE=0
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

INCOMING_DIR="${NESSUS_MANAGE_UPLOAD_DIR:-${DOWNLOAD_DIR}/incoming}"

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
    for path in "$INCOMING_DIR"/*.tar.gz "$INCOMING_DIR"/*.tgz "$INCOMING_DIR"/*.sig; do
        [ -f "$path" ] || continue
        rm -f "$path" && count=$((count + 1))
    done
    [ "$count" -gt 0 ] && log "Cleaned ${count} uploaded feed file(s) from ${INCOMING_DIR}"
}

mark_update_complete() {
    write_update_feed_stamp "$update_source" || log "Warning: Could not write feed stamp"
    mkdir -p "$(dirname "$UPDATE_SUCCESS_FILE")"
    if date +%s > "${UPDATE_SUCCESS_FILE}.tmp" \
        && mv "${UPDATE_SUCCESS_FILE}.tmp" "$UPDATE_SUCCESS_FILE"; then
        :
    else
        log "Warning: Could not write update success timestamp"
    fi
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
        if [ -f "${path}.sig" ]; then
            cp -f "${path}.sig" "$ARCHIVE_SIG" || {
                log "Error: Could not copy $(basename "${path}.sig") to $DOWNLOAD_DIR/$ARCHIVE_SIG"
                return 1
            }
            ARCHIVE_SIG_FILE="$ARCHIVE_SIG"
        fi
        if [ "$(readlink -f "$path")" = "$(readlink -f "$DOWNLOAD_DIR/$ARCHIVE_NAME")" ]; then
            return 0
        fi
        cp -f "$path" "$ARCHIVE_NAME" || {
            log "Error: Could not copy local archive to $DOWNLOAD_DIR/$ARCHIVE_NAME"
            return 1
        }
        return 0
    fi

    if [ -z "$cli_arg" ]; then
        if local_archive=$(resolve_local_archive); then
            log "Using local plugin archive: $local_archive"
            UPDATE_MODE=offline
            if [ -f "${local_archive}.sig" ]; then
                cp -f "${local_archive}.sig" "$ARCHIVE_SIG" || {
                    log "Error: Could not copy $(basename "${local_archive}.sig") to $DOWNLOAD_DIR/$ARCHIVE_SIG"
                    return 1
                }
                ARCHIVE_SIG_FILE="$ARCHIVE_SIG"
            fi
            if [ "$(readlink -f "$local_archive")" = "$(readlink -f "$DOWNLOAD_DIR/$ARCHIVE_NAME")" ]; then
                return 0
            fi
            cp -f "$local_archive" "$ARCHIVE_NAME" || {
                log "Error: Could not copy local archive to $DOWNLOAD_DIR/$ARCHIVE_NAME"
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
    local download_log download_rc
    local -a download_args=()
    if [ -n "${NESSUS_UPDATE_SHA256:-}" ]; then
        download_args=(--sha256 "$NESSUS_UPDATE_SHA256")
    fi
    rm -f "$DOWNLOAD_TMP"
    download_log=$(/usr/local/bin/secure-download.py \
        "$update_url" "$DOWNLOAD_TMP" \
        "${download_args[@]}" 2>&1)
    download_rc=$?
    if [ "$download_rc" -ne 0 ] || [ ! -f "$DOWNLOAD_TMP" ]; then
        log "Error: Secure download failed: $download_log"
        [ -f "$DOWNLOAD_TMP" ] && log_archive_diagnostics "$DOWNLOAD_TMP"
        rm -f "$DOWNLOAD_TMP"
        return 1
    fi
    log "$download_log"

    mv -f "$DOWNLOAD_TMP" "$ARCHIVE_NAME" || {
        log "Error: Could not move downloaded archive into place"
        rm -f "$DOWNLOAD_TMP"
        return 1
    }
    log_archive_diagnostics "$ARCHIVE_NAME"

    # Newer Nessus requires the detached signature beside the archive.
    # Download it when the source URL exposes one; older Nessus ignores it.
    local sig_url="${update_url//$ARCHIVE_NAME/$ARCHIVE_SIG}"
    if [ "$sig_url" != "$update_url" ]; then
        rm -f "$SIG_DOWNLOAD_TMP"
        if /usr/local/bin/secure-download.py "$sig_url" "$SIG_DOWNLOAD_TMP" >/dev/null 2>&1 \
            && [ -s "$SIG_DOWNLOAD_TMP" ]; then
            mv -f "$SIG_DOWNLOAD_TMP" "$ARCHIVE_SIG"
            ARCHIVE_SIG_FILE="$ARCHIVE_SIG"
            log "Downloaded detached plugin archive signature"
        else
            rm -f "$SIG_DOWNLOAD_TMP"
            log "Warning: no detached plugin archive signature downloaded; continuing without it"
        fi
    fi
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
        exit "$UPDATE_ALREADY_RUNNING"
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
log "Archive size: $((filesize / 1024 / 1024))MB"

if [ "$filesize" -lt 10240 ]; then
    log "Error: File too small (${filesize} bytes)"
    log_archive_diagnostics "$ARCHIVE_NAME"
    rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG"
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
    rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG"
    exit 1
fi

log_archive_diagnostics "$ARCHIVE_NAME"

pkill -f "nessus-service" > /dev/null 2>&1 || true
pkill -f "nessusd" > /dev/null 2>&1 || true
sleep 3

if ! /usr/local/bin/patch.sh --feed-unlock; then
    /opt/nessus/sbin/nessus-service -D >/dev/null 2>&1 &
    log "Error: Could not unlock plugins before update"
    exit 1
fi
if ! create_update_snapshot; then
    /usr/local/bin/patch.sh --feed-lock || true
    /opt/nessus/sbin/nessus-service -D >/dev/null 2>&1 &
    log "Error: Update aborted because a rollback snapshot could not be created"
    exit 1
fi
rm -f /opt/nessus/var/nessus/agent-activity.db 2>/dev/null

log "Installing plugins..."
if [ -n "$ARCHIVE_SIG_FILE" ] && [ -f "$ARCHIVE_SIG_FILE" ]; then
    log "Using detached plugin archive signature: $(basename "$ARCHIVE_SIG_FILE")"
    update_output=$(/opt/nessus/sbin/nessuscli update "$ARCHIVE_NAME" "$ARCHIVE_SIG_FILE" 2>&1)
else
    update_output=$(/opt/nessus/sbin/nessuscli update "$ARCHIVE_NAME" 2>&1)
fi
update_result=$?
echo "$update_output" | grep -v '^$' | while read -r line; do log "  $line"; done

if [ $update_result -ne 0 ]; then
    log_archive_diagnostics "$ARCHIVE_NAME"
    rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG"
    fail_with_rollback "Plugin installation failed (exit code $update_result)"
fi

nasl_count=$(find /opt/nessus/lib/nessus/plugins -maxdepth 1 -name "*.nasl" 2>/dev/null | wc -l)
log "Installed: $nasl_count plugins"

log "Applying patch..."
if ! /usr/local/bin/patch.sh; then
    log "Warning: Initial patch failed, retrying after brief wait..."
    sleep 5
    if ! /usr/local/bin/patch.sh; then
        rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG"
        fail_with_rollback "Plugin patch failed"
    fi
fi

rm -f "$ARCHIVE_NAME" "$ARCHIVE_SIG"

log "Starting Nessus..."
/opt/nessus/sbin/nessus-service -D > /dev/null 2>&1 &

log "Compiling plugins (timeout ${NESSUS_READY_TIMEOUT:-1800}s, this may take several minutes)..."
waited=0
max_wait="${NESSUS_READY_TIMEOUT:-1800}"
while [ "$waited" -lt "$max_wait" ]; do
    status=$(curl -sL -k "${NESSUS_API_BASE}/server/status" 2>/dev/null)
    if [ -n "$status" ]; then
        engine_state=$(status_field "$status" engine_status)
        plugin_data=$(status_field "$status" plugin_data)
        engine_progress=$(status_field "$status" engine_progress)

        if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
            log "Compilation complete"
            if [ -f /tmp/nessus_feed_immutable ]; then
                mark_update_complete
                exit 0
            fi
            log "Re-applying patch after compile..."
            pkill -f "nessus-service" > /dev/null 2>&1 || true
            pkill -f "nessusd" > /dev/null 2>&1 || true
            sleep 3
            if ! /usr/local/bin/patch.sh; then
                fail_with_rollback "Post-compile patch failed"
            fi
            log "Starting Nessus after final patch..."
            /opt/nessus/sbin/nessus-service -D > /dev/null 2>&1 &
            waited2=0
            max_wait2="${NESSUS_READY_RETRY_TIMEOUT:-600}"
            while [ "$waited2" -lt "$max_wait2" ]; do
                status=$(curl -sL -k "${NESSUS_API_BASE}/server/status" 2>/dev/null)
                if [ -n "$status" ]; then
                    engine_state=$(status_field "$status" engine_status)
                    plugin_data=$(status_field "$status" plugin_data)
                    if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
                        log "Nessus ready after update"
                        mark_update_complete
                        exit 0
                    fi
                fi
                sleep 10
                waited2=$((waited2 + 10))
            done
            fail_with_rollback "Nessus did not report ready within ${max_wait2}s after final patch"
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

fail_with_rollback "Plugin compilation did not finish within ${max_wait}s"
