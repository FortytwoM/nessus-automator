#!/bin/bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy

set -u
umask 022
export LC_ALL=C

NESSUS_ROOT="${NESSUS_ROOT:-/opt/nessus}"
NESSUS_DATA_DIR="${NESSUS_DATA_DIR:-$NESSUS_ROOT/var/nessus}"
NESSUS_PLUGIN_DIR="${NESSUS_PLUGIN_DIR:-$NESSUS_ROOT/lib/nessus/plugins}"

PLUGIN_FEED_FILE="$NESSUS_DATA_DIR/plugin_feed_info.inc"
PLUGIN_FEED_DOT="$NESSUS_DATA_DIR/.plugin_feed_info.inc"
PLUGIN_FEED_LIB="$NESSUS_PLUGIN_DIR/plugin_feed_info.inc"
PLUGIN_SET_CACHE="$NESSUS_DATA_DIR/.plugin_set_last"

PLUGIN_SET_PHP_URL="https://plugins.nessus.org/v2/plugins.php"

# /tmp marker is kept for update.sh compatibility. The persistent marker is the
# source of truth for whether the plugin tree is currently locked.
FEED_IMMUTABLE_MARKER="${NESSUS_FEED_IMMUTABLE_MARKER:-/tmp/nessus_feed_immutable}"
FEED_IMMUTABLE_STATE="$NESSUS_DATA_DIR/.feed_immutable"
FEED_LOCK_FAILED_STATE="$NESSUS_DATA_DIR/.feed_lock_failed"

PATCH_LOCK_FILE="${NESSUS_PATCH_LOCK_FILE:-/run/nessus-patch.lock}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [patch] $*"
}

validate_plugin_set_digits() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -eq 12 ]
}

cache_plugin_set() {
    local value="${1:-}" tmp

    validate_plugin_set_digits "$value" || return 1
    tmp=$(mktemp "${PLUGIN_SET_CACHE}.tmp.XXXXXX") || return 1
    if ! printf '%s\n' "$value" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    chmod 0644 "$tmp" 2>/dev/null || true
    if ! mv -f "$tmp" "$PLUGIN_SET_CACHE"; then
        rm -f "$tmp"
        return 1
    fi
}

fetch_online_plugin_set() {
    local result=""

    result=$(curl -fsS --proto '=https' --tlsv1.2 --retry 2 --retry-delay 1 \
        --connect-timeout 10 --max-time 30 \
        "$PLUGIN_SET_PHP_URL" 2>/dev/null | tr -d '\n\r ' | head -c 32)
    if validate_plugin_set_digits "$result"; then
        cache_plugin_set "$result" || log "Warning: could not cache plugin set" >&2
        log "Using online plugin set from $PLUGIN_SET_PHP_URL: $result" >&2
        printf '%s\n' "$result"
        return 0
    fi

    log "Error: Could not fetch plugin set from $PLUGIN_SET_PHP_URL" >&2
    return 1
}

resolve_offline_plugin_set() {
    local value="${NESSUS_PLUGIN_SET:-}"

    if [ -z "$value" ]; then
        log "Error: offline update requires plugin_set (NESSUS_PLUGIN_SET or --plugin-set)" >&2
        return 1
    fi
    if ! validate_plugin_set_digits "$value"; then
        log "Error: plugin_set must be a 12-digit feed id (YYYYMMDDHHMM), got: $value" >&2
        return 1
    fi
    if ! cache_plugin_set "$value"; then
        log "Error: Could not cache plugin set: $value" >&2
        return 1
    fi
    log "Using offline plugin set: $value" >&2
    printf '%s\n' "$value"
}

is_offline_plugin_mode() {
    [ "${NESSUS_PROFILE:-}" = "offline" ] && return 0
    [ -f /mnt/nessus/all-2.0.tar.gz ] && return 0
    if [ -n "${NESSUS_UPDATE_FILE:-}" ] && [ -f "${NESSUS_UPDATE_FILE}" ]; then
        return 0
    fi
    return 1
}

read_installed_plugin_set() {
    local f content result

    for f in "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT" "$PLUGIN_FEED_LIB"; do
        [ -f "$f" ] || continue
        content=$(grep -oE 'PLUGIN_SET[[:space:]]*=[[:space:]]*"[0-9]{12}"' "$f" 2>/dev/null | head -n1)
        result=$(printf '%s\n' "$content" | grep -oE '[0-9]{12}' | head -n1)
        if validate_plugin_set_digits "$result"; then
            log "Using plugin set from installed feed ($f): $result" >&2
            printf '%s\n' "$result"
            return 0
        fi
    done

    if [ -f "$PLUGIN_SET_CACHE" ]; then
        result=$(tr -d '\r\n ' < "$PLUGIN_SET_CACHE")
        if validate_plugin_set_digits "$result"; then
            log "Using cached plugin set: $result" >&2
            printf '%s\n' "$result"
            return 0
        fi
    fi

    return 1
}

get_plugin_set() {
    local result=""

    # An explicit value is an operator override and always wins.
    if [ -n "${NESSUS_PLUGIN_SET:-}" ]; then
        resolve_offline_plugin_set
        return $?
    fi

    # Prefer the set that the installed feed actually carries. This keeps
    # plugin_feed_info.inc in sync with the compiled plugins and avoids a
    # spurious full recompile when plugins.php advertises a newer set than the
    # archive that was installed.
    if result=$(read_installed_plugin_set); then
        cache_plugin_set "$result" || log "Warning: could not cache plugin set" >&2
        printf '%s\n' "$result"
        return 0
    fi

    if [ "${NESSUS_UPDATE_ONLINE:-0}" = "1" ]; then
        fetch_online_plugin_set
        return $?
    fi

    if is_offline_plugin_mode; then
        log "Error: offline mode requires NESSUS_PLUGIN_SET in .env (from plugins.nessus.org/offline.php)" >&2
        return 1
    fi

    # Fresh installs have no installed feed yet; use the online set.
    fetch_online_plugin_set
}

mkdirs_exist() {
    [ -d "$NESSUS_DATA_DIR" ]
}

file_is_immutable() {
    local file="$1"

    [ -e "$file" ] || return 1
    lsattr -d "$file" 2>/dev/null | awk '{print $1}' | grep -q 'i'
}

files_are_locked() {
    file_is_immutable "$PLUGIN_FEED_FILE" && file_is_immutable "$PLUGIN_FEED_DOT"
}

plugin_tree_sample() {
    [ -d "$NESSUS_PLUGIN_DIR" ] || return 0
    find "$NESSUS_PLUGIN_DIR" -maxdepth 1 -type f \
        ! -name 'plugin_feed_info.inc' -print -quit 2>/dev/null
}

tree_is_locked() {
    local sample=""

    [ -f "$FEED_IMMUTABLE_STATE" ] || return 1
    sample=$(plugin_tree_sample)
    if [ -n "$sample" ]; then
        file_is_immutable "$sample" || return 1
    fi
    return 0
}

mark_feed_immutable() {
    : > "$FEED_IMMUTABLE_MARKER" 2>/dev/null || true
    : > "$FEED_IMMUTABLE_STATE" 2>/dev/null || true
    rm -f "$FEED_LOCK_FAILED_STATE" 2>/dev/null || true
}

clear_feed_immutable_markers() {
    rm -f "$FEED_IMMUTABLE_MARKER" "$FEED_IMMUTABLE_STATE" "$FEED_LOCK_FAILED_STATE"
}

unlock_one() {
    local file="$1"

    [ -e "$file" ] || return 0
    if ! chattr -i "$file" 2>/dev/null; then
        log "Error: chattr -i failed: $file"
        return 1
    fi
    return 0
}

feed_unlock_files() {
    local rc=0

    unlock_one "$PLUGIN_FEED_FILE" || rc=1
    unlock_one "$PLUGIN_FEED_DOT" || rc=1
    unlock_one "$PLUGIN_FEED_LIB" || rc=1

    # The plugin directory itself is intentionally left writable so the lib feed
    # copy can be replaced atomically. Existing plugin files keep their flags.
    if [ -d "$NESSUS_PLUGIN_DIR" ]; then
        chattr -i "$NESSUS_PLUGIN_DIR" 2>/dev/null || true
    fi
    return "$rc"
}

feed_unlock_tree() {
    if [ -d "$NESSUS_PLUGIN_DIR" ]; then
        if ! chattr -i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null; then
            log "Error: chattr -i -R failed: $NESSUS_PLUGIN_DIR"
            return 1
        fi
    fi
    clear_feed_immutable_markers
    return 0
}

feed_unlock_all() {
    local rc=0

    feed_unlock_files || rc=1
    feed_unlock_tree || rc=1
    return "$rc"
}

lock_one() {
    local file="$1"

    if [ ! -e "$file" ]; then
        log "Error: missing feed file: $file"
        return 1
    fi
    if ! chattr +i "$file" 2>/dev/null; then
        log "Error: chattr +i failed: $file"
        return 1
    fi
    if ! file_is_immutable "$file"; then
        log "Error: immutable flag not observed after chattr: $file"
        return 1
    fi
    return 0
}

feed_lock_primary() {
    local rc=0

    lock_one "$PLUGIN_FEED_FILE" || rc=1
    lock_one "$PLUGIN_FEED_DOT" || rc=1
    if [ "$rc" -ne 0 ]; then
        unlock_one "$PLUGIN_FEED_FILE" >/dev/null 2>&1 || true
        unlock_one "$PLUGIN_FEED_DOT" >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}

feed_lock_tree() {
    local sample=""

    if [ -d "$NESSUS_PLUGIN_DIR" ]; then
        if ! chattr +i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null; then
            log "Error: chattr +i -R failed: $NESSUS_PLUGIN_DIR"
            chattr -i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null || true
            return 1
        fi

        # Match nessusd's expected state: the lib feed copy and the plugin
        # directory stay writable, all other plugin files stay immutable.
        chattr -i "$PLUGIN_FEED_LIB" 2>/dev/null || true
        if ! chattr -i "$NESSUS_PLUGIN_DIR" 2>/dev/null; then
            log "Error: could not unlock plugin directory: $NESSUS_PLUGIN_DIR"
            chattr -i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null || true
            return 1
        fi
        if file_is_immutable "$NESSUS_PLUGIN_DIR"; then
            log "Error: plugin directory is still immutable: $NESSUS_PLUGIN_DIR"
            chattr -i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null || true
            return 1
        fi

        sample=$(plugin_tree_sample)
        if [ -n "$sample" ] && ! file_is_immutable "$sample"; then
            log "Error: plugin tree lock verification failed: $sample"
            chattr -i -R "$NESSUS_PLUGIN_DIR" 2>/dev/null || true
            return 1
        fi
    fi

    mark_feed_immutable
    log "Plugin feed metadata locked"
    return 0
}

feed_lock_all() {
    local rc=0

    feed_lock_primary || rc=1
    if [ "$rc" -eq 0 ]; then
        feed_lock_tree || rc=1
    fi
    if [ "$rc" -ne 0 ]; then
        feed_unlock_files >/dev/null 2>&1 || true
        feed_unlock_tree >/dev/null 2>&1 || true
    fi
    return "$rc"
}

content_matches() {
    local file="$1"

    [ -f "$file" ] || return 1
    cmp -s "$file" <(printf '%s\n' "$PATCH_BODY")
}

sync_file() {
    local file="$1"

    if command -v sync >/dev/null 2>&1; then
        sync "$file" 2>/dev/null || sync 2>/dev/null || true
    fi
}

write_feed_file() {
    local dest="$1" tmp

    tmp=$(mktemp "${dest}.tmp.XXXXXX") || {
        log "Error: could not create temporary file for $dest"
        return 1
    }
    if ! printf '%s\n' "$PATCH_BODY" > "$tmp"; then
        log "Error: could not write temporary file for $dest"
        rm -f "$tmp"
        return 1
    fi
    if ! chmod 0644 "$tmp"; then
        log "Error: could not set mode on temporary file for $dest"
        rm -f "$tmp"
        return 1
    fi
    sync_file "$tmp"
    if ! mv -f "$tmp" "$dest"; then
        log "Error: could not replace $dest"
        rm -f "$tmp"
        return 1
    fi
    sync_file "$(dirname "$dest")"
    return 0
}

install_feed_file() {
    local dest="$1"

    if content_matches "$dest"; then
        log "unchanged: $dest"
        return 0
    fi
    write_feed_file "$dest" || return 1
    if ! content_matches "$dest"; then
        log "Error: verification failed after writing $dest"
        return 1
    fi
    log "updated: $dest"
    return 0
}

acquire_patch_lock() {
    local lock_dir=""

    if ! command -v flock >/dev/null 2>&1; then
        log "Warning: flock not found; continuing without patch lock"
        return 0
    fi

    lock_dir=$(dirname "$PATCH_LOCK_FILE")
    if [ ! -d "$lock_dir" ] || [ ! -w "$lock_dir" ]; then
        PATCH_LOCK_FILE="/tmp/nessus-patch.lock"
        lock_dir="/tmp"
    fi

    if ! exec 9>"$PATCH_LOCK_FILE"; then
        log "Error: could not open patch lock: $PATCH_LOCK_FILE"
        return 1
    fi
    if ! flock -w 60 9; then
        log "Error: another patch is already running"
        return 1
    fi
    return 0
}

on_exit() {
    local rc=$?

    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "${PATCH_PREVIOUSLY_LOCKED:-0}" = "1" ]; then
        feed_lock_primary >/dev/null 2>&1 || true
    fi
    exit "$rc"
}

if [ "${1:-}" = "--feed-unlock" ]; then
    acquire_patch_lock || exit 1
    log "Removing immutable flags from feed files and plugins tree..."
    if ! feed_unlock_all; then
        log "Error: Could not remove all immutable flags"
        exit 1
    fi
    log "Feed unlock finished"
    exit 0
fi

if [ "${1:-}" = "--feed-lock" ]; then
    acquire_patch_lock || exit 1
    log "Applying immutable flags to feed files and plugins tree..."
    if ! feed_lock_all; then
        log "Error: Could not apply all immutable flags"
        exit 1
    fi
    log "Feed lock finished"
    exit 0
fi

if [ "${1:-}" = "--plugin-set" ]; then
    value="${2:-}"
    if ! validate_plugin_set_digits "$value"; then
        log "Error: --plugin-set requires a 12-digit feed id (YYYYMMDDHHMM)"
        exit 1
    fi
    export NESSUS_PLUGIN_SET="$value"
    shift 2
fi

if [ "${1:-}" = "--version" ]; then
    echo "patch.sh v4 (atomic feed write, scoped immutable locks)"
    exit 0
fi

acquire_patch_lock || exit 1

if ! mkdirs_exist; then
    log "Fatal: Nessus data directory not found: $NESSUS_DATA_DIR"
    exit 1
fi

PATCH_PREVIOUSLY_LOCKED=0
if files_are_locked; then
    PATCH_PREVIOUSLY_LOCKED=1
fi
trap on_exit EXIT

if ! PLUGIN_SET=$(get_plugin_set) || [ -z "$PLUGIN_SET" ]; then
    log "Fatal: Could not determine plugin set"
    exit 1
fi

if ! validate_plugin_set_digits "$PLUGIN_SET"; then
    log "Fatal: Invalid plugin set: $PLUGIN_SET"
    exit 1
fi

PATCH_BODY="PLUGIN_SET = \"$PLUGIN_SET\";
PLUGIN_FEED = \"ProfessionalFeed (Direct)\";
PLUGIN_FEED_TRANSPORT = \"Tenable Network Security Lightning\";"

if ! feed_unlock_files; then
    log "Fatal: Could not unlock plugin files before patching"
    exit 1
fi

for target in "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT"; do
    install_feed_file "$target" || exit 1
done

if [ -d "$NESSUS_PLUGIN_DIR" ]; then
    install_feed_file "$PLUGIN_FEED_LIB" || exit 1
else
    log "Skipping $PLUGIN_FEED_LIB: plugin directory not present"
fi

if ! feed_lock_primary; then
    log "Fatal: Could not lock feed files"
    exit 1
fi

if tree_is_locked; then
    mark_feed_immutable
else
    if ! feed_lock_tree; then
        log "Error: feed patched, but plugin tree immutable lock failed"
        : > "$FEED_LOCK_FAILED_STATE" 2>/dev/null || true
        exit 3
    fi
fi

rm -f "$FEED_LOCK_FAILED_STATE" 2>/dev/null || true
log "Patch applied (plugin set: $PLUGIN_SET)"
trap - EXIT
exit 0
