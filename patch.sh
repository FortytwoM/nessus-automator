#!/bin/bash

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy

PLUGIN_FEED_FILE="/opt/nessus/var/nessus/plugin_feed_info.inc"
PLUGIN_FEED_DOT="/opt/nessus/var/nessus/.plugin_feed_info.inc"
PLUGIN_FEED_LIB="/opt/nessus/lib/nessus/plugins/plugin_feed_info.inc"
PLUGINS_LIB_DIR="/opt/nessus/lib/nessus/plugins"
PLUGIN_SET_CACHE="/opt/nessus/var/nessus/.plugin_set_last"
PLUGIN_SET_PHP_URL="https://plugins.nessus.org/v2/plugins.php"
FEED_IMMUTABLE_MARKER="/tmp/nessus_feed_immutable"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [patch] $*"
}

feed_unlock() {
    if [ -d "$PLUGINS_LIB_DIR" ]; then
        chattr -i -R "$PLUGINS_LIB_DIR" 2>/dev/null || true
    fi
    chattr -i "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT" "$PLUGIN_FEED_LIB" 2>/dev/null || true
    rm -f "$FEED_IMMUTABLE_MARKER"
}

feed_lock() {
    if ! chattr +i "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT" 2>/dev/null; then
        log "Warning: could not set immutable flag on feed files"
        return 1
    fi
    if [ ! -d "$PLUGINS_LIB_DIR" ]; then
        return 0
    fi
    if chattr +i -R "$PLUGINS_LIB_DIR" 2>/dev/null; then
        chattr -i "$PLUGIN_FEED_LIB" 2>/dev/null || true
        chattr -i "$PLUGINS_LIB_DIR" 2>/dev/null || true
        : > "$FEED_IMMUTABLE_MARKER"
        log "Plugin feed metadata locked"
        return 0
    fi
    log "Warning: could not lock plugins directory with chattr"
    chattr -i "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT" 2>/dev/null || true
    return 1
}

if [ "${1:-}" = "--feed-unlock" ]; then
    log "Removing immutable flags from feed files and plugins tree..."
    feed_unlock
    log "Feed unlock finished"
    exit 0
fi

cache_plugin_set() {
    local value="$1"
    [ -n "$value" ] || return 1
    echo "$value" > "$PLUGIN_SET_CACHE"
}

validate_plugin_set_digits() {
    local value="$1"
    echo "$value" | grep -qE '^[0-9]{12}$'
}

fetch_online_plugin_set() {
    local result=""

    result=$(curl -s -k --connect-timeout 10 --max-time 30 "$PLUGIN_SET_PHP_URL" 2>/dev/null | tr -d '\n\r ' | head -c 32)
    if [ -n "$result" ] && validate_plugin_set_digits "$result"; then
        cache_plugin_set "$result"
        log "Using online plugin set from $PLUGIN_SET_PHP_URL: $result" >&2
        echo "$result"
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
    cache_plugin_set "$value"
    log "Using offline plugin set: $value" >&2
    echo "$value"
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
        content=$(grep -oE 'PLUGIN_SET[[:space:]]*=[[:space:]]*"[0-9]{12}"' "$f" 2>/dev/null | head -1)
        result=$(echo "$content" | grep -oE '[0-9]{12}' | head -1)
        if [ -n "$result" ]; then
            log "Using plugin set from installed feed ($f): $result" >&2
            echo "$result"
            return 0
        fi
    done

    if [ -f "$PLUGIN_SET_CACHE" ]; then
        result=$(tr -d '\r\n ' < "$PLUGIN_SET_CACHE")
        if validate_plugin_set_digits "$result"; then
            log "Using cached plugin set: $result" >&2
            echo "$result"
            return 0
        fi
    fi

    return 1
}

get_plugin_set() {
    if [ "${NESSUS_UPDATE_ONLINE:-0}" = "1" ]; then
        fetch_online_plugin_set
        return $?
    fi
    if [ -n "${NESSUS_PLUGIN_SET:-}" ]; then
        resolve_offline_plugin_set
        return $?
    fi
    if is_offline_plugin_mode; then
        result=$(read_installed_plugin_set) && cache_plugin_set "$result" && echo "$result" && return 0
        log "Error: offline mode requires NESSUS_PLUGIN_SET in .env (from plugins.nessus.org/offline.php)" >&2
        return 1
    fi
    fetch_online_plugin_set
}

if [ "${1:-}" = "--plugin-set" ]; then
    value="${2:-}"
    if [ -z "$value" ] || ! validate_plugin_set_digits "$value"; then
        log "Error: --plugin-set requires a 12-digit feed id (YYYYMMDDHHMM)"
        exit 1
    fi
    cache_plugin_set "$value"
    export NESSUS_PLUGIN_SET="$value"
    shift 2
fi

if [ "${1:-}" = "--version" ]; then
    echo "patch.sh v3 (online: plugins.php, offline: explicit plugin_set)"
    exit 0
fi

feed_unlock

PLUGIN_SET=$(get_plugin_set)
if [ $? -ne 0 ] || [ -z "$PLUGIN_SET" ]; then
    log "Fatal: Could not determine plugin set"
    exit 1
fi

PATCH_BODY="PLUGIN_SET = \"$PLUGIN_SET\";
PLUGIN_FEED = \"ProfessionalFeed (Direct)\";
PLUGIN_FEED_TRANSPORT = \"Tenable Network Security Lightning\";"

printf '%s\n' "$PATCH_BODY" > "$PLUGIN_FEED_FILE" || { log "Error: Failed to write $PLUGIN_FEED_FILE"; exit 1; }

cp -f "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_DOT" || { log "Error: Failed to copy to $PLUGIN_FEED_DOT"; exit 1; }
mkdir -p "$(dirname "$PLUGIN_FEED_LIB")"
cp -f "$PLUGIN_FEED_FILE" "$PLUGIN_FEED_LIB" || { log "Error: Failed to copy to $PLUGIN_FEED_LIB"; exit 1; }

log "Patch applied (plugin set: $PLUGIN_SET)"
feed_lock || true
