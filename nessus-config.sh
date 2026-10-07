# Central defaults and profile presets. Sourced by entrypoint and update scripts.
# shellcheck shell=bash

# Trim accidental comment text copied into NESSUS_PROFILE (e.g. "offline — ...")
NESSUS_PROFILE="${NESSUS_PROFILE:-}"
NESSUS_PROFILE="${NESSUS_PROFILE%%[[:space:]]*}"

nessus_apply_profile() {
    case "${NESSUS_PROFILE:-}" in
        offline)
            NESSUS_UPDATE_URL=""
            NESSUS_DEB_INSTALL="${NESSUS_DEB_INSTALL:-local}"
            ;;
        online)
            ;;
        ""|custom)
            ;;
        *)
            echo "[config] Warning: unknown NESSUS_PROFILE='${NESSUS_PROFILE}' (use online, offline, or custom)" >&2
            ;;
    esac
}

nessus_apply_profile

# --- Core (human admin UI login) ---
export NESSUS_USERNAME="${NESSUS_USERNAME:-admin}"
export NESSUS_PASSWORD="${NESSUS_PASSWORD:-admin}"
export NESSUS_ALLOW_DEFAULT_PASSWORD="${NESSUS_ALLOW_DEFAULT_PASSWORD:-0}"

# --- Startup / readiness (seconds) ---
export NESSUS_READY_TIMEOUT="${NESSUS_READY_TIMEOUT:-1800}"
export NESSUS_READY_RETRY_TIMEOUT="${NESSUS_READY_RETRY_TIMEOUT:-600}"
export NESSUS_HEALTH_START_PERIOD="${NESSUS_HEALTH_START_PERIOD:-1800}"
export NESSUS_HEALTH_STRICT="${NESSUS_HEALTH_STRICT:-1}"
export NESSUS_BOOTSTRAP_READY_FILE="${NESSUS_BOOTSTRAP_READY_FILE:-/tmp/nessus_bootstrap_ready}"

# --- Install (.deb) ---
export NESSUS_DEB_URL="${NESSUS_DEB_URL:-}"
export NESSUS_DEB_PATH="${NESSUS_DEB_PATH:-}"
export NESSUS_DEB_SHA256="${NESSUS_DEB_SHA256:-}"
export NESSUS_DEB_INSTALL="${NESSUS_DEB_INSTALL:-}"

# --- Plugins ---
export NESSUS_UPDATE_URL="${NESSUS_UPDATE_URL:-}"
export NESSUS_UPDATE_FILE="${NESSUS_UPDATE_FILE:-}"
export NESSUS_PLUGIN_SET="${NESSUS_PLUGIN_SET:-}"
export NESSUS_DOWNLOAD_DIR="${NESSUS_DOWNLOAD_DIR:-/var/lib/nessus-downloads}"
export NESSUS_DOWNLOAD_MAX_BYTES="${NESSUS_DOWNLOAD_MAX_BYTES:-1073741824}"
export NESSUS_DOWNLOAD_TIMEOUT="${NESSUS_DOWNLOAD_TIMEOUT:-1800}"
export NESSUS_DOWNLOAD_ALLOWED_SCHEMES="${NESSUS_DOWNLOAD_ALLOWED_SCHEMES:-https}"
export NESSUS_DOWNLOAD_ALLOWED_HOSTS="${NESSUS_DOWNLOAD_ALLOWED_HOSTS:-plugins.nessus.org,*.tenable.com}"
export NESSUS_DOWNLOAD_ALLOWED_PORTS="${NESSUS_DOWNLOAD_ALLOWED_PORTS:-443}"

# --- Updates: scan safety before stop (operator triggers update via /manage/v1/update) ---
export NESSUS_UPDATE_WAIT_FOR_SCANS="${NESSUS_UPDATE_WAIT_FOR_SCANS:-14400}"
export NESSUS_UPDATE_SCAN_POLL_INTERVAL="${NESSUS_UPDATE_SCAN_POLL_INTERVAL:-10}"
export NESSUS_UPDATE_SCAN_GRACE_SEC="${NESSUS_UPDATE_SCAN_GRACE_SEC:-3}"
# Writable path (packages mount at /mnt/nessus is read-only in compose).
export NESSUS_UPDATE_HOLD_FILE="${NESSUS_UPDATE_HOLD_FILE:-/opt/nessus/var/nessus/.update_hold}"
export NESSUS_UPDATE_SKIP_SCAN_CHECK="${NESSUS_UPDATE_SKIP_SCAN_CHECK:-0}"
export NESSUS_UPDATE_WINDOW_UTC="${NESSUS_UPDATE_WINDOW_UTC:-}"
export NESSUS_UPDATE_MAX_FEED_AGE_HOURS="${NESSUS_UPDATE_MAX_FEED_AGE_HOURS:-48}"
export NESSUS_UPDATE_RETRY_INITIAL_SECONDS="${NESSUS_UPDATE_RETRY_INITIAL_SECONDS:-300}"
export NESSUS_UPDATE_RETRY_MAX_SECONDS="${NESSUS_UPDATE_RETRY_MAX_SECONDS:-3600}"
export NESSUS_UPDATE_SUCCESS_FILE="${NESSUS_UPDATE_SUCCESS_FILE:-/opt/nessus/var/nessus/.update_success_epoch}"
export NESSUS_UPDATE_ROLLBACK="${NESSUS_UPDATE_ROLLBACK:-1}"
export NESSUS_UPDATE_ROLLBACK_KEEP="${NESSUS_UPDATE_ROLLBACK_KEEP:-2}"
export NESSUS_UPDATE_ROLLBACK_MAX_BYTES="${NESSUS_UPDATE_ROLLBACK_MAX_BYTES:-5368709120}"
export NESSUS_UPDATE_SNAPSHOT_DIR="${NESSUS_UPDATE_SNAPSHOT_DIR:-/opt/nessus/var/nessus/update-snapshots}"

# --- Operator API (/manage/v1/* via gateway; auth = Nessus API keys) ---
export NESSUS_MANAGE_API="${NESSUS_MANAGE_API:-1}"
export NESSUS_MANAGE_BIND="${NESSUS_MANAGE_BIND:-127.0.0.1}"
export NESSUS_MANAGE_PORT="${NESSUS_MANAGE_PORT:-8080}"
export NESSUS_MANAGE_UPLOAD_DIR="${NESSUS_MANAGE_UPLOAD_DIR:-${NESSUS_DOWNLOAD_DIR}/incoming}"
export NESSUS_MANAGE_MAX_UPLOAD_BYTES="${NESSUS_MANAGE_MAX_UPLOAD_BYTES:-1073741824}"

# --- Host networking (gateway :8834 -> local Nessus backend) ---
export NESSUS_BACKEND_PORT="${NESSUS_BACKEND_PORT:-8835}"
export NESSUS_LISTEN_ADDRESS="${NESSUS_LISTEN_ADDRESS:-127.0.0.1}"
export NESSUS_API_BASE="${NESSUS_API_BASE:-https://127.0.0.1:${NESSUS_BACKEND_PORT}}"

# --- TLS ---
export NESSUS_CERT_SAN="${NESSUS_CERT_SAN:-}"

# --- Scan source IP(s) on multi-homed hosts (nessuscli: source_ip) ---
# Comma-separated list; empty = Nessus default (OS routing).
export NESSUS_SOURCE_IP="${NESSUS_SOURCE_IP:-}"

# --- DNS resolver ---
export NESSUS_DNS_SERVERS="${NESSUS_DNS_SERVERS:-}"
export NESSUS_DNS_SEARCH="${NESSUS_DNS_SEARCH:-}"

# --- Outbound proxy (optional) ---
export NESSUS_PROXY="${NESSUS_PROXY:-}"
export NESSUS_HTTP_PROXY="${NESSUS_HTTP_PROXY:-}"
export NESSUS_HTTPS_PROXY="${NESSUS_HTTPS_PROXY:-}"
export NESSUS_ALL_PROXY="${NESSUS_ALL_PROXY:-}"
export NESSUS_NO_PROXY="${NESSUS_NO_PROXY:-localhost,127.0.0.1,::1}"

# --- API auth for scripts: filled by nessus_load_api_credentials() ---
export NESSUS_API_USERNAME="${NESSUS_API_USERNAME:-}"
export NESSUS_API_PASSWORD="${NESSUS_API_PASSWORD:-}"

nessus_load_api_credentials() {
    export NESSUS_API_USERNAME="${NESSUS_USERNAME:-admin}"
    export NESSUS_API_PASSWORD="${NESSUS_PASSWORD:-admin}"
}

nessus_load_api_credentials
