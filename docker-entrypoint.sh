#!/bin/bash

LOCK_FILE="/tmp/nessus_update.lock"
MANAGE_API_PID=""
BOOTSTRAP_PID=""

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh
if ! /usr/local/bin/configure-dns.sh; then
    echo "[dns] Fatal: resolver configuration failed" >&2
    exit 1
fi
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-users.sh ] && . /usr/local/bin/nessus-users.sh

mkdir -p "${NESSUS_DOWNLOAD_DIR}" || {
    echo "Error: Cannot create NESSUS_DOWNLOAD_DIR=${NESSUS_DOWNLOAD_DIR}" >&2
    exit 1
}
chmod 700 "${NESSUS_DOWNLOAD_DIR}" || exit 1

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

get_display_url() {
    local san="${NESSUS_CERT_SAN:-}"
    if [ -n "$san" ]; then
        local first_san
        first_san=$(echo "$san" | cut -d',' -f1 | xargs)
        echo "https://${first_san}:8834"
    else
        echo "https://localhost:8834"
    fi
}

get_status() {
    curl -sL -k "${NESSUS_API_BASE}/server/status" 2>/dev/null
}

status_field() {
    local status="$1" field="$2"
    printf '%s' "$status" | /usr/local/bin/nessus-status.py --field "$field" 2>/dev/null
}

wait_for_ready() {
    local max_wait="${1:-${NESSUS_READY_TIMEOUT:-1800}}"
    local waited=0
    local last_progress=""

    while [ "$waited" -lt "$max_wait" ]; do
        local full_status engine_progress engine_state plugin_data
        full_status=$(get_status)
        engine_progress=$(status_field "$full_status" engine_progress)
        engine_state=$(status_field "$full_status" engine_status)
        plugin_data=$(status_field "$full_status" plugin_data)

        if [ "$engine_state" = "ready" ] && [ "$plugin_data" = "true" ]; then
            return 0
        fi

        if [ -n "$engine_progress" ] && [ "$engine_progress" != "$last_progress" ]; then
            log "  Compiling plugins: $engine_progress%"
            last_progress="$engine_progress"
        fi

        sleep 5
        waited=$((waited + 5))
    done
    log "Warning: wait_for_ready timed out after ${max_wait}s"
    return 1
}

wait_for_nessus() {
    local max_attempts=${1:-60}
    local attempt=0

    log "Waiting for Nessus service to respond..."
    while [ "$attempt" -lt "$max_attempts" ]; do
        if curl -k -s -f "${NESSUS_API_BASE}/server/status" > /dev/null 2>&1; then
            log "  Nessus is responding"
            return 0
        fi
        attempt=$((attempt + 1))
        if [ $((attempt % 6)) -eq 0 ]; then
            log "  Still waiting... (${attempt}/${max_attempts})"
        fi
        sleep 5
    done
    log "Error: Nessus did not respond after $((max_attempts * 5))s"
    return 1
}

wait_for_bootstrap_nessus() {
    local configured_base="$1"
    local max_attempts="${2:-120}"
    local attempt=0
    local base
    local factory_base="https://127.0.0.1:8834"
    local backend_base="https://127.0.0.1:${NESSUS_BACKEND_PORT:-8835}"

    log "Waiting for Nessus database initialization..."
    while [ "$attempt" -lt "$max_attempts" ]; do
        # Fresh Nessus listens on 8834 until configure-nessus.sh sets the backend port.
        for base in "$configured_base" "$factory_base" "$backend_base"; do
            [ -n "$base" ] || continue
            if curl -k -s -f "${base}/server/status" >/dev/null 2>&1; then
                export NESSUS_API_BASE="$base"
                log "  Nessus bootstrap API is responding at ${base}"
                return 0
            fi
        done
        attempt=$((attempt + 1))
        if [ $((attempt % 6)) -eq 0 ]; then
            log "  Still initializing... (${attempt}/${max_attempts})"
        fi
        sleep 5
    done

    log "Error: Nessus bootstrap API did not respond"
    return 1
}

stop_nessus() {
    pkill -f "nessus-service" 2>/dev/null || true
    pkill -f "nessusd" 2>/dev/null || true
    sleep 2

    if pgrep -f "nessus-service|nessusd" > /dev/null 2>&1; then
        log "Warning: Nessus did not stop gracefully, sending SIGKILL"
        pkill -9 -f "nessus-service" 2>/dev/null || true
        pkill -9 -f "nessusd" 2>/dev/null || true
        sleep 2
    fi
}

start_nessus() {
    if pgrep -f "nessus-service" > /dev/null 2>&1; then
        return 0
    fi
    /opt/nessus/sbin/nessus-service -D >/dev/null 2>&1 &
}

create_admin_user() {
    ensure_admin_user "$@"
}

ensure_nessusd_rules() {
    local rules_file="/opt/nessus/etc/nessus/nessusd.rules"
    mkdir -p "$(dirname "$rules_file")"
    if [ ! -f "$rules_file" ] || grep -q "default reject" "$rules_file" 2>/dev/null; then
        log "Setting nessusd.rules (default accept)..."
        echo "default accept" > "$rules_file"
        log "  nessusd.rules: OK"
    fi
}

generate_nessus_cert() {
    local san="${NESSUS_CERT_SAN:-}"
    [ -z "$san" ] && return 0

    local pub_dir="/opt/nessus/com/nessus/CA"
    local marker="/opt/nessus/var/nessus/.cert_san"
    local tmp="/tmp/nessus-certs"

    if [ -f "$marker" ] && [ "$(cat "$marker")" = "$san" ] \
        && [ -f "$pub_dir/servercert.pem" ] && [ -f "$pub_dir/cacert.pem" ] \
        && openssl verify -CAfile "$pub_dir/cacert.pem" "$pub_dir/servercert.pem" >/dev/null 2>&1; then
        log "SSL certificate: up to date"
        return 0
    fi

    log "Generating SSL certificate..."
    mkdir -p "$tmp"

    local alt_names=""
    local idx=1
    IFS=',' read -ra SANS <<< "$san"
    for s in "${SANS[@]}"; do
        s=$(echo "$s" | xargs)
        if echo "$s" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            alt_names="${alt_names}IP.${idx} = ${s}"$'\n'
        else
            alt_names="${alt_names}DNS.${idx} = ${s}"$'\n'
        fi
        idx=$((idx + 1))
    done

    openssl req -new -x509 -days 3650 -nodes \
        -subj "/C=US/ST=NY/L=New York/O=Nessus Users United/OU=Nessus CA/CN=Nessus CA" \
        -keyout "$tmp/cakey.pem" \
        -out "$tmp/cacert.pem" 2>/dev/null || { log "  CA generation: FAILED"; rm -rf "$tmp"; return 1; }

    cat > "$tmp/server.cnf" <<CERTEOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = NY
L = New York
O = Nessus Users United
OU = Nessus Server
CN = Nessus

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
${alt_names}
CERTEOF

    openssl req -new -nodes \
        -config "$tmp/server.cnf" \
        -keyout "$tmp/serverkey.pem" \
        -out "$tmp/server.csr" 2>/dev/null || { log "  Server key: FAILED"; rm -rf "$tmp"; return 1; }

    openssl x509 -req -days 3650 \
        -in "$tmp/server.csr" \
        -CA "$tmp/cacert.pem" \
        -CAkey "$tmp/cakey.pem" \
        -CAcreateserial \
        -extfile "$tmp/server.cnf" \
        -extensions v3_req \
        -out "$tmp/servercert.pem" 2>/dev/null || { log "  Cert signing: FAILED"; rm -rf "$tmp"; return 1; }

    /opt/nessus/sbin/nessuscli import-certs \
        --serverkey="$tmp/serverkey.pem" \
        --servercert="$tmp/servercert.pem" \
        --cacert="$tmp/cacert.pem" >/dev/null 2>&1 || { log "  import-certs: FAILED"; rm -rf "$tmp"; return 1; }

    echo "$san" > "$marker"
    log "  SSL certificate: OK"
    rm -rf "$tmp"
}

resolve_local_deb() {
    local mount_dir="/mnt/nessus"
    local deb_files=() seen="" f candidate=""

    if [ -n "${NESSUS_DEB_PATH:-}" ] && [ -f "$NESSUS_DEB_PATH" ]; then
        printf '%s' "$NESSUS_DEB_PATH"
        return 0
    fi
    if [ -n "${NESSUS_DEB_PATH:-}" ]; then
        log "Warning: NESSUS_DEB_PATH not found: $NESSUS_DEB_PATH (scanning $mount_dir/)"
    fi

    if [ ! -d "$mount_dir" ]; then
        log "Error: $mount_dir is not mounted (check docker-compose volumes)"
        return 1
    fi

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        case " $seen " in
            *" $f "*) continue ;;
        esac
        seen="$seen $f"
        deb_files+=("$f")
    done < <(find "$mount_dir" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | sort)

    if [ "${#deb_files[@]}" -eq 1 ]; then
        printf '%s' "${deb_files[0]}"
        return 0
    fi
    if [ "${#deb_files[@]}" -gt 1 ]; then
        log "Error: Multiple .deb files in $mount_dir; set NESSUS_DEB_PATH to choose one:"
        for f in "${deb_files[@]}"; do
            log "  - $f"
        done
        return 1
    fi

    log "Error: No .deb in $mount_dir (host ./packages/ next to docker-compose.yml)"
    log "  Contents:"
    for candidate in "$mount_dir"/*; do
        [ -e "$candidate" ] || continue
        log "    $(basename "$candidate")"
    done
    return 1
}

nessus_remote_install_allowed() {
    case "${NESSUS_DEB_INSTALL:-}" in
        local|offline) return 1 ;;
    esac
    [ "${NESSUS_PROFILE:-}" = "offline" ] && return 1
    return 0
}

log_local_deb_hint() {
    log "Hint: First install needs a local Nessus .deb package:"
    log "  1. Download Nessus-*-debian10_amd64.deb from your Tenable account"
    log "  2. Put it in ./packages/  (container path: /mnt/nessus/)"
    log "  3. Or set NESSUS_DEB_PATH=/mnt/nessus/Nessus-....deb"
    log "  4. Or set NESSUS_DEB_URL=<direct .deb download URL>"
    log "  Offline profile (NESSUS_PROFILE=offline) never uses the Tenable API."
}

download_nessus_deb() {
    local url="$1"
    local destination="$2"
    local -a download_args=()
    local output

    if [ -n "${NESSUS_DEB_SHA256:-}" ]; then
        download_args=(--sha256 "$NESSUS_DEB_SHA256")
    fi
    output=$(/usr/local/bin/secure-download.py \
        "$url" "$destination" "${download_args[@]}" 2>&1) || {
        log "Error: Secure Nessus package download failed: $output"
        rm -f "$destination"
        return 1
    }
    log "$output"
}

install_nessus() {
    if [ -f /opt/nessus/sbin/nessus-service ]; then
        log "Nessus already installed"
        return 0
    fi

    local deb_file=""
    local downloaded_deb=0

    if deb_file=$(resolve_local_deb); then
        log "Using local Nessus package: $deb_file"
    elif [ -n "${NESSUS_DEB_URL:-}" ]; then
        log "Using NESSUS_DEB_URL from environment"
        deb_file="${NESSUS_DOWNLOAD_DIR}/nessus.deb"
        downloaded_deb=1
        log "Downloading Nessus from configured URL"
        download_nessus_deb "$NESSUS_DEB_URL" "$deb_file" || {
            log "Error: Download failed"
            log_local_deb_hint
            return 1
        }
    elif ! nessus_remote_install_allowed; then
        log "Error: Local Nessus .deb required (remote install disabled)"
        log_local_deb_hint
        return 1
    else
        log "Fetching latest Nessus download URL..."

        api_response=$(curl -s --connect-timeout 30 --max-time 120 -w "%{http_code}" https://www.tenable.com/downloads/api/v2/pages/nessus 2>/dev/null)
        http_code=${api_response: -3}
        body=${api_response:: -3}

        if [ "$http_code" != "200" ] || [ -z "$body" ]; then
            log "Error: Tenable API HTTP $http_code"
            log_local_deb_hint
            return 1
        fi

        local download_url
        download_url=$(printf '%s' "$body" | jq -r '
            .releases.latest
            | ..
            | objects
            | select(.file? and (.file | endswith("debian10_amd64.deb")))
            | .file_url
        ' | head -n 1)

        if [ -z "$download_url" ] || [ "$download_url" = "null" ]; then
            log "Error: Could not parse Nessus download URL from API response"
            log_local_deb_hint
            return 1
        fi

        deb_file="${NESSUS_DOWNLOAD_DIR}/nessus.deb"
        downloaded_deb=1
        log "Downloading Nessus from allowlisted Tenable URL"
        download_nessus_deb "$download_url" "$deb_file" || {
            log "Error: Download failed"
            log_local_deb_hint
            return 1
        }
    fi

    local deb_size
    deb_size=$(stat -c%s "$deb_file" 2>/dev/null || echo 0)
    if [ "$deb_size" -lt 10240 ]; then
        log "Error: Nessus .deb is too small (${deb_size} bytes)"
        [ "$downloaded_deb" -eq 1 ] && rm -f "$deb_file"
        return 1
    fi

    log "Installing Nessus ($(( deb_size / 1024 / 1024 ))MB)..."
    dpkg -i "$deb_file" >/dev/null 2>&1 || apt-get install -f -y >/dev/null 2>&1 || {
        log "Error: dpkg/apt installation failed"
        [ "$downloaded_deb" -eq 1 ] && rm -f "$deb_file"
        return 1
    }

    [ "$downloaded_deb" -eq 1 ] && rm -f "$deb_file"
    log "Nessus installed successfully"
}

has_update_source() {
    [ -n "${NESSUS_UPDATE_URL:-}" ] && return 0
    [ -n "${NESSUS_UPDATE_FILE:-}" ] && [ -f "$NESSUS_UPDATE_FILE" ] && return 0
    [ -f /mnt/nessus/all-2.0.tar.gz ] && return 0
    return 1
}

cleanup() {
    local update_pid="" pid="" attempt=0 active=0

    trap - SIGTERM SIGINT SIGQUIT
    echo ""
    log "Shutting down Nessus gracefully..."
    [ -f "$LOCK_FILE" ] && update_pid=$(cat "$LOCK_FILE" 2>/dev/null || true)

    for pid in "$MANAGE_API_PID" "$BOOTSTRAP_PID" "$update_pid"; do
        case "$pid" in
            ''|*[!0-9]*|"$$") continue ;;
        esac
        if kill -0 "$pid" 2>/dev/null; then
            pkill -TERM -P "$pid" 2>/dev/null || true
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    while [ "$attempt" -lt 120 ]; do
        active=0
        for pid in "$MANAGE_API_PID" "$BOOTSTRAP_PID" "$update_pid"; do
            case "$pid" in
                ''|*[!0-9]*|"$$") continue ;;
            esac
            if kill -0 "$pid" 2>/dev/null \
                && ! ps -o stat= -p "$pid" 2>/dev/null | grep -q '^Z'; then
                active=1
            fi
        done
        [ "$active" -eq 0 ] && break
        sleep 1
        attempt=$((attempt + 1))
    done

    for pid in "$MANAGE_API_PID" "$BOOTSTRAP_PID" "$update_pid"; do
        case "$pid" in
            ''|*[!0-9]*|"$$") continue ;;
        esac
        if kill -0 "$pid" 2>/dev/null; then
            pkill -KILL -P "$pid" 2>/dev/null || true
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    wait "$MANAGE_API_PID" "$BOOTSTRAP_PID" 2>/dev/null || true

    stop_nessus
    if /usr/local/bin/patch.sh --feed-unlock; then
        log "Plugin immutable flags removed for shutdown"
        exit 0
    fi
    log "Error: Could not remove plugin immutable flags during shutdown"
    exit 1
}
trap cleanup SIGTERM SIGINT SIGQUIT

validate_credentials() {
    local password="${NESSUS_PASSWORD:-admin}"

    case "$password" in
        admin|changeme)
            if [ "${NESSUS_ALLOW_DEFAULT_PASSWORD:-0}" != "1" ]; then
                log "Fatal: Refusing to start with default password '${password}'"
                log "Set NESSUS_PASSWORD to a strong value or set NESSUS_ALLOW_DEFAULT_PASSWORD=1 for disposable lab use"
                exit 1
            fi
            log "Warning: default password allowed by NESSUS_ALLOW_DEFAULT_PASSWORD=1"
            ;;
    esac
}

start_operator_api() {
    if [ "${NESSUS_MANAGE_API:-1}" != "1" ]; then
        log "Operator API disabled (NESSUS_MANAGE_API=0)"
        MANAGE_API_PID=""
        return 0
    fi

    if [ -n "$MANAGE_API_PID" ] && kill -0 "$MANAGE_API_PID" 2>/dev/null; then
        return 0
    fi

    /usr/local/bin/start-manage-api.sh &
    MANAGE_API_PID=$!
    log "Operator API process started (pid ${MANAGE_API_PID})"
}

bootstrap_plugins_async() {
    (
        local UPDATE_FLAG="/opt/nessus/var/nessus/.update_completed"
        local READY_FILE="${NESSUS_BOOTSTRAP_READY_FILE:-/tmp/nessus_bootstrap_ready}"
        local status plugin_set plugin_data update_result

        if has_update_source; then
            if [ ! -f "$UPDATE_FLAG" ] || /usr/local/bin/update.sh --feed-changed; then
                log "[bootstrap] Starting plugin update in background..."
                /usr/local/bin/update.sh
                update_result=$?
                case "$update_result" in
                    0)
                        log "[bootstrap] Plugin update completed"
                        ;;
                    2|3)
                        log "[bootstrap] Plugin update deferred; continuing with installed plugins"
                        ;;
                    4)
                        log "[bootstrap] Plugin update failed; previous plugins restored"
                        ;;
                    *)
                        log "[bootstrap] Error: Plugin update failed; scanner remains unhealthy"
                        return 1
                        ;;
                esac
            elif [ -f "$UPDATE_FLAG" ]; then
                log "[bootstrap] Feed unchanged; startup patch already applied"
            fi
        elif [ -f "$UPDATE_FLAG" ]; then
            log "[bootstrap] No update source; startup patch already applied"
        else
            log "[bootstrap] No plugin source configured; checking installed plugins"
        fi

        log "[bootstrap] Waiting for plugin compilation (timeout ${NESSUS_READY_TIMEOUT:-1800}s)..."
        if ! wait_for_ready "${NESSUS_READY_TIMEOUT:-1800}"; then
            log "[bootstrap] Warning: Plugin compilation did not finish within timeout"
            return 1
        fi

        status=$(get_status)
        plugin_data=$(status_field "$status" plugin_data)
        if [ "$plugin_data" != "true" ] && [ -f "$UPDATE_FLAG" ]; then
            log "[bootstrap] Plugins not loaded; retrying patch..."
            stop_nessus
            if [ "${NESSUS_PROFILE:-}" = "offline" ]; then
                /usr/local/bin/patch.sh 2>&1 || true
            else
                NESSUS_UPDATE_ONLINE=1 /usr/local/bin/patch.sh 2>&1 || true
            fi
            start_nessus
            wait_for_ready "${NESSUS_READY_RETRY_TIMEOUT:-600}" || true
        fi

        status=$(get_status)
        plugin_set=$(status_field "$status" plugin_set)
        plugin_data=$(status_field "$status" plugin_data)
        if [ "$plugin_data" = "true" ]; then
            touch "$READY_FILE"
            log "[bootstrap] Plugins ready${plugin_set:+ ($plugin_set)}"
        else
            rm -f "$READY_FILE"
            log "[bootstrap] Error: Plugins still not loaded after bootstrap"
            return 1
        fi
    ) &
    BOOTSTRAP_PID=$!
    log "Plugin bootstrap running in background (pid ${BOOTSTRAP_PID})"
}

print_startup_banner() {
    local display_url

    display_url=$(get_display_url)

    echo ""
    echo "========================================="
    echo "         NESSUS SERVICE STARTED"
    echo "========================================="
    echo "  URL:      $display_url"
    echo "  User:     ${NESSUS_USERNAME:-admin}"
    echo "  Scanner:  Verifying plugins (health remains starting)"
    echo "========================================="
    echo ""
}

echo ""
echo "=== Starting Nessus Container ==="
echo ""

validate_credentials

mkdir -p /opt/nessus/var/nessus
mkdir -p "${NESSUS_MANAGE_UPLOAD_DIR}"
chmod 700 "${NESSUS_MANAGE_UPLOAD_DIR}"

if ! install_nessus; then
    log "Fatal: Installation failed"
    exit 1
fi

configured_api_base="${NESSUS_API_BASE}"
if [ ! -f /opt/nessus/var/nessus/global.db ] || [ ! -s /opt/nessus/var/nessus/global.db ]; then
    log "Initializing database..."
    export NESSUS_API_BASE="https://127.0.0.1:8834"
    start_nessus
else
    log "Applying patch..."
    /usr/local/bin/patch.sh 2>&1 || true
    stop_nessus
fi

if [ ! -f /opt/nessus/var/nessus/.nessus_configured ]; then
    log "Completing initial Nessus database setup..."
    start_nessus
    if ! wait_for_bootstrap_nessus "$configured_api_base" 120; then
        stop_nessus
        exit 1
    fi
    if ! ensure_admin_user log; then
        log "Fatal: Database initialization did not complete"
        stop_nessus
        exit 1
    fi
    stop_nessus
    log "Database: ready"
fi

export NESSUS_API_BASE="$configured_api_base"
if ! /usr/local/bin/configure-nessus.sh --startup; then
    log "Fatal: Failed to configure host networking or scan source IP"
    exit 1
fi

ensure_nessusd_rules
generate_nessus_cert

log "Starting Nessus..."
start_nessus
wait_for_nessus || exit 1

if ! ensure_admin_user log; then
    log "Warning: Admin user setup incomplete, continuing anyway"
    stop_nessus
    start_nessus
    wait_for_nessus || exit 1
fi

rm -f "${NESSUS_BOOTSTRAP_READY_FILE:-/tmp/nessus_bootstrap_ready}"
start_operator_api

nessus_load_api_credentials

print_startup_banner
bootstrap_plugins_async

while true; do
    if [ "${NESSUS_MANAGE_API:-1}" = "1" ]; then
        if [ -z "$MANAGE_API_PID" ] || ! kill -0 "$MANAGE_API_PID" 2>/dev/null; then
            log "Warning: Operator API process not found, restarting..."
            start_operator_api
        fi
    fi

    if ! pgrep -f "nessus-service" > /dev/null 2>&1; then
        if [ -f "$LOCK_FILE" ] && kill -0 "$(cat "$LOCK_FILE" 2>/dev/null)" 2>/dev/null; then
            :
        else
            log "Warning: Nessus process not found, restarting..."
            stop_nessus
            start_nessus
            if ! wait_for_nessus 24; then
                log "Error: Nessus failed to restart, will retry in 30s"
            fi
        fi
    fi
    sleep 30 &
    wait $!
done
