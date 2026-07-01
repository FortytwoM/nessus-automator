#!/bin/bash

LOCK_FILE="/tmp/nessus_update.lock"
MANAGE_API_PID=""

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-proxy.sh ] && . /usr/local/bin/nessus-proxy.sh && nessus_export_proxy
# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-users.sh ] && . /usr/local/bin/nessus-users.sh

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
    curl -sL -k https://localhost:8834/server/status 2>/dev/null
}

# /server/status JSON may use spaces after ":"; naive cut/grep breaks pluginData / pluginSet checks.
status_plugin_data() {
    echo "$1" | sed -n 's/.*"pluginData"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' | head -1
}

status_plugin_set() {
    echo "$1" | sed -n 's/.*"pluginSet"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

get_status_field() {
    local field="$1"
    get_status | grep -o "\"$field\":[^,}]*" | cut -d: -f2 | tr -d '"' | head -1
}

wait_for_ready() {
    local max_wait="${1:-${NESSUS_READY_TIMEOUT:-1800}}"
    local waited=0
    local last_progress=""

    while [ $waited -lt $max_wait ]; do
        local full_status=$(get_status)
        local engine_progress=$(echo "$full_status" | grep -o '"engine_status":{[^}]*}' | grep -o '"progress":[0-9]*' | cut -d: -f2)
        local engine_state=$(echo "$full_status" | grep -o '"engine_status":{[^}]*}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        local plugin_data
        plugin_data=$(status_plugin_data "$full_status")

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
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s -f https://localhost:8834/server/status > /dev/null 2>&1; then
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
    if [ -n "${NESSUS_DEB_PATH:-}" ] && [ -f "$NESSUS_DEB_PATH" ]; then
        printf '%s' "$NESSUS_DEB_PATH"
        return 0
    fi

    local mount_dir="/mnt/nessus"
    if [ -d "$mount_dir" ]; then
        local deb_files=()
        local f
        for f in "$mount_dir"/*.deb; do
            [ -f "$f" ] || continue
            deb_files+=("$f")
        done
        if [ "${#deb_files[@]}" -eq 1 ]; then
            printf '%s' "${deb_files[0]}"
            return 0
        fi
        if [ "${#deb_files[@]}" -gt 1 ]; then
            log "Warning: Multiple .deb files in $mount_dir; set NESSUS_DEB_PATH to choose one"
        fi
    fi

    return 1
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
        deb_file="/tmp/nessus.deb"
        downloaded_deb=1
        log "Downloading Nessus from $NESSUS_DEB_URL"
        wget -q --no-check-certificate -O "$deb_file" "$NESSUS_DEB_URL" || {
            log "Error: Download failed"
            return 1
        }
    else
        log "Fetching latest Nessus download URL..."

        api_response=$(curl -s --connect-timeout 30 --max-time 120 -w "%{http_code}" https://www.tenable.com/downloads/api/v2/pages/nessus 2>/dev/null)
        http_code=${api_response: -3}
        body=${api_response:: -3}

        if [ "$http_code" != "200" ] || [ -z "$body" ]; then
            log "Error: Tenable API HTTP $http_code"
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
            return 1
        fi

        deb_file="/tmp/nessus.deb"
        downloaded_deb=1
        log "Downloading Nessus from $download_url"
        wget -q --no-check-certificate -O "$deb_file" "$download_url" || {
            log "Error: Download failed"
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
    echo ""
    log "Shutting down Nessus gracefully..."
    if [ -n "$MANAGE_API_PID" ] && kill -0 "$MANAGE_API_PID" 2>/dev/null; then
        kill "$MANAGE_API_PID" 2>/dev/null || true
    fi
    stop_nessus
    exit 0
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

echo ""
echo "=== Starting Nessus Container ==="
echo ""

validate_credentials

mkdir -p /opt/nessus/var/nessus
mkdir -p /opt/nessus/var/nessus/incoming

if ! install_nessus; then
    log "Fatal: Installation failed"
    exit 1
fi

if [ ! -f /opt/nessus/var/nessus/global.db ] || [ ! -s /opt/nessus/var/nessus/global.db ]; then
    log "Initializing database..."
    start_nessus
    wait_for_nessus 120 || { log "Error: DB init failed"; exit 1; }
    sleep 5
    stop_nessus
    log "Database: ready"
else
    log "Applying patch..."
    /usr/local/bin/patch.sh 2>&1 || true
    stop_nessus
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

start_operator_api

nessus_load_api_credentials

/usr/local/bin/configure-nessus.sh
if ! pgrep -f "nessus-service" > /dev/null 2>&1; then
    start_nessus
    wait_for_nessus || exit 1
fi

UPDATE_FLAG="/opt/nessus/var/nessus/.update_completed"

if has_update_source; then
    if [ ! -f "$UPDATE_FLAG" ] || /usr/local/bin/update.sh --feed-changed; then
        if /usr/local/bin/update.sh; then
            log "Plugin bootstrap/update completed"
        else
            log "Warning: Plugin update failed"
        fi
    elif [ -f "$UPDATE_FLAG" ]; then
        log "Plugins: cached (feed unchanged)"
        stop_nessus
        /usr/local/bin/patch.sh 2>&1 || true
    fi
elif [ -f "$UPDATE_FLAG" ]; then
    log "Plugins: cached"
    stop_nessus
    /usr/local/bin/patch.sh 2>&1 || true
fi

if ! pgrep -f "nessus-service" > /dev/null; then
    start_nessus
    wait_for_nessus || exit 1
fi

log "Waiting for Nessus to be fully ready (timeout ${NESSUS_READY_TIMEOUT:-1800}s)..."
wait_for_ready "${NESSUS_READY_TIMEOUT:-1800}"

parse_status() {
    local s="$1"
    plugin_set=$(status_plugin_set "$s")
    plugin_data=$(status_plugin_data "$s")
}

status=$(get_status)
parse_status "$status"

if [ "$plugin_data" != "true" ] && [ -f "$UPDATE_FLAG" ]; then
    log "Plugins not loaded, restarting with patch..."
    stop_nessus
    /usr/local/bin/patch.sh 2>&1 || true
    start_nessus
    wait_for_nessus || exit 1
    wait_for_ready "${NESSUS_READY_RETRY_TIMEOUT:-600}"
    status=$(get_status)
    parse_status "$status"
fi

display_url=$(get_display_url)

echo ""
echo "========================================="
echo "           NESSUS IS READY"
echo "========================================="
echo "  URL:      $display_url"
echo "  User:     ${NESSUS_USERNAME:-admin}"
if [ "$plugin_data" = "true" ]; then
    if [ -n "$plugin_set" ]; then
        echo "  Plugins:  Loaded ($plugin_set)"
    else
        echo "  Plugins:  Loaded"
    fi
else
    echo "  Plugins:  Not loaded"
fi
echo "========================================="
echo ""

# Operator API already started earlier; ensure it is still running before the watchdog loop.
start_operator_api

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
