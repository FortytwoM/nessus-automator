#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs
SAN="${GATEWAY_CERT_SAN:-localhost,127.0.0.1}"
CN="${GATEWAY_CERT_CN:-localhost}"

mkdir -p "$CERT_DIR"

# subjectAltName for openssl -addext, e.g. DNS:localhost,IP:127.0.0.1
build_san_addext() {
    local part san="" old_ifs
    old_ifs=$IFS
    IFS=','
    for part in $SAN; do
        part=$(echo "$part" | tr -d ' ')
        [ -z "$part" ] && continue
        [ -n "$san" ] && san="${san},"
        if echo "$part" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            san="${san}IP:${part}"
        else
            san="${san}DNS:${part}"
        fi
    done
    IFS=$old_ifs
    printf '%s' "$san"
}

if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    san_addext=$(build_san_addext)
    echo "[gateway] Generating TLS certificate (CN=${CN}, SAN=${SAN})..."
    if ! openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -subj "/CN=${CN}" \
        -addext "subjectAltName=${san_addext}"; then
        echo "[gateway] Error: openssl failed to generate TLS certificate" >&2
        exit 1
    fi
    echo "[gateway] TLS certificate ready"
fi

echo "[gateway] Starting nginx reverse proxy on :8834"
echo "[gateway]   /        -> Nessus UI/API (https://nessus:8834)"
echo "[gateway]   /manage/ -> Operator API (http://nessus:8080)"

exec nginx -g 'daemon off;'
