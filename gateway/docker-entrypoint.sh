#!/bin/sh
set -e

CERT_DIR=/etc/nginx/certs
CERT_FILE="${CERT_DIR}/cert.pem"
KEY_FILE="${CERT_DIR}/key.pem"
CA_FILE="${GATEWAY_CA_FILE:-${CERT_DIR}/ca.pem}"
NESSUS_BACKEND_HOST="${NESSUS_BACKEND_HOST:-127.0.0.1}"
NESSUS_BACKEND_PORT="${NESSUS_BACKEND_PORT:-8835}"
NESSUS_MANAGE_HOST="${NESSUS_MANAGE_HOST:-127.0.0.1}"
NESSUS_MANAGE_PORT="${NESSUS_MANAGE_PORT:-8080}"
GATEWAY_BIND_IP="${GATEWAY_BIND_IP:-127.0.0.1}"
GATEWAY_ALLOWED_CIDRS="${GATEWAY_ALLOWED_CIDRS:-}"
GATEWAY_LISTEN_IP="$GATEWAY_BIND_IP"
GATEWAY_MAX_BODY_SIZE="${GATEWAY_MAX_BODY_SIZE:-1024m}"

case "$NESSUS_BACKEND_PORT" in
    *[!0-9]*|'')
        echo "[gateway] Error: NESSUS_BACKEND_PORT must be a number" >&2
        exit 1
        ;;
esac
case "$NESSUS_MANAGE_PORT" in
    *[!0-9]*|'')
        echo "[gateway] Error: NESSUS_MANAGE_PORT must be a number" >&2
        exit 1
        ;;
esac
if [ "$NESSUS_BACKEND_PORT" -lt 1 ] || [ "$NESSUS_BACKEND_PORT" -gt 65535 ] \
    || [ "$NESSUS_BACKEND_PORT" -eq 8834 ]; then
    echo "[gateway] Error: backend port must be 1-65535 and cannot be 8834" >&2
    exit 1
fi
if [ "$NESSUS_MANAGE_PORT" -lt 1 ] || [ "$NESSUS_MANAGE_PORT" -gt 65535 ] \
    || [ "$NESSUS_MANAGE_PORT" -eq 8834 ] \
    || [ "$NESSUS_MANAGE_PORT" -eq "$NESSUS_BACKEND_PORT" ]; then
    echo "[gateway] Error: manage port must be 1-65535 and distinct from gateway/backend ports" >&2
    exit 1
fi
if ! echo "$NESSUS_BACKEND_HOST" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
    echo "[gateway] Error: NESSUS_BACKEND_HOST is invalid" >&2
    exit 1
fi
if ! echo "$NESSUS_MANAGE_HOST" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
    echo "[gateway] Error: NESSUS_MANAGE_HOST is invalid" >&2
    exit 1
fi

case "$GATEWAY_BIND_IP" in
    0.0.0.0|::|'')
        echo "[gateway] Error: GATEWAY_BIND_IP must be a specific management IP" >&2
        exit 1
        ;;
esac
if ! echo "$GATEWAY_BIND_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    echo "[gateway] Error: GATEWAY_BIND_IP must be a specific IPv4 address" >&2
    exit 1
fi
if ! ip -o addr show | awk '{sub(/\/.*/, "", $4); print $4}' | grep -Fxq "$GATEWAY_BIND_IP"; then
    echo "[gateway] Error: GATEWAY_BIND_IP=${GATEWAY_BIND_IP} is not assigned to this host" >&2
    exit 1
fi

if [ "$GATEWAY_BIND_IP" = "127.0.0.1" ] \
    && grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
    GATEWAY_LISTEN_IP=0.0.0.0
    echo "[gateway] Docker Desktop detected; listening on 0.0.0.0:8834 for localhost publish"
fi

ACCESS_FILE=/etc/nginx/gateway-allow.conf
if [ "$GATEWAY_BIND_IP" = "127.0.0.1" ]; then
    {
        printf 'allow 127.0.0.0/8;\n'
        # Docker Desktop publishes localhost through a bridge proxy whose
        # source address is a private VM IP, not 127.0.0.1.
        if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
            printf 'allow 10.0.0.0/8;\nallow 172.16.0.0/12;\nallow 192.168.0.0/16;\nallow ::1;\n'
        fi
        printf 'deny all;\n'
    } >"$ACCESS_FILE"
else
    if [ -z "$GATEWAY_ALLOWED_CIDRS" ]; then
        echo "[gateway] Error: GATEWAY_ALLOWED_CIDRS is required for a non-loopback bind" >&2
        exit 1
    fi
    if ! echo "$GATEWAY_ALLOWED_CIDRS" | grep -Eq '^[0-9.,/[:space:]]+$'; then
        echo "[gateway] Error: GATEWAY_ALLOWED_CIDRS contains invalid characters" >&2
        exit 1
    fi
    : >"$ACCESS_FILE"
    old_ifs=$IFS
    IFS=','
    for cidr in $GATEWAY_ALLOWED_CIDRS; do
        cidr=$(echo "$cidr" | tr -d '[:space:]')
        [ -n "$cidr" ] && printf 'allow %s;\n' "$cidr" >>"$ACCESS_FILE"
    done
    IFS=$old_ifs
    printf 'allow %s/32;\ndeny all;\n' "$GATEWAY_BIND_IP" >>"$ACCESS_FILE"
fi

case "$GATEWAY_MAX_BODY_SIZE" in
    *[!0-9kKmMgG]*|'')
        echo "[gateway] Error: invalid GATEWAY_MAX_BODY_SIZE=${GATEWAY_MAX_BODY_SIZE}" >&2
        exit 1
        ;;
esac

if [ ! -r "$CERT_FILE" ] || [ ! -r "$KEY_FILE" ]; then
    echo "[gateway] Error: mount a stable cert.pem and key.pem read-only at ${CERT_DIR}" >&2
    exit 1
fi
if [ ! -r "$CA_FILE" ]; then
    echo "[gateway] Error: trusted CA bundle is not readable: ${CA_FILE}" >&2
    exit 1
fi
if ! openssl x509 -in "$CERT_FILE" -noout -checkend 86400 >/dev/null 2>&1; then
    echo "[gateway] Error: TLS certificate is invalid or expires within 24 hours" >&2
    exit 1
fi
if ! openssl pkey -in "$KEY_FILE" -noout -check >/dev/null 2>&1; then
    echo "[gateway] Error: TLS private key is invalid" >&2
    exit 1
fi

NGINX_RESOLVER=""
if echo "${NESSUS_BACKEND_HOST}${NESSUS_MANAGE_HOST}" | grep -Eq '[A-Za-z]'; then
    NGINX_RESOLVER="resolver 127.0.0.11 valid=10s ipv6=off;"
fi

sed -i "s/__NESSUS_BACKEND_HOST__/${NESSUS_BACKEND_HOST}/g" /etc/nginx/nginx.conf
sed -i "s/__NESSUS_BACKEND_PORT__/${NESSUS_BACKEND_PORT}/g" /etc/nginx/nginx.conf
sed -i "s/__NESSUS_MANAGE_HOST__/${NESSUS_MANAGE_HOST}/g" /etc/nginx/nginx.conf
sed -i "s/__NESSUS_MANAGE_PORT__/${NESSUS_MANAGE_PORT}/g" /etc/nginx/nginx.conf
sed -i "s/__GATEWAY_BIND_IP__/${GATEWAY_LISTEN_IP}/g" /etc/nginx/nginx.conf
sed -i "s/__GATEWAY_MAX_BODY_SIZE__/${GATEWAY_MAX_BODY_SIZE}/g" /etc/nginx/nginx.conf
sed -i "s|__NGINX_RESOLVER__|${NGINX_RESOLVER}|" /etc/nginx/nginx.conf

echo "[gateway] Starting nginx reverse proxy on ${GATEWAY_LISTEN_IP}:8834"
echo "[gateway]   /        -> Nessus UI/API (https://${NESSUS_BACKEND_HOST}:${NESSUS_BACKEND_PORT})"
echo "[gateway]   /manage/ -> Operator API (http://${NESSUS_MANAGE_HOST}:${NESSUS_MANAGE_PORT})"

exec nginx -g 'daemon off;'
