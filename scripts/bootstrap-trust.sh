#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CERT_DIR="${GATEWAY_CERT_DIR:-$ROOT_DIR/certs}"
CA_DIR="${GATEWAY_CA_PRIVATE_DIR:-$ROOT_DIR/.private-ca}"
BIND_IP="${1:-}"
DNS_NAME="${2:-}"

[ -n "$BIND_IP" ] || {
    echo "Usage: $0 <gateway-ip> [dns-name]" >&2
    exit 2
}
[[ "$BIND_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
    echo "gateway-ip must be IPv4" >&2
    exit 2
}
command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"
mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"

if [ ! -f "$CA_DIR/ca.key.pem" ] || [ ! -f "$CA_DIR/ca.pem" ]; then
    echo "[trust] Creating local Nessus gateway CA"
    openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 3650 \
        -keyout "$CA_DIR/ca.key.pem" \
        -out "$CA_DIR/ca.pem" \
        -subj "/CN=Nessus Gateway Local CA"
    chmod 600 "$CA_DIR/ca.key.pem"
    chmod 644 "$CA_DIR/ca.pem"
fi
cp "$CA_DIR/ca.pem" "$CERT_DIR/ca.pem"
chmod 644 "$CERT_DIR/ca.pem"

if [ -e "$CERT_DIR/cert.pem" ] || [ -e "$CERT_DIR/key.pem" ]; then
    echo "[trust] cert.pem or key.pem already exists; refusing to overwrite" >&2
    exit 1
fi

EXT_FILE=$(mktemp)
CSR_FILE=$(mktemp)
trap 'rm -f "$EXT_FILE" "$CSR_FILE"' EXIT
{
    echo "subjectAltName=IP:${BIND_IP}${DNS_NAME:+,DNS:${DNS_NAME}}"
    echo "extendedKeyUsage=serverAuth"
    echo "keyUsage=digitalSignature,keyEncipherment"
} >"$EXT_FILE"

CN="${DNS_NAME:-$BIND_IP}"
openssl req -new -nodes -newkey rsa:3072 -sha256 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CSR_FILE" \
    -subj "/CN=${CN}"
openssl x509 -req -sha256 -days 365 \
    -in "$CSR_FILE" \
    -CA "$CA_DIR/ca.pem" \
    -CAkey "$CA_DIR/ca.key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/cert.pem" \
    -extfile "$EXT_FILE"
chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo "[trust] Gateway certificate created in $CERT_DIR"
echo "[trust] Install $CERT_DIR/ca.pem in every client trust store before deployment"
