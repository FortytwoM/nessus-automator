#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
APPLY_FIREWALL=0
[ "${1:-}" = "--apply-firewall" ] && APPLY_FIREWALL=1

read_env() {
    local key="$1" line
    [ -r "$ENV_FILE" ] || return 0
    line=$(awk -v key="$key" '
        $0 ~ "^[[:space:]]*" key "=" {
            sub("^[[:space:]]*" key "=", "")
            print
            exit
        }
    ' "$ENV_FILE")
    line="${line%$'\r'}"
    if [[ "$line" == \"*\" && "$line" == *\" ]]; then
        line="${line:1:${#line}-2}"
    elif [[ "$line" == \'*\' && "$line" == *\' ]]; then
        line="${line:1:${#line}-2}"
    fi
    printf '%s' "$line"
}

setting() {
    local key="$1" default="${2:-}" value
    value="${!key:-}"
    [ -n "$value" ] || value=$(read_env "$key")
    printf '%s' "${value:-$default}"
}

fail() {
    printf '[preflight] ERROR: %s\n' "$*" >&2
    exit 1
}

ok() {
    printf '[preflight] OK: %s\n' "$*"
}

[ "$(uname -s)" = "Linux" ] || fail "Linux Docker host is required"
for command in ip ss firewall-cmd openssl docker; do
    command -v "$command" >/dev/null 2>&1 || fail "missing host command: $command"
done

BIND_IP=$(setting GATEWAY_BIND_IP)
ALLOWED_CIDRS=$(setting GATEWAY_ALLOWED_CIDRS)
EXPECTED_MANAGEMENT_IFACE=$(setting GATEWAY_INTERFACE)
SOURCE_IP=$(setting NESSUS_SOURCE_IP)
EXPECTED_SCAN_IFACE=$(setting NESSUS_SCAN_INTERFACE)
ROUTE_PROBE=$(setting NESSUS_ROUTE_PROBE_IP 8.8.8.8)
CERT_DIR=$(setting GATEWAY_CERT_DIR "$ROOT_DIR/certs")
DNS_SERVERS=$(setting NESSUS_DNS_SERVERS)
BACKEND_PORT=$(setting NESSUS_BACKEND_PORT 8835)
MANAGE_PORT=$(setting NESSUS_MANAGE_PORT 8080)

[ -n "$BIND_IP" ] || fail "GATEWAY_BIND_IP is required"
[[ "$BIND_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || fail "GATEWAY_BIND_IP must be a specific IPv4 address"
[ "$BIND_IP" != "0.0.0.0" ] || fail "wildcard gateway bind is forbidden"

MANAGEMENT_IFACE=$(ip -o -4 addr show | awk -v ip="$BIND_IP" '
    { split($4, address, "/"); if (address[1] == ip) { print $2; exit } }
')
[ -n "$MANAGEMENT_IFACE" ] || fail "$BIND_IP is not assigned to this host"
if [ -n "$EXPECTED_MANAGEMENT_IFACE" ] && [ "$MANAGEMENT_IFACE" != "$EXPECTED_MANAGEMENT_IFACE" ]; then
    fail "$BIND_IP is on $MANAGEMENT_IFACE, expected $EXPECTED_MANAGEMENT_IFACE"
fi
ok "gateway bind $BIND_IP is on $MANAGEMENT_IFACE"

if [ -n "$SOURCE_IP" ]; then
    [[ "$SOURCE_IP" != *,* ]] \
        || fail "preflight currently requires one NESSUS_SOURCE_IP"
    ACTUAL_SCAN_IFACE=$(ip -o -4 addr show | awk -v ip="$SOURCE_IP" '
        { split($4, address, "/"); if (address[1] == ip) { print $2; exit } }
    ')
    [ -n "$ACTUAL_SCAN_IFACE" ] || fail "$SOURCE_IP is not assigned to this host"
    [ -n "$EXPECTED_SCAN_IFACE" ] || EXPECTED_SCAN_IFACE="$ACTUAL_SCAN_IFACE"
    [ "$ACTUAL_SCAN_IFACE" = "$EXPECTED_SCAN_IFACE" ] \
        || fail "$SOURCE_IP is on $ACTUAL_SCAN_IFACE, expected $EXPECTED_SCAN_IFACE"
    ROUTE=$(ip route get "$ROUTE_PROBE" from "$SOURCE_IP" 2>&1) \
        || fail "no route to $ROUTE_PROBE from $SOURCE_IP"
    grep -Eq "(^| )dev ${EXPECTED_SCAN_IFACE}( |$)" <<<"$ROUTE" \
        || fail "source route does not use $EXPECTED_SCAN_IFACE: $ROUTE"
    ok "scan source $SOURCE_IP routes via $EXPECTED_SCAN_IFACE"
fi

if [ -n "$DNS_SERVERS" ]; then
    IFS=',' read -r -a dns_server_list <<<"$DNS_SERVERS"
    for dns_server in "${dns_server_list[@]}"; do
        dns_server="${dns_server//[[:space:]]/}"
        [ -n "$dns_server" ] || fail "NESSUS_DNS_SERVERS contains an empty address"
        DNS_ROUTE=$(ip route get "$dns_server" 2>&1) \
            || fail "no route to DNS server $dns_server"
        ok "DNS server $dns_server has a route: $DNS_ROUTE"
    done
fi

if [[ "$CERT_DIR" != /* ]]; then
    CERT_DIR="$ROOT_DIR/${CERT_DIR#./}"
fi
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
CA_FILE="$CERT_DIR/ca.pem"
[ -r "$CERT_FILE" ] || fail "missing readable certificate: $CERT_FILE"
[ -r "$KEY_FILE" ] || fail "missing readable private key: $KEY_FILE"
[ -r "$CA_FILE" ] || fail "missing readable CA bundle: $CA_FILE"
openssl x509 -in "$CERT_FILE" -noout -checkend 86400 >/dev/null \
    || fail "certificate is invalid or expires within 24 hours"
openssl verify -CAfile "$CA_FILE" -untrusted "$CERT_FILE" "$CERT_FILE" >/dev/null \
    || fail "certificate does not verify against ca.pem"
openssl x509 -in "$CERT_FILE" -noout -checkip "$BIND_IP" >/dev/null \
    || fail "certificate SAN does not contain $BIND_IP"
CERT_PUB=$(openssl x509 -in "$CERT_FILE" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)
KEY_PUB=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | sha256sum)
[ "$CERT_PUB" = "$KEY_PUB" ] || fail "certificate and private key do not match"
ok "TLS certificate, key and CA bundle are valid"

port_owner_expected() {
    local port="$1" container="$2"
    ! ss -H -ltn "sport = :$port" | grep -q . && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" = "true" ]
}
port_owner_expected 8834 nessus-gateway || fail "TCP/8834 is occupied unexpectedly"
port_owner_expected "$BACKEND_PORT" nessus || fail "TCP/$BACKEND_PORT is occupied unexpectedly"
port_owner_expected "$MANAGE_PORT" nessus || fail "TCP/$MANAGE_PORT is occupied unexpectedly"
ok "required ports are free or owned by this stack"

if [ "$BIND_IP" != "127.0.0.1" ]; then
    [ -n "$ALLOWED_CIDRS" ] || fail "GATEWAY_ALLOWED_CIDRS is required for a non-loopback bind"
    firewall-cmd --state >/dev/null 2>&1 || fail "firewalld must be running"
    ZONE=$(firewall-cmd --get-zone-of-interface="$MANAGEMENT_IFACE" 2>/dev/null || true)
    [ -n "$ZONE" ] || ZONE=$(firewall-cmd --get-default-zone)

    if [ "$APPLY_FIREWALL" -eq 1 ]; then
        [ "${EUID}" -eq 0 ] || fail "--apply-firewall must run as root"
        firewall-cmd --permanent --zone="$ZONE" --remove-port=8834/tcp >/dev/null 2>&1 || true
        IFS=',' read -r -a cidrs <<<"$ALLOWED_CIDRS"
        for cidr in "${cidrs[@]}"; do
            cidr="${cidr//[[:space:]]/}"
            [ -n "$cidr" ] || continue
            rule="rule family=\"ipv4\" source address=\"$cidr\" port port=\"8834\" protocol=\"tcp\" accept"
            firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$rule" >/dev/null
        done
        firewall-cmd --reload >/dev/null
    fi

    firewall-cmd --zone="$ZONE" --query-port=8834/tcp >/dev/null 2>&1 \
        && fail "unrestricted TCP/8834 rule exists in firewalld zone $ZONE"
    IFS=',' read -r -a cidrs <<<"$ALLOWED_CIDRS"
    for cidr in "${cidrs[@]}"; do
        cidr="${cidr//[[:space:]]/}"
        [ -n "$cidr" ] || continue
        rule="rule family=\"ipv4\" source address=\"$cidr\" port port=\"8834\" protocol=\"tcp\" accept"
        firewall-cmd --zone="$ZONE" --query-rich-rule="$rule" >/dev/null 2>&1 \
            || fail "missing firewalld allow rule for $cidr in zone $ZONE"
    done

    while IFS= read -r existing_rule; do
        [[ "$existing_rule" == *'port port="8834" protocol="tcp"'*accept* ]] || continue
        rule_source=$(sed -n 's/.*source address="\([^"]*\)".*/\1/p' <<<"$existing_rule")
        source_allowed=0
        IFS=',' read -r -a cidrs <<<"$ALLOWED_CIDRS"
        for cidr in "${cidrs[@]}"; do
            [ "$rule_source" = "${cidr//[[:space:]]/}" ] && source_allowed=1
        done
        [ "$source_allowed" -eq 1 ] \
            || fail "unexpected TCP/8834 rich rule in zone $ZONE: $existing_rule"
    done < <(firewall-cmd --zone="$ZONE" --list-rich-rules)

    for service in $(firewall-cmd --zone="$ZONE" --list-services); do
        service_ports=$(firewall-cmd --info-service="$service" 2>/dev/null \
            | awk -F: '/^[[:space:]]*ports:/ {print $2}')
        grep -Eq '(^|[[:space:]])8834/tcp([[:space:]]|$)' <<<"$service_ports" \
            && fail "firewalld service $service exposes TCP/8834 without a source restriction"
    done
    ok "TCP/8834 is restricted by source CIDR in firewalld zone $ZONE"
else
    ok "loopback-only gateway does not require an inbound firewalld rule"
fi

ok "all mandatory checks passed"
