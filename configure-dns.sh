#!/bin/bash
set -euo pipefail

# shellcheck source=/dev/null
[ -f /usr/local/bin/nessus-config.sh ] && . /usr/local/bin/nessus-config.sh

servers="${NESSUS_DNS_SERVERS:-}"
search_domains="${NESSUS_DNS_SEARCH:-}"
resolv_conf="${NESSUS_RESOLV_CONF:-/etc/resolv.conf}"

[ -n "$servers" ] || [ -n "$search_domains" ] || exit 0

tmp_file=$(mktemp)
trap 'rm -f "$tmp_file"' EXIT

python3 /usr/local/bin/configure-dns.py \
    --source "$resolv_conf" \
    --output "$tmp_file" \
    --servers "$servers" \
    --search "$search_domains"

cat "$tmp_file" > "$resolv_conf"
echo "[dns] Resolver configured: servers=$(awk '/^nameserver / {printf "%s%s", sep, $2; sep=","}' "$resolv_conf")${search_domains:+, search=${search_domains}}"
