#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
. "$ROOT_DIR/scripts/compose-lib.sh"
cd "$ROOT_DIR"

case "${1:-}" in
    --apply-firewall)
        sudo --preserve-env=ENV_FILE "$ROOT_DIR/scripts/host-preflight.sh" --apply-firewall
        ;;
    "")
        "$ROOT_DIR/scripts/host-preflight.sh"
        ;;
    *)
        echo "Usage: $0 [--apply-firewall]" >&2
        exit 2
        ;;
esac

compose config --quiet
compose build --pull
compose up -d
