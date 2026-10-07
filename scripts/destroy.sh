#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
. "$ROOT_DIR/scripts/compose-lib.sh"
cd "$ROOT_DIR"

if [ "${1:-}" != "--yes" ] || [ "$#" -ne 1 ]; then
    echo "Usage: $0 --yes" >&2
    echo "This permanently deletes the Nessus database, users, configuration, and plugins." >&2
    exit 2
fi

echo "[destroy] Stopping services..."
compose down --remove-orphans

echo "[destroy] Removing immutable flags from persistent plugin data..."
compose_run --rm --no-deps \
    --entrypoint /usr/local/bin/patch.sh \
    nessus --feed-unlock

echo "[destroy] Removing persistent volumes..."
compose down -v --remove-orphans
echo "[destroy] Nessus persistent data removed"
