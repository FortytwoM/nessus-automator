#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
. "$ROOT_DIR/scripts/compose-lib.sh"
cd "$ROOT_DIR"

if [ "$#" -ne 2 ] || [ "$2" != "--yes" ]; then
    echo "Usage: $0 <backup.tar.gz> --yes" >&2
    echo "This permanently replaces the current Nessus persistent data." >&2
    exit 2
fi

case "$1" in
    *.tar.gz) ;;
    *)
        echo "[restore] Error: backup filename must end with .tar.gz" >&2
        exit 2
        ;;
esac

ARCHIVE_DIR=$(cd "$(dirname "$1")" 2>/dev/null && pwd) || {
    echo "[restore] Error: backup directory does not exist" >&2
    exit 1
}
ARCHIVE_FILE=$(basename "$1")
BACKUP_NAME="${ARCHIVE_FILE%.tar.gz}"
MANIFEST_FILE="${BACKUP_NAME}.manifest.json"
CHECKSUM_FILE="${BACKUP_NAME}.sha256"

for file in "$ARCHIVE_FILE" "$MANIFEST_FILE" "$CHECKSUM_FILE"; do
    [ -f "$ARCHIVE_DIR/$file" ] || {
        echo "[restore] Error: missing backup file: $ARCHIVE_DIR/$file" >&2
        exit 1
    }
done

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nessus-restore.XXXXXX")
NESSUS_WAS_RUNNING=0
GATEWAY_WAS_RUNNING=0
GATEWAY_STOPPED=0
NESSUS_STOPPED=0
DATA_REPLACED=0
STARTED_AFTER_REPLACE=0

cleanup_stage() {
    rm -rf "$STAGE_DIR"
}

[ -n "$(compose ps --status running -q nessus 2>/dev/null)" ] \
    && NESSUS_WAS_RUNNING=1
[ -n "$(compose ps --status running -q gateway 2>/dev/null)" ] \
    && GATEWAY_WAS_RUNNING=1

restore_after_failure() {
    local result=$?
    trap - EXIT INT TERM
    cleanup_stage

    if [ "$result" -eq 0 ]; then
        exit 0
    fi
    if [ "$STARTED_AFTER_REPLACE" -eq 1 ]; then
        echo "[restore] Restore failed after service start; stopping stack" >&2
        compose stop gateway nessus || true
    fi
    if [ "$DATA_REPLACED" -eq 0 ]; then
        echo "[restore] Restore failed before data replacement; restarting previous services" >&2
        if [ "$NESSUS_STOPPED" -eq 1 ] && [ "$NESSUS_WAS_RUNNING" -eq 1 ]; then
            compose up -d nessus || true
        fi
        if [ "$GATEWAY_STOPPED" -eq 1 ] && [ "$GATEWAY_WAS_RUNNING" -eq 1 ]; then
            compose up -d gateway || true
        fi
    else
        echo "[restore] Restore failed after data replacement; services remain stopped" >&2
    fi
    exit "$result"
}

trap restore_after_failure EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[restore] Staging and revalidating backup files..."
cp -p "$ARCHIVE_DIR/$ARCHIVE_FILE" "$STAGE_DIR/$ARCHIVE_FILE"
cp -p "$ARCHIVE_DIR/$MANIFEST_FILE" "$STAGE_DIR/$MANIFEST_FILE"
cp -p "$ARCHIVE_DIR/$CHECKSUM_FILE" "$STAGE_DIR/$CHECKSUM_FILE"
chmod 700 "$STAGE_DIR"
chmod 600 "$STAGE_DIR/$ARCHIVE_FILE" "$STAGE_DIR/$MANIFEST_FILE" "$STAGE_DIR/$CHECKSUM_FILE"

export ARCHIVE_FILE MANIFEST_FILE CHECKSUM_FILE
compose_run --rm --no-deps \
    -v "$(compose_bind "$STAGE_DIR" /backup ro)" \
    -v "$(compose_bind "$ROOT_DIR/scripts" /maintenance ro)" \
    --entrypoint python3 \
    nessus /maintenance/backup-tools.py validate \
    --archive "/backup/$ARCHIVE_FILE" \
    --manifest "/backup/$MANIFEST_FILE" \
    --checksum "/backup/$CHECKSUM_FILE"

echo "[restore] Stopping gateway and Nessus..."
GATEWAY_STOPPED=1
compose stop gateway
NESSUS_STOPPED=1
compose stop nessus

echo "[restore] Unlocking current plugin data..."
compose_run --rm --no-deps \
    --entrypoint /usr/local/bin/patch.sh \
    nessus --feed-unlock

echo "[restore] Extracting into a staging directory on the volume..."
# Container script must expand its own environment, not the host shell.
# shellcheck disable=SC2016
compose_run --rm --no-deps \
    -e ARCHIVE_FILE \
    -v "$(compose_bind "$STAGE_DIR" /backup ro)" \
    --entrypoint /bin/bash \
    nessus -c '
set -euo pipefail
root=/opt/nessus
staging="$root/.restore-staging"
previous="$root/.restore-previous"

restore_previous() {
    echo "[restore] Rolling live volume back from staging swap" >&2
    mkdir -p "$previous"
    for path in "$root"/* "$root"/.[!.]* "$root"/..?*; do
        [ -e "$path" ] || continue
        case "$(basename "$path")" in
            .restore-staging|.restore-previous) continue ;;
        esac
        rm -rf "$path"
    done
    for path in "$previous"/* "$previous"/.[!.]* "$previous"/..?*; do
        [ -e "$path" ] || continue
        mv "$path" "$root/"
    done
}

rm -rf "$staging" "$previous"
mkdir -p "$staging"
tar --extract --gzip --numeric-owner --same-owner \
    --file "/backup/$ARCHIVE_FILE" --directory "$staging"
[ -x "$staging/sbin/nessuscli" ] && [ -d "$staging/var/nessus" ] || {
    echo "[restore] Error: restored volume layout is incomplete" >&2
    rm -rf "$staging"
    exit 1
}

mkdir -p "$previous"
for path in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [ -e "$path" ] || continue
    case "$(basename "$path")" in
        .restore-staging|.restore-previous) continue ;;
    esac
    mv "$path" "$previous/"
done

if ! {
    for path in "$staging"/* "$staging"/.[!.]* "$staging"/..?*; do
        [ -e "$path" ] || continue
        mv "$path" "$root/"
    done
    [ -x "$root/sbin/nessuscli" ] && [ -d "$root/var/nessus" ]
}; then
    restore_previous
    rm -rf "$staging" "$previous"
    exit 1
fi

rmdir "$staging" 2>/dev/null || rm -rf "$staging"
chattr -i -R "$previous" 2>/dev/null || true
rm -rf "$previous"
'

DATA_REPLACED=1

echo "[restore] Reapplying plugin feed protection..."
compose_run --rm --no-deps \
    --entrypoint /usr/local/bin/patch.sh \
    nessus

STARTED_AFTER_REPLACE=1
echo "[restore] Starting Nessus and gateway..."
compose up -d nessus
compose up -d gateway

trap - EXIT INT TERM
cleanup_stage
echo "[restore] Restore completed from $ARCHIVE_DIR/$ARCHIVE_FILE"
