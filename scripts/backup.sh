#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
. "$ROOT_DIR/scripts/compose-lib.sh"

BACKUP_DIR="${1:-$ROOT_DIR/backups}"
mkdir -p "$BACKUP_DIR"
BACKUP_DIR=$(cd "$BACKUP_DIR" && pwd)
cd "$ROOT_DIR"

stamp=$(date -u '+%Y%m%dT%H%M%SZ')
BACKUP_NAME="nessus-backup-${stamp}"
attempt=0
while ! ( set -C; : > "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" ) 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 20 ]; then
        echo "[backup] Error: could not reserve a unique backup name" >&2
        exit 1
    fi
    BACKUP_NAME="nessus-backup-${stamp}-${attempt}"
done
rm -f "$BACKUP_DIR/${BACKUP_NAME}.tar.gz"

SOURCE_IMAGE_ID=$(compose images -q nessus 2>/dev/null | awk 'NR == 1 {print; exit}')
BACKUP_UID=$(id -u)
BACKUP_GID=$(id -g)
NESSUS_WAS_RUNNING=0
GATEWAY_WAS_RUNNING=0
GATEWAY_STOPPED=0
NESSUS_STOPPED=0

[ -n "$(compose ps --status running -q nessus 2>/dev/null)" ] \
    && NESSUS_WAS_RUNNING=1
[ -n "$(compose ps --status running -q gateway 2>/dev/null)" ] \
    && GATEWAY_WAS_RUNNING=1

restore_services() {
    local result=$?
    trap - EXIT INT TERM

    if [ "$NESSUS_STOPPED" -eq 1 ] && [ "$NESSUS_WAS_RUNNING" -eq 1 ]; then
        echo "[backup] Restarting Nessus..."
        compose up -d nessus || result=1
    fi
    if [ "$GATEWAY_STOPPED" -eq 1 ] && [ "$GATEWAY_WAS_RUNNING" -eq 1 ]; then
        echo "[backup] Restarting gateway..."
        compose up -d gateway || result=1
    fi
    exit "$result"
}

trap restore_services EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[backup] Stopping gateway and Nessus for a consistent snapshot..."
GATEWAY_STOPPED=1
compose stop gateway
NESSUS_STOPPED=1
compose stop nessus

export BACKUP_NAME SOURCE_IMAGE_ID BACKUP_UID BACKUP_GID
# Container script must expand its own environment, not the host shell.
# shellcheck disable=SC2016
compose_run --rm --no-deps \
    -e BACKUP_NAME \
    -e SOURCE_IMAGE_ID \
    -e BACKUP_UID \
    -e BACKUP_GID \
    -v "$(compose_bind "$BACKUP_DIR" /backup)" \
    -v "$(compose_bind "$ROOT_DIR/scripts" /maintenance ro)" \
    --entrypoint /bin/bash \
    nessus -c '
set -euo pipefail
root=/opt/nessus
archive="/backup/${BACKUP_NAME}.tar.gz"
archive_partial="${archive}.partial"
manifest="/backup/${BACKUP_NAME}.manifest.json"
manifest_partial="${manifest}.partial"
checksum="/backup/${BACKUP_NAME}.sha256"
checksum_partial="${checksum}.partial"
trap "rm -f \"${archive_partial}\" \"${manifest_partial}\" \"${checksum_partial}\"" EXIT

[ -x "${root}/sbin/nessuscli" ] && [ -d "${root}/var/nessus" ] || {
    echo "[backup] Error: persistent volume does not contain an installed Nessus" >&2
    exit 1
}

tar --create --gzip --numeric-owner --one-file-system \
    --exclude="./var/nessus/update-snapshots" \
    --file "$archive_partial" --directory "$root" .
python3 /maintenance/backup-tools.py create \
    --root "$root" \
    --archive "$archive_partial" \
    --archive-name "${BACKUP_NAME}.tar.gz" \
    --manifest-output "$manifest_partial" \
    --checksum-output "$checksum_partial" \
    --source-image-id "$SOURCE_IMAGE_ID"

if [ -e "$archive" ] || [ -e "$manifest" ] || [ -e "$checksum" ]; then
    echo "[backup] Error: backup destination already exists" >&2
    exit 1
fi
mv "$archive_partial" "$archive"
mv "$manifest_partial" "$manifest"
mv "$checksum_partial" "$checksum"
chmod 600 "$archive" "$manifest" "$checksum"
chown "${BACKUP_UID}:${BACKUP_GID}" "$archive" "$manifest" "$checksum" 2>/dev/null || true
trap - EXIT
'

echo "[backup] Created:"
echo "  $BACKUP_DIR/$BACKUP_NAME.tar.gz"
echo "  $BACKUP_DIR/$BACKUP_NAME.manifest.json"
echo "  $BACKUP_DIR/$BACKUP_NAME.sha256"
