#!/bin/bash
# Regression tests for patch.sh. Uses fake chattr/lsattr so it runs unprivileged
# on any Linux host and does not touch /opt/nessus.
set -u
unset NESSUS_UPDATE_ONLINE NESSUS_PLUGIN_SET NESSUS_PROFILE NESSUS_UPDATE_FILE

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/nessus-patch-test.XXXXXX")
BIN="$T/bin"
STATE="$T/state"
mkdir -p "$BIN" "$STATE" "$T/root/var/nessus" "$T/root/lib/nessus/plugins"
printf 'sample\n' > "$T/root/lib/nessus/plugins/known_CA.inc"
export FAKE_IMMUTABLE_DIR="$STATE"
export FAKE_CHATTR_LOG="$T/chattr.log"
export FAKE_CURL_CALLED="$T/curl_called"

cleanup() {
    rm -rf "$T"
}
trap cleanup EXIT

cat > "$BIN/chattr" <<'EOF'
#!/bin/bash
state="${FAKE_IMMUTABLE_DIR:?}"
op=""
rec=0
paths=()
for arg in "$@"; do
    case "$arg" in
        -R) rec=1 ;;
        +i) op=add ;;
        -i) op=del ;;
        -*) ;;
        *) paths+=("$arg") ;;
    esac
done
printf '%s %s\n' "$op" "$rec" >> "${FAKE_CHATTR_LOG:-/dev/null}"
if [ "$op" = add ] && [ "$rec" = 1 ] && [ "${FAKE_FAIL_TREE:-0}" = 1 ]; then
    exit 1
fi
key() { printf '%s' "$1" | md5sum | cut -d' ' -f1; }
setone() {
    local p="$1" k
    k=$(key "$p")
    if [ "$op" = add ]; then
        : > "$state/$k"
    else
        rm -f "$state/$k"
    fi
}
for p in "${paths[@]}"; do
    if [ "$rec" = 1 ] && [ -d "$p" ]; then
        while IFS= read -r -d '' f; do setone "$f"; done < <(find "$p" -print0)
    else
        setone "$p"
    fi
done
exit 0
EOF

cat > "$BIN/lsattr" <<'EOF'
#!/bin/bash
state="${FAKE_IMMUTABLE_DIR:?}"
path=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *) path="$arg" ;;
    esac
done
k=$(printf '%s' "$path" | md5sum | cut -d' ' -f1)
if [ -f "$state/$k" ]; then
    flags="----i---------e-------"
else
    flags="--------------e-------"
fi
printf '%s %s\n' "$flags" "$path"
EOF

chmod +x "$BIN/chattr" "$BIN/lsattr"
export PATH="$BIN:$PATH"
export NESSUS_ROOT="$T/root"
export NESSUS_DATA_DIR="$T/root/var/nessus"
export NESSUS_PLUGIN_DIR="$T/root/lib/nessus/plugins"
export NESSUS_FEED_IMMUTABLE_MARKER="$T/feed_marker"
export NESSUS_PATCH_LOCK_FILE="$T/patch.lock"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

run_patch() {
    bash "$ROOT_DIR/patch.sh" "$@"
}

is_immutable() {
    "$BIN/lsattr" -d "$1" | awk '{print $1}' | grep -q i
}

echo "== first patch =="
run_patch --plugin-set 202601010101 || fail "first patch rc"
grep -qx 'PLUGIN_SET = "202601010101";' "$T/root/var/nessus/plugin_feed_info.inc" || fail "main content"
cmp -s "$T/root/var/nessus/plugin_feed_info.inc" "$T/root/var/nessus/.plugin_feed_info.inc" || fail "dot differs"
cmp -s "$T/root/var/nessus/plugin_feed_info.inc" "$T/root/lib/nessus/plugins/plugin_feed_info.inc" || fail "lib differs"
is_immutable "$T/root/var/nessus/plugin_feed_info.inc" || fail "main not locked"
is_immutable "$T/root/var/nessus/.plugin_feed_info.inc" || fail "dot not locked"
is_immutable "$T/root/lib/nessus/plugins/known_CA.inc" || fail "sample not locked"
if is_immutable "$T/root/lib/nessus/plugins/plugin_feed_info.inc"; then
    fail "lib should stay writable"
fi
if is_immutable "$T/root/lib/nessus/plugins"; then
    fail "plugin dir should stay writable"
fi
[ -f "$T/feed_marker" ] || fail "tmp marker missing"
[ -f "$T/root/var/nessus/.feed_immutable" ] || fail "persistent marker missing"
[ "$(grep -c '^add 1$' "$T/chattr.log")" -eq 1 ] || fail "unexpected recursive lock count"

echo "== idempotent patch =="
m1=$(stat -c %Y "$T/root/var/nessus/plugin_feed_info.inc")
sleep 1
NESSUS_PLUGIN_SET=202601010101 run_patch >"$T/out2" 2>&1 || fail "second patch rc"
grep -q "unchanged" "$T/out2" || fail "not idempotent"
m2=$(stat -c %Y "$T/root/var/nessus/plugin_feed_info.inc")
[ "$m1" = "$m2" ] || fail "file rewritten unnecessarily"
[ "$(grep -c '^add 1$' "$T/chattr.log")" -eq 1 ] || fail "recursive lock repeated on idempotent patch"

echo "== installed feed preferred over online =="
cat > "$BIN/curl" <<'EOF'
#!/bin/bash
: > "${FAKE_CURL_CALLED:?}"
exit 1
EOF
chmod +x "$BIN/curl"
run_patch >"$T/out_online" 2>&1 || fail "installed-feed preference rc"
grep -q "Using plugin set from installed feed" "$T/out_online" || fail "installed feed was not used"
[ ! -f "$FAKE_CURL_CALLED" ] || fail "curl was called although an installed feed exists"

echo "== invalid multiline plugin set =="
if run_patch --plugin-set $'123456789012\n999' >"$T/out3" 2>&1; then
    fail "multiline accepted"
fi
grep -qx 'PLUGIN_SET = "202601010101";' "$T/root/var/nessus/plugin_feed_info.inc" || fail "file damaged by invalid input"

echo "== unlock =="
run_patch --feed-unlock >"$T/out4" 2>&1 || fail "unlock rc"
for f in "$T/root/var/nessus/plugin_feed_info.inc" \
    "$T/root/var/nessus/.plugin_feed_info.inc" \
    "$T/root/lib/nessus/plugins/known_CA.inc"; do
    if is_immutable "$f"; then
        fail "still locked: $f"
    fi
done
[ ! -f "$T/feed_marker" ] || fail "tmp marker still present"
[ ! -f "$T/root/var/nessus/.feed_immutable" ] || fail "persistent marker still present"

echo "== fresh install uses online plugin set =="
rm -f "$T/root/var/nessus/plugin_feed_info.inc" \
    "$T/root/var/nessus/.plugin_feed_info.inc" \
    "$T/root/lib/nessus/plugins/plugin_feed_info.inc" \
    "$T/root/var/nessus/.plugin_set_last"
cat > "$BIN/curl" <<'EOF'
#!/bin/bash
: > "${FAKE_CURL_CALLED:?}"
printf '202604040404\n'
EOF
chmod +x "$BIN/curl"
rm -f "$FAKE_CURL_CALLED"
run_patch >"$T/out_fresh" 2>&1 || fail "fresh online patch rc"
grep -qx 'PLUGIN_SET = "202604040404";' "$T/root/var/nessus/plugin_feed_info.inc" || fail "fresh online set not written"
[ -f "$FAKE_CURL_CALLED" ] || fail "curl was not called for a fresh feed"

echo "== lock =="
run_patch --feed-lock >"$T/out5" 2>&1 || fail "lock rc"
is_immutable "$T/root/var/nessus/plugin_feed_info.inc" || fail "main not locked by lock"
is_immutable "$T/root/lib/nessus/plugins/known_CA.inc" || fail "sample not locked by lock"
[ -f "$T/root/var/nessus/.feed_immutable" ] || fail "persistent marker missing after lock"

echo "== tree lock failure returns 3 =="
run_patch --feed-unlock >/dev/null 2>&1
FAKE_FAIL_TREE=1 run_patch --plugin-set 202602020202 >"$T/out6" 2>&1
rc=$?
[ "$rc" -eq 3 ] || fail "tree failure rc=$rc, expected 3"
is_immutable "$T/root/var/nessus/plugin_feed_info.inc" || fail "main should stay locked on rc=3"
[ -f "$T/root/var/nessus/.feed_lock_failed" ] || fail "failed marker missing"

echo "== no lib dir =="
rm -rf "$T/root/lib/nessus/plugins"
run_patch --plugin-set 202603030303 >"$T/out7" 2>&1 || fail "no-lib patch rc"
[ -f "$T/root/var/nessus/plugin_feed_info.inc" ] || fail "main missing no-lib"
[ ! -f "$T/root/lib/nessus/plugins/plugin_feed_info.inc" ] || fail "lib unexpectedly created"
[ -f "$T/root/var/nessus/.feed_immutable" ] || fail "marker missing no-lib"

echo "ALL PATCH TESTS PASSED"
