#!/usr/bin/env bash
# SecRisk controlled XZ-style build-tampering simulation.
#
# This is a TEST HARNESS for a defensive tool. It does not reproduce the XZ
# Utils backdoor, does not touch liblzma, sshd, authentication, system
# libraries or system packages, and does not download anything. Every input is
# generated here, the build is local, and everything lives under
# /tmp/secrisk-xzsim/secrisk-build-<id>.
#
# It mirrors the *shape* of the 2024 xz build compromise: a build step pulls a
# "test file" out of tests/files/, decompresses it, and a shell script — not a
# compiler — drops an object file into the liblzma source tree.
#
#   make -> sh ./build-to-host.sh                 (process: P1, anchor = make, C1)
#        -> xz -dc tests/files/bad-3-corrupt_lzma2.xz   (process: L5)
#        -> sh writes src/liblzma/liblzma_la-crc64_fast.o   (file: L6)
#
# Expected: P1 L5 L6 C1 = 60, Medium. The engine test
# `xz_style_build_tampering` (detection_engine/tests/scenarios.rs) asserts the
# same chain on the same names.
#
# Run from YOUR OWN terminal under the sensors (see README). The sensors mute
# Claude Code's process subtree, so this is invisible if launched from Claude.
#
# Needs xz and make on PATH. The script does not install them.

set -u

# Each run gets its own directory, tagged with a build ID, so the dashboard's
# Pipeline Context page can link the run's events to it. Set SECRISK_BUILD_ID
# to name a run; otherwise a timestamp is used.
BUILD_ID="${SECRISK_BUILD_ID:-$(date +%Y%m%d%H%M%S)}"
case "$BUILD_ID" in
    *[!A-Za-z0-9_-]*|"") echo "SECRISK_BUILD_ID must match [A-Za-z0-9_-]+" >&2; exit 1 ;;
esac
SIM_DIR="/tmp/secrisk-xzsim/secrisk-build-$BUILD_ID"
SRC_DIR="$SIM_DIR/xz-5.6.1"          # the "release tarball", unpacked
TEST_FILE="tests/files/bad-3-corrupt_lzma2.xz"
OBJECT="src/liblzma/liblzma_la-crc64_fast.o"
KEEP="${KEEP:-0}"

teardown() {
    if [[ "$KEEP" == "1" ]]; then
        echo "[*] KEEP=1 — leaving $SIM_DIR in place for inspection."
    else
        echo "[*] Cleaning up $SIM_DIR"
        rm -rf "$SIM_DIR"
        rmdir /tmp/secrisk-xzsim 2>/dev/null
    fi
}

for tool in xz make; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is not installed (this script does not install it)" >&2; exit 1; }
done

rm -rf "$SIM_DIR"
trap teardown EXIT
mkdir -p "$SRC_DIR/tests/files" "$SRC_DIR/src/liblzma"

# --- Synthetic "test file" --------------------------------------------------
# Plain text, xz-compressed. ~1 MiB decompressed so xz outlives the 64 KiB pipe
# buffer below — see the recipe script.
for _ in $(seq 1 30000); do echo "secrisk synthetic test payload line"; done \
    | xz -c > "$SRC_DIR/$TEST_FILE"

# --- The tampered build script ----------------------------------------------
# Stands in for the injected build-to-host step. Two details keep the capture
# reliable, because the normalizer reads cmdline and cwd from /proc after the
# exec and a process that has already exited has neither:
#   * xz's output goes into a pipe whose reader waits before draining, so xz
#     blocks on the full pipe and is still alive when its cmdline is read (L5
#     matches on the tests/ argument).
#   * the object is written by absolute path, so it resolves without the
#     shell's cwd (L6 matches on the .o suffix).
cat > "$SRC_DIR/build-to-host.sh" <<'SCRIPT'
#!/bin/sh
srcdir=$(pwd)
echo "    [build-to-host] extracting tests/files/bad-3-corrupt_lzma2.xz"
xz -dc tests/files/bad-3-corrupt_lzma2.xz | { sleep 0.5; cat >/dev/null; }
echo "    [build-to-host] writing src/liblzma/liblzma_la-crc64_fast.o (no compiler)"
printf 'synthetic-object\n' > "$srcdir/src/liblzma/liblzma_la-crc64_fast.o"
echo "    [build-to-host] done"
SCRIPT

# --- Makefile ----------------------------------------------------------------
# Recipe lines must start with a real tab, so printf writes them. A recipe with
# no shell metacharacters is exec'd by make directly: make -> sh, no sh -c.
printf 'all: %s\n\n%s: %s build-to-host.sh\n\tsh ./build-to-host.sh\n' \
    "$OBJECT" "$OBJECT" "$TEST_FILE" > "$SRC_DIR/Makefile"

# --- Run it ------------------------------------------------------------------
echo "[*] build $BUILD_ID: make in $SRC_DIR"
echo "[*] Watch the sensor terminal for make -> sh -> xz -dc tests/files/... and the write to $OBJECT."
echo

( cd "$SRC_DIR" && make )
status=$?

# Let the sensors' ring buffer drain before teardown deletes the tree.
sleep 1

echo
if [[ -f "$SRC_DIR/$OBJECT" ]]; then
    echo "[*] Build finished (exit $status). $OBJECT written."
else
    echo "[!] Build finished (exit $status) but $OBJECT was not written."
fi
