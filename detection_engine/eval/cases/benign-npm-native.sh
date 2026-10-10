#!/usr/bin/env bash
# Benign case: a clean npm install that compiles native code. The package's
# postinstall runs make, which runs gcc, which writes a .o and a .so inside a
# build chain under the npm anchor. This is the textbook L6/L7/N1 false
# positive: a non-anchor (gcc) writing object files in a build. The engine
# must not alert — gcc is an exempt compiler, there is no network, and C1
# alone scores 0.
set -uo pipefail

command -v npm >/dev/null 2>&1 || { echo "npm not installed" >&2; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "gcc not installed" >&2; exit 1; }

DIR=/tmp/secrisk-eval-npm-native
rm -rf "$DIR"
mkdir -p "$DIR/pkg" "$DIR/app"

cat > "$DIR/pkg/addon.c" <<'C'
int secrisk_add(int a, int b) { return a + b; }
C

cat > "$DIR/pkg/Makefile" <<'MK'
all:
	gcc -c -fPIC addon.c -o addon.o
	gcc -shared addon.o -o addon.so
MK

cat > "$DIR/pkg/package.json" <<'PKG'
{ "name": "native-addon", "version": "1.0.0", "scripts": { "postinstall": "make" } }
PKG

TARBALL="$DIR/$(cd "$DIR/pkg" && npm pack --silent --pack-destination "$DIR")"

cat > "$DIR/app/package.json" <<APP
{
  "name": "native-app",
  "version": "1.0.0",
  "private": true,
  "allowScripts": { "file:$TARBALL": true }
}
APP

echo "[*] benign-npm-native: npm install building a native addon"
( cd "$DIR/app" && npm install --offline --no-audit --no-fund --foreground-scripts \
    --cache "$DIR/npm-cache" "$TARBALL" )
rm -rf "$DIR"
