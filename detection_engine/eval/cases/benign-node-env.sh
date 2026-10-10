#!/usr/bin/env bash
# Benign case: an app reading its own .env, then connecting to its database.
# The sensor watchlists .env, so this is a secret read followed by a network
# connect — the exfiltration shape — but the app is its own anchor, not a
# dependency. Under the engine's rule that .env counts only inside a package
# or build chain, F1 does not fire, so N2 cannot, and the chain scores 0.
set -uo pipefail

command -v node >/dev/null 2>&1 || { echo "node not installed" >&2; exit 1; }

DIR=/tmp/secrisk-eval-node-env
rm -rf "$DIR"
mkdir -p "$DIR"

cat > "$DIR/.env" <<'ENV'
DB_HOST=127.0.0.1
DB_PORT=5432
DB_PASSWORD=not-a-real-secret-eval-only
ENV

cat > "$DIR/app.js" <<'JS'
const net = require("net");
const fs = require("fs");
// A stand-in database the app connects to once, then both sides close.
const srv = net.createServer(s => { s.end(); srv.close(); });
srv.listen(0, "127.0.0.1", () => {
  const port = srv.address().port;
  // Read the app's own configuration, including the DB password.
  fs.readFileSync(__dirname + "/.env", "utf8");
  const c = net.connect(port, "127.0.0.1", () => c.end());
});
JS

echo "[*] benign-node-env: app reads its .env and connects to its database"
node "$DIR/app.js"
rm -rf "$DIR"
