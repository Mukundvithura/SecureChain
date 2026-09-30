#!/usr/bin/env bash
# The SecRisk demo, end to end, in one command.
#
#   ./demo/run_demo.sh
#
# Starts the sensors, runs the simulated compromised-package attack against
# them, stops them cleanly, and prints the chain that was reconstructed.
# Needs sudo to load the eBPF programs; everything else runs as you.
#
# The capture is kept afterwards — the path is printed at the end — so you can
# open it in demo/event_viewer.html or pick it apart with jq.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENSORS="$ROOT/sensors"
BIN="$SENSORS/target/debug/sensors"
CAPTURE="${SECRISK_CAPTURE:-$SENSORS/captures/demo-$(date +%Y%m%d-%H%M%S).jsonl}"
LOG="$(mktemp)"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# The sensor is root-owned, so stopping it needs sudo too. Runs on every exit
# path, including Ctrl-C, so a half-finished demo never leaves probes attached.
cleanup() {
    if [[ -n "${SENSOR_PID:-}" ]] && kill -0 "$SENSOR_PID" 2>/dev/null; then
        sudo pkill -TERM -x sensors 2>/dev/null
        wait "$SENSOR_PID" 2>/dev/null
    fi
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

[[ -x "$ROOT/demo/supply_chain_demo.sh" ]] || die "demo/supply_chain_demo.sh is missing or not executable"

if [[ ! -x "$BIN" ]]; then
    say "Building the sensors (first run only)…"
    ( cd "$SENSORS" && cargo build ) || die "cargo build failed"
fi

# Prompt for the password now, with a clear reason, rather than having sudo
# interrupt later from a backgrounded process where the prompt is invisible.
say "Loading eBPF programs needs root."
sudo -v || die "sudo is required to attach the sensors"

mkdir -p "$(dirname "$CAPTURE")"

say "Starting sensors…"
sudo -E env SECRISK_CAPTURE="$CAPTURE" "$BIN" >/dev/null 2>"$LOG" &
SENSOR_PID=$!

# Wait for the loader to report that every probe is attached. Polling the log
# beats a fixed sleep: too short and the demo runs before the probes are live,
# too long and every run wastes the difference.
for _ in $(seq 1 60); do
    grep -q "Waiting for Ctrl-C" "$LOG" 2>/dev/null && break
    kill -0 "$SENSOR_PID" 2>/dev/null || { cat "$LOG" >&2; die "sensors exited during startup"; }
    sleep 0.5
done
grep -q "Waiting for Ctrl-C" "$LOG" || { cat "$LOG" >&2; die "sensors did not attach within 30s"; }
say "Sensors attached."

echo
say "Simulating: npm install left-pad  (with a compromised postinstall)"
"$ROOT/demo/supply_chain_demo.sh"
echo

# The network sensor fires on the SYN, but the ring buffer drain is async —
# give the last events a moment to land before tearing down.
sleep 2

say "Stopping sensors…"
sudo pkill -TERM -x sensors 2>/dev/null
for _ in $(seq 1 30); do
    grep -q "^Wrote " "$LOG" 2>/dev/null && break
    sleep 0.5
done
SENSOR_PID=""   # already stopped; stop cleanup from trying again
grep "^Wrote " "$LOG" || say "warning: sensor did not report a final flush"

echo
say "The chain it reconstructed:"
echo
if command -v jq >/dev/null 2>&1; then
    jq -r 'select(.comm == "npm-install.sh"
                  or ([.ancestry[]?.comm] | index("npm-install.sh")))
           | "  \(.time[11:23])  \(.action | ascii_upcase | .[0:12])  \(.path // "\(.daddr):\(.dport)")"' \
        "$CAPTURE"
else
    grep 'npm-install.sh' "$CAPTURE"
    echo
    say "(install jq for readable output)"
fi

echo
say "Capture: $CAPTURE"
say "Open demo/event_viewer.html and drop that file on it, then click Chains."
