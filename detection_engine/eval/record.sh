#!/usr/bin/env bash
# Record one evaluation case into a capture the scorer can read.
#
#   ./eval/record.sh <case>        # one case from eval/cases/
#   ./eval/record.sh all           # every case in expected.tsv
#
# Starts the sensors, runs the case's workload against them, stops them, and
# saves eval/captures/<case>.jsonl. Needs sudo to load the eBPF programs.
#
# Run this from your OWN terminal, not through Claude: the sensors mute Claude
# Code and everything it starts, so a case launched from Claude's shell is
# invisible to them and records an empty capture.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SENSORS="$ROOT/sensors"
BIN="$SENSORS/target/debug/sensors"
EVAL="$ROOT/detection_engine/eval"
CASES="$EVAL/cases"
OUT="$EVAL/captures"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

list_cases() { grep -v '^#' "$EVAL/expected.tsv" | awk 'NF {print $1}'; }

record_one() {
    local name="$1"
    local workload="$CASES/$name.sh"
    [[ -x "$workload" ]] || die "no workload for '$name' ($workload)"

    local capture="$OUT/$name.jsonl"
    local log
    log="$(mktemp)"

    say "[$name] starting sensors…"
    sudo -E env SECRISK_CAPTURE="$capture" "$BIN" >/dev/null 2>"$log" &
    local pid=$!
    local stopped=""
    # shellcheck disable=SC2064
    trap "sudo pkill -TERM -x sensors 2>/dev/null; rm -f '$log'" RETURN

    local ok=""
    for _ in $(seq 1 60); do
        grep -q "Waiting for Ctrl-C" "$log" 2>/dev/null && { ok=1; break; }
        kill -0 "$pid" 2>/dev/null || { cat "$log" >&2; die "[$name] sensors exited at startup"; }
        sleep 0.5
    done
    [[ -n "$ok" ]] || { cat "$log" >&2; die "[$name] sensors did not attach"; }

    say "[$name] running workload…"
    "$workload" || say "[$name] workload exited non-zero (kept the capture anyway)"

    # The network sensor fires on the SYN; let the async ring-buffer drain land.
    sleep 2

    say "[$name] stopping sensors…"
    sudo pkill -TERM -x sensors 2>/dev/null
    for _ in $(seq 1 30); do
        grep -q "^Wrote " "$log" 2>/dev/null && { stopped=1; break; }
        sleep 0.5
    done
    [[ -n "$stopped" ]] || say "[$name] warning: no final flush reported"
    say "[$name] saved $capture ($(wc -l <"$capture" 2>/dev/null || echo 0) events)"
}

[[ -x "$BIN" ]] || die "build the sensors first: ( cd sensors && cargo build )"
[[ $# -eq 1 ]] || die "usage: record.sh <case|all>"

mkdir -p "$OUT"
say "Loading eBPF programs needs root."
sudo -v || die "sudo is required to attach the sensors"

if [[ "$1" == "all" ]]; then
    for c in $(list_cases); do record_one "$c"; done
else
    record_one "$1"
fi

say "Done. Score with: ./eval/run_eval.sh"
