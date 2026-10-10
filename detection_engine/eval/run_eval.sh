#!/usr/bin/env bash
# Score every recorded evaluation capture against its expected label and print
# a results table with precision, recall and false-positive rate — the numbers
# Phase 4 reports. Reads eval/expected.tsv and whatever captures have been
# recorded into eval/captures/ by record.sh.
#
#   ./eval/run_eval.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVAL="$ROOT/detection_engine/eval"
ENGINE="$ROOT/detection_engine/target/debug/secrisk-engine"
CAPTURES="$EVAL/captures"

[[ -x "$ENGINE" ]] || { echo "build the engine first: ( cd detection_engine && cargo build )" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "this script needs jq" >&2; exit 1; }

# score -> band label, by the same thresholds the engine uses.
band() {
    local s="$1"
    if   (( s <= 30 )); then echo none
    elif (( s <= 60 )); then echo Medium
    elif (( s <= 80 )); then echo High
    else                     echo Critical
    fi
}
rank() { case "$1" in none) echo 0;; Medium) echo 1;; High) echo 2;; Critical) echo 3;; *) echo 0;; esac; }

tp=0 fp=0 tn=0 fn=0 skipped=0
printf '%-22s %-7s %7s %-9s %-9s %s\n' CASE CLASS SCORE BAND EXPECT RESULT
printf '%s\n' "----------------------------------------------------------------------------"

while IFS=$'\t' read -r name class expect_alert min_band max_band _note; do
    [[ -z "${name:-}" || "$name" == \#* ]] && continue
    capture="$CAPTURES/$name.jsonl"

    if [[ ! -s "$capture" ]]; then
        printf '%-22s %-7s %7s %-9s %-9s %s\n' "$name" "$class" "-" "-" "$min_band" "SKIP (not recorded)"
        skipped=$((skipped + 1))
        continue
    fi

    # Worst chain in the capture: the highest score any chain reached.
    score="$("$ENGINE" --all-chains "$capture" 2>/dev/null \
        | jq -s 'map(.score) | max // 0')"
    got_band="$(band "$score")"
    alerted=no; (( score >= 31 )) && alerted=yes

    result="PASS"
    if [[ "$class" == "benign" ]]; then
        # Any alert on a benign case is a false positive.
        if [[ "$alerted" == yes ]]; then result="FAIL (false positive)"; fp=$((fp+1)); else tn=$((tn+1)); fi
    else
        # Attack: must alert, within the expected band range.
        if [[ "$alerted" == no ]]; then
            result="FAIL (missed)"; fn=$((fn+1))
        else
            tp=$((tp+1))
            if (( $(rank "$got_band") < $(rank "$min_band") || $(rank "$got_band") > $(rank "$max_band") )); then
                result="PASS (band $got_band, expected $min_band..$max_band)"
            fi
        fi
    fi

    expect="$min_band"; [[ "$min_band" != "$max_band" ]] && expect="$min_band..$max_band"
    printf '%-22s %-7s %7s %-9s %-9s %s\n' "$name" "$class" "$score" "$got_band" "$expect" "$result"
done < "$EVAL/expected.tsv"

echo
echo "Confusion matrix (alert = positive):"
printf '  TP %d   FP %d\n  FN %d   TN %d\n' "$tp" "$fp" "$fn" "$tn"

f() { awk -v a="$1" -v b="$2" 'BEGIN{ if (a+b==0) print "n/a"; else printf "%.3f", a/(a+b) }'; }
echo
echo "  precision            $(f "$tp" "$fp")   (of alerts, how many were attacks)"
echo "  recall               $(f "$tp" "$fn")   (of attacks, how many alerted)"
echo "  false-positive rate  $(f "$fp" "$tn")   (of benign, how many alerted)"
(( skipped > 0 )) && echo && echo "  $skipped case(s) not yet recorded — see eval/README.md"
exit 0
