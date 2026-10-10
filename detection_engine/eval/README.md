# Evaluation set

A small labelled set for measuring the engine: two supply-chain attacks and the
benign workloads most likely to look like one — builds that run compilers and
write object files, a browser reaching out, an SSH session reading its own key,
an app reading its `.env`. It produces the precision, recall and
false-positive rate Phase 4 reports.

```
eval/
  expected.tsv      each case, its label (attack/benign) and the band it should reach
  cases/            one workload script per case
  record.sh         run a case under the sensors and save its capture
  run_eval.sh       score every recorded capture against expected.tsv
  captures/         recorded captures (git-ignored; you record these)
```

## Recording captures

The sensors mute Claude Code and every process it starts, so a case launched
through Claude's shell records an empty capture. **Record from your own
terminal.**

```shell
# Build once.
( cd sensors && cargo build )
( cd detection_engine && cargo build )

# Record one case, or all of them. Needs sudo to load the eBPF programs.
./detection_engine/eval/record.sh attack-npm
./detection_engine/eval/record.sh all
```

Each run starts the sensors, runs the workload, stops the sensors, and writes
`captures/<case>.jsonl`.

## Scoring

```shell
./detection_engine/eval/run_eval.sh
```

For each capture it takes the worst chain's score, turns it into a band, and
checks it against the label: a benign case that reaches Medium or above is a
false positive; the attack must reach its expected band. It prints a per-case
table, the confusion matrix, and precision / recall / false-positive rate.
Cases with no capture yet are marked SKIP.

## The cases

| Case | Class | Should | Why it is here |
|------|-------|--------|----------------|
| `attack-npm` | attack | **Critical** | compromised postinstall: reads an SSH key, stages an implant, exfiltrates |
| `attack-pip-revshell` | attack | **alert** | compromised `setup.py` opens a bash reverse shell during `pip install` |
| `benign-ssh` | benign | no alert | `ssh` reading its own key and connecting on 22 is the exempt reader, not a package manager |
| `benign-firefox` | benign | no alert | a browser is its own anchor; its traffic is not a dependency's |
| `benign-npm-native` | benign | no alert | `npm` → `make` → `gcc` writing `.o`/`.so`: the classic L6/L7/N1 false positive |
| `benign-pip-cext` | benign | no alert | `pip` building a C extension through setuptools and gcc |
| `benign-cargo-buildrs` | benign | no alert | `cargo` running a crate's `build.rs`, a build-time program writing to its target dir |
| `benign-node-env` | benign | no alert | an app reading its own `.env`, then its database — `.env` counts only inside a dependency chain |

All workloads run offline and confine themselves to `/tmp`; none reads a real
credential or contacts the network beyond localhost (the browser case aside).

`benign-firefox` skips itself if firefox is absent, `benign-pip-cext` if the
Python headers are missing — a skipped workload records a capture with only
the shell's own activity, which still scores 0.
