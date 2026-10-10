# secrisk-engine

The SecRisk correlation engine. It reads the normalized events the sensors
write, groups each one into the chain of its anchor process, runs the detection
rules against the chain and scores it. It writes an alert whenever a chain's
score enters a severity band at Medium or above that it has not alerted in
before.

The rules are the ones in "SecRisk Detection Rules"; the design follows the
"SecRisk Correlation Engine Plan".

## Run

```shell
cargo build

# Score a capture (or several — each file is scored on its own):
./target/debug/secrisk-engine replay ../sensors/captures/demo-<timestamp>.jsonl

# Live, straight from the sensors:
sudo ../sensors/target/debug/sensors | ./target/debug/secrisk-engine
```

`../demo/run_demo.sh` builds the engine on first run and scores the demo's
capture at the end.

Alerts and chain summaries go to stdout, one JSON object per line. A one-line
headline per alert and a closing tally go to stderr:

```
[Medium 55] chain 1 bash (pid 454122): P3 L1 F1
[Critical 85] chain 1 bash (pid 454122): P3 L1 F1 F2 N2 C3
demo-capture.jsonl: 35 events, 1 chains, 2 alerts
```

By default only chains where some rule fired are summarized; `--all-chains`
summarizes every chain, which is what a false-positive count needs.

## Records

| Field | Meaning |
|-------|---------|
| `record` | `alert` (the chain entered a new band) or `chain` (its summary, written when it goes 60 s without events or the input ends) |
| `chain` | chain id, in order of first appearance |
| `anchor` | the chain's top process: `pid`, `kind` (`dependency`, `runtime_dependency`, `user`), `name`, `exe`, `cmdline` |
| `score`, `severity` | 0–100; Low ≤ 30 < Medium ≤ 60 < High ≤ 80 < Critical |
| `components` | the four capped totals: process (30), file (25), network (25), context (20) |
| `rules` | every rule that fired: `id`, `points`, `counted` (false when a gate held it back), `technique`, `tactic`, and the `time`, `pid`, `comm` and `detail` of the event that fired it |
| `techniques` | distinct ATT&CK techniques among the counted rules |

## How it decides

- **Anchor.** The outermost package manager or build tool above the acting
  process (npm, pip, cargo, make, …), or a `node`/`python` running a script
  inside `node_modules/` or `site-packages/` (C4). Failing that, the command
  started by the nearest session shell, or the topmost ancestor running the
  same binary. The chain is the anchor plus everything beneath it.
- **Rules** fire at most once per chain. Most look at one event; L1, N2 and C3
  depend on order, and C1 and N3 count only beside other rules.
- **Score** is the sum of the four components, each capped.

Choices the plan left open are marked **Decision** in
[`src/rules/lists.rs`](src/rules/lists.rs), [`src/chain.rs`](src/chain.rs)
and [`src/score.rs`](src/score.rs). All 25 rules are implemented; L12
(pre-authentication sshd execution) assumes the OpenSSH 9.8+ process model
(`sshd-session` / `sshd-auth`) and still wants validation against a real SSH
login capture.

## Test

```shell
cargo test
```

`tests/scenarios.rs` builds the plan's attack and benign cases from
hand-written events and replays `tests/fixtures/demo-capture.jsonl`, a real
capture of `demo/run_demo.sh`. `tests/rules.rs` gives each rule a firing and a
non-firing case.

## Evaluate

`eval/` holds a labelled set — two attacks and the benign workloads most likely
to be mistaken for one — and scripts to record captures from the sensors and
score them into precision, recall and a false-positive rate. See
[`eval/README.md`](eval/README.md).

## Benchmark

```shell
cargo run --release --example throughput [events]
```

Times `Engine::process` over a synthetic stream, in isolation from the sensors
and JSON parsing, and reports nanoseconds per event and events per second. On a
13th-gen i7 it processes ~0.4 M events/s (~2.6 µs/event) — orders of magnitude
above any real sensor event rate.
