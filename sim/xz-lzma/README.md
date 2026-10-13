# XZ-style build-tampering simulation

A benign, self-contained fixture that drives the existing SecRisk sensors
through the *shape* of the 2024 XZ Utils build compromise: a build step pulls a
"test file" out of `tests/files/`, decompresses it, and a shell script — not a
compiler — drops an object file into the liblzma source tree. It changes no
sensor code, detection rule, score, or production config.

It does **not** reproduce the backdoor: no liblzma, sshd, authentication, system
library or package is touched, and nothing is downloaded.

## What it does

`make` in a synthetic `xz-5.6.1/` tree runs `sh ./build-to-host.sh`, which:

| # | Behaviour | Expected telemetry | Rule |
|---|-----------|--------------------|------|
| 1 | `make` runs the recipe shell | `exec` (make → sh) | P1, C1 (anchor = make) |
| 2 | `xz -dc tests/files/bad-3-corrupt_lzma2.xz` | `exec` (sh → xz) | L5 |
| 3 | the shell writes `src/liblzma/liblzma_la-crc64_fast.o` | `file` / `write` | L6 |

Expected chain: **P1 L5 L6 C1 = 60, Medium.** The engine test
`xz_style_build_tampering` in `detection_engine/tests/scenarios.rs` asserts the
same chain on the same names, and a capture of this script's real process tree
(taken with strace) replayed through `secrisk-engine` scores exactly that.

The alert fires at 40 (P1 L5 C1); the L6 write raises the chain to 60 in the
same band, so it shows in the chain summary rather than as a second alert.

## Safety

- Synthetic input: the `.xz` "test file" is plain text compressed by the script.
- Local build only; nothing downloaded or executed from a download.
- No system file, library, package, or persistence location is touched.
- Everything lives under `/tmp/secrisk-xzsim/` and is removed on exit.

## Run it (from your own terminal, with sudo)

The sensors mute Claude Code's process subtree, so run this yourself, not
through Claude. Requires `xz`, `make`, and `sudo` (to load the eBPF probes).

### Option A — live
```bash
# Terminal 1
sudo ./sensors/target/debug/sensors | ./detection_engine/target/debug/secrisk-engine
# Terminal 2
./sim/xz-lzma/run_sim.sh
```

### Option B — dashboard
```bash
# Terminal 1
./dashboard/run.sh live
# Terminal 2
SECRISK_BUILD_ID=185 ./sim/xz-lzma/run_sim.sh
```

### Option C — evaluation case
```bash
./detection_engine/eval/record.sh attack-xz-build
./detection_engine/eval/run_eval.sh
```

## Knobs

- `SECRISK_BUILD_ID` — names the run (`[A-Za-z0-9_-]+`); default is a timestamp.
  Files live under `/tmp/secrisk-xzsim/secrisk-build-<id>/`, so the dashboard's
  Pipeline Context page links the run by that tag.
- `KEEP=1` — leave the build tree in place for inspection.

## Why the script looks the way it does

The normalizer reads `cmdline` and `cwd` from `/proc` *after* an exec. A process
that has already exited has neither, and L5 matches on the `tests/` argument.
Two details keep the capture reliable:

1. **xz is held alive.** Its ~1 MiB of output goes into a pipe whose reader
   sleeps 0.5 s before draining, so xz blocks on the full 64 KiB pipe and is
   still running when its cmdline is read. Without this, xz on a small file
   exits in a few milliseconds and L5 can silently miss.
2. **The object is written by absolute path**, so L6 resolves it without the
   shell's cwd.

## Caveats

1. **Medium, not Critical, by design.** No credential, staging, or network
   behaviour is involved, and the default Slack threshold is High, so this run
   shows in the dashboard but does not post to Slack.
2. **No `sh -c`.** A recipe with no shell metacharacters is exec'd by make
   directly (make → sh). Adding a pipe or redirect to the recipe would insert
   an extra `sh -c`. It would still score P1, but it would no longer match
   the scenario test.
3. **The real attack ran in `configure`** (via `build-to-host.m4`). The engine
   treats `configure` as a build flag, not an anchor, so a configure-only
   chain under a terminal would have no anchor. `make` keeps the chain anchored.
