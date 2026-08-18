# sensors

SecRisk eBPF sensor suite — process, file and network. Loading the sensors needs
root; events are emitted as JSON on stdout, diagnostics on stderr. See
[`../docs/ebpf/sensors_design.md`](../docs/ebpf/sensors_design.md) for the full
design and build notes.

Each event is normalized and enriched in the loader before it is written out, so
a record is self-contained rather than something a later stage has to go and
look things up for:

```json
{"ts":1787047040118181744,"time":"2026-08-18T15:27:20.118181744+05:30","type":"file","action":"secret_read","pid":41759,"ppid":41758,"uid":1000,"user":"mukunda","comm":"cat","exe":"/usr/bin/cat","cmdline":"cat /tmp/secrisk-demo/home/.ssh/id_rsa","ancestry":[{"pid":41758,"comm":"npm-install.sh"},{"pid":25330,"comm":"zsh"}],"path":"/tmp/secrisk-demo/home/.ssh/id_rsa","flags":0}
```

| Field | Meaning |
|-------|---------|
| `ts` / `time` | epoch nanoseconds / RFC 3339 local — the kernel's boot-relative clock, shifted by an offset sampled once at startup |
| `type` | which sensor: `exec`, `file`, `net` |
| `action` | what happened: `exec`, `write`, `secret_read`, `connect` |
| `pid` / `ppid` / `uid` | acting process; `ppid` is backfilled from `/proc` when the fork went unobserved |
| `user` | resolved from `/etc/passwd` |
| `comm` | the kernel's 16-byte name — for a threaded process this is the *thread* |
| `exe` / `cmdline` | process identity, from the exec event or `/proc` |
| `ancestry` | `{pid, comm}` up to 8 levels, still correct after an ancestor exits |
| `container` | 12-hex id from `/proc/<pid>/cgroup`; absent on the host |
| `path` / `path_raw` | absolute path, resolved against the cwd or the `openat` directory fd; the raw argument is kept as `path_raw` when resolution changed it |

Fields that could not be established are omitted rather than zero-filled.
`§7` of the design doc covers how each is derived and where it can be wrong.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Build as your normal user, then run only the sensor as root:

```shell
cargo build
sudo ./target/debug/sensors
```

A build script compiles the eBPF object and embeds it in the binary, so the
binary is self-contained — nothing else needs to be on disk at run time.

## Captures

Every run writes its events to a capture file as well as stdout, so nothing is
lost if you forget to redirect. The path is printed at startup and again on
exit; Ctrl-C drains whatever is still in the ring buffer, flushes and reports
the count:

```shell
$ sudo ./target/debug/sensors
Capturing to captures/sensors-20260816-224500.jsonl
Waiting for Ctrl-C...
^CExiting...
Wrote 143 events to captures/sensors-20260816-224500.jsonl
```

The default is `captures/sensors-<YYYYmmdd-HHMMSS>.jsonl` relative to the
working directory (git-ignored); `SECRISK_CAPTURE` overrides it with an exact
path:

```shell
sudo SECRISK_CAPTURE=~/secrisk-capture.jsonl ./target/debug/sensors
```

The file is chowned to `$SUDO_USER`, so reading or deleting it afterwards needs
no sudo. Paste it into `../demo/event_viewer.html` for a readable view.

stdout still carries the same JSON lines (stderr carries the aya-log output), so
piping keeps working if you'd rather stream it somewhere:

```shell
sudo ./target/debug/sensors 2>/dev/null | jq -c 'select(.action=="secret_read")'
```

### Why not `cargo run`

`cargo run` also works, but `.cargo/config.toml` sets `runner = "sudo -E"`, so
under `sudo` you end up running the whole build toolchain as root:

```shell
# works, but builds as root — prefer the two-step form above
RUST_LOG=info sudo -E env PATH="$PATH" cargo run
```

That form needs `env PATH="$PATH"` only because sudo's `secure_path` drops
`~/.cargo/bin` even with `-E`. The bigger cost is that a root cargo leaves
root-owned files in `target/`, and a later non-root build fails on them with a
permission error that looks nothing like its cause. If that has already
happened:

```shell
sudo find target -user root -delete
```

`RUST_LOG` only controls stderr diagnostics — events reach stdout through
`println!` regardless, so it makes no difference to a capture.

## Tests

The normalizer's unit tests are plain userspace tests and need no root — but
`.cargo/config.toml` sets `runner = "sudo -E"` for every binary in the
workspace, so a bare `cargo test` tries to run the test harness under sudo and
stops at a password prompt. Override the runner:

```shell
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env cargo test -p sensors
```

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package sensors --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/sensors` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, sensors is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
