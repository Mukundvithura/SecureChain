# Process Monitor — Design & Build Notes

eBPF-based process-launch sensor for the SecRisk supply-chain attack detection
project. This document summarises what was built, the problems hit along the
way, and how to run/verify it.

---

## 1. Goal

Capture every real process launch on the host and enrich each event with enough
context (path, pid, parent pid, uid) to later reason about supply-chain attack
patterns (e.g. a build tool spawning a network downloader or shell).

---

## 2. Environment

| Item | Value |
|------|-------|
| OS | Kali Linux 2026.1 |
| Kernel | 6.19.x (`+kali-amd64`) |
| Language | Rust (stable + nightly + `rust-src`) |
| Framework | [Aya](https://github.com/aya-rs/aya) (full upstream, pulled from git) |
| Toolchain | clang, bpftool, bpf-linker, cargo-generate |
| Scaffold | `cargo generate aya-rs/aya-template` → tracepoint / syscalls / `sys_enter_execve` |

**Workspace** (`process_monitor/`):

```
process_monitor/
├── process_monitor/          # userspace loader (Tokio)
├── process_monitor-common/   # shared types
├── process_monitor-ebpf/     # the eBPF program  <-- main.rs is the real code
└── Cargo.toml                # workspace; aya deps point at git
```

> The framework is stock Aya; the **program** is fully custom. The generated
> template was a one-line `info!("tracepoint sys_enter_execve called")`.
> `process_monitor-ebpf/src/lib.rs` is unused template residue — the program
> lives in `main.rs`.

---

## 3. What it does

Two tracepoints sharing two BPF maps:

| Program | Tracepoint | Role |
|---------|-----------|------|
| `process_monitor` | `syscalls/sys_enter_execve` | Log each exec: `pid / ppid / uid / path` |
| `sched_fork` | `sched/sched_process_fork` | Record `child → parent` pid; propagate mute |

| Map | Type | Purpose |
|-----|------|---------|
| `PID_PARENT` | `HashMap<u32,u32>` (8192) | child pid → parent pid, for ppid lookup |
| `MUTED` | `LruHashMap<u32,u8>` (1024) | pids whose events are suppressed (noise) |

**Event flow**

- `sched_process_fork` fires → store `child→parent` in `PID_PARENT`. If the
  parent is in `MUTED`, mute the child too (taints the whole subtree).
- `sys_enter_execve` fires → look up `ppid`; if pid is muted, drop. Otherwise
  read the exec path from user memory; if it's the known-noisy widget, mute it
  and drop; else log the enriched event.

The exec path is read with `bpf_probe_read_user_str_bytes` into a 64-byte stack
buffer (the `filename` pointer is the first syscall arg in the tracepoint).

---

## 4. Noise handling

The XFCE panel's VPN-IP widget
(`/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh`) polled every second and
spawned `ip`/`cut`/`head`/`grep`, flooding the logs. Handled two ways:

1. **Throttle the source** — `~/.config/xfce4/panel/genmon-15.rc`
   `UpdatePeriod` raised `1000` → `60000` ms (then `xfce4-panel -r`). Reversible.
2. **Kernel-side subtree mute** — match the widget by path, add its pid to
   `MUTED`, and propagate the mute to all descendants **at fork time** (see the
   subshell bug below).

---

## 5. Problems hit & fixes (the useful part)

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| `cargo: command not found` under sudo | `sudo` resets `PATH` even with `-E` | run as `sudo -E env PATH="$PATH" cargo run` |
| No output at all | `env_logger` silent unless `RUST_LOG` set; aya-log routes through `log` | run with `RUST_LOG=info`. (`trace_pipe` is unrelated — aya-log uses a ring buffer, not ftrace) |
| Only "execve called", no path | template logic was a stub | read `filename` arg via `bpf_probe_read_user_str_bytes` |
| `no method as_ptr` | `EbpfContext` trait not in scope | `use aya_ebpf::EbpfContext` |
| Verifier: `1000001 insns (limit 1000000)` | `iter().position()` over a 256-byte buffer exploded state | use the slice the helper returns; shrink buffer to 64 |
| `bpf_link_create … Permission denied (EACCES)` on fork attach | program read tracepoint context **past the record size**; kernel check `max_ctx_offset > off` rejects at attach | fix struct to the real kernel-6.19 layout |
| Wrong fork offsets | 6.19 uses `__data_loc char[]` (4-byte descriptors), not inline `char[16]`; record is 24 B, not 48 B | `parent_pid` @12, `child_pid` @20 |
| Filter let `ip`/`cut`/… through | bash forks **subshells that never execve**, so exec-time mute never tagged them | propagate mute in the **fork** tracepoint, not just on exec |
| `pwd` not recorded | `pwd` is a shell **builtin** — no execve happens | expected; use `command pwd` / `/usr/bin/pwd` to force an exec |

### Key kernel insight
A tracepoint BPF program is rejected **at attach time** (not load) with
`EACCES` if it reads the context buffer beyond that specific tracepoint's record
size. Always match the `#[repr(C)]` struct to the live
`/sys/kernel/tracing/events/<cat>/<name>/format`.

`sched_process_fork` format on this kernel:
```
offset 0  common header (8)
offset 8  __data_loc parent_comm (4)
offset 12 parent_pid (4)
offset 16 __data_loc child_comm (4)
offset 20 child_pid (4)   -> total record = 24 bytes
```

---

## 6. Build & run

```bash
cd process_monitor
cargo build                                   # builds eBPF object + userspace (no root)
RUST_LOG=info sudo -E env PATH="$PATH" cargo run
```

Generate events in a second terminal (`ls`, `curl google.com`). Stop with Ctrl-C.

Sample output:
```
execve pid=70169 ppid=2215 uid=1000 path=/usr/bin/ls
execve pid=70312 ppid=2215 uid=1000 path=/usr/bin/curl
```

### Inspect the loaded program
```bash
sudo bpftool prog show          # tracepoint progs named process_monitor / sched_fork
sudo bpftool link show          # links to syscalls/sys_enter_execve & sched/sched_process_fork
sudo bpftool map show           # PID_PARENT (hash) and MUTED (lru_hash)
```

---

## 7. Status & next steps

**Working:** two-tracepoint sensor, correct ppid lineage, kernel-side noise
filtering, verifier-clean on kernel 6.19. Committed as Phase 1.

**Not done yet (next milestones):**
1. Detection rules — suspicious lineage (build tool → `curl`/`wget`/shell),
   exec from `/tmp` or `/dev/shm`, unexpected `uid=0`.
2. Structured events — replace `info!` logging with a perf/ring-buffer channel
   to the userspace `collector`.
3. File and network monitors (the other two `ebpf/` subdirs).
