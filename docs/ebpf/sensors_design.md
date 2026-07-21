# Sensors — Design & Build Notes

eBPF sensor suite for the SecRisk supply-chain attack detection project. All
sensors live in one BPF object, emit a single unified event type into one ring
buffer, and are drained by one userspace loader that normalizes each event to a
JSON line. This document summarises what was built, the problems hit along the
way, and how to run/verify it.

Current sensors: **process** (exec + fork lineage), **file** (write-intent
opens), and **network** (outbound TCP connect attempts).

---

## 1. Goal

Capture security-relevant runtime activity — process launches, file writes, and
(later) outbound connections — enriched with lineage (`pid / ppid / uid / comm`)
and unified into one event stream, so the detection layer can reason over
cross-source attack chains (e.g. a build tool that execs a downloader, writes a
binary to `/tmp`, then connects out).

---

## 2. Environment

| Item | Value |
|------|-------|
| OS | Kali Linux 2026.1 |
| Kernel | 6.19.x (`+kali-amd64`) |
| Language | Rust (stable + nightly + `rust-src`) |
| Framework | [Aya](https://github.com/aya-rs/aya) (full upstream, pulled from git) |
| Toolchain | clang, bpftool, bpf-linker, cargo-generate |

**Workspace** (`sensors/`):

```
sensors/
├── sensors/              # userspace loader (Tokio): drains ring buffer, emits JSON
├── sensors-common/       # shared event schema (no_std; `user` feature adds aya::Pod)
├── sensors-ebpf/         # the eBPF program
│   └── src/
│       ├── main.rs       # maps (EVENTS, PID_PARENT, MUTED) + module wiring
│       ├── process.rs    # sched_process_exec + sched_process_fork  → EVENT_EXEC
│       ├── file.rs       # sys_enter_openat                          → EVENT_FILE
│       └── network.rs    # inet_sock_set_state                       → EVENT_NET
└── Cargo.toml            # workspace; aya deps point at git
```

> One BPF object, three logical sensors as **source modules** (not separate
> binaries). Each `#[tracepoint]` program is `no_mangle`, so its symbol name is
> module-independent — userspace looks them up by function name regardless of
> which module they live in. `sensors-ebpf/src/lib.rs` is unused template
> residue (it only enables the library target).

---

## 3. Architecture: one stream

```
sensor programs ──> EVENTS ring buffer ──> userspace loader ──> JSON line / event
(process, file)     (256 KiB, shared)      (tokio AsyncFd)      (stdout)
```

**Shared schema** (`sensors-common`): every sensor emits the same fixed-size
`#[repr(C)]` `Event` — a common `EventHeader` (`timestamp, pid, ppid, uid, kind,
comm`) plus a tagged `Payload` union selected by `kind`:

| `kind` | Payload | Fields |
|--------|---------|--------|
| `EVENT_EXEC` | `ExecPayload` | `filename[256]` |
| `EVENT_FILE` | `FilePayload` | `path[256]`, `flags` |
| `EVENT_NET`  | `NetPayload`  | `daddr, saddr, dport, sport, proto` |

One `Event` type ⇒ one ring buffer ⇒ one userspace decode path (`Event::from_bytes`,
an unaligned read into an owned value). `kind` is a plain `u8` + consts, not a
Rust enum, because it's transmuted from kernel bytes (an out-of-range enum
discriminant would be UB).

> **Kernel-writer contract:** the ring-buffer slot is uninitialized memory. Each
> sensor builds a **zeroed** `Event` on the stack before filling it — otherwise
> the uninitialized tail of the union (the bytes past a small variant) would leak
> kernel memory to userspace. `Event` is ~304 B, within the 512 B BPF stack, so
> the path/filename is read straight into the payload field rather than via a
> second buffer.

**Shared maps** (declared in `main.rs`, used by every module):

| Map | Type | Purpose |
|-----|------|---------|
| `EVENTS` | `RingBuf` (256 KiB) | all sensor events → userspace |
| `PID_PARENT` | `HashMap<u32,u32>` (8192) | child pid → parent pid, for ppid lookup |
| `MUTED` | `LruHashMap<u32,u8>` (1024) | pids whose events are suppressed (noise) |

---

## 4. The sensors

### Process (`process.rs`)

| Program | Tracepoint | Role |
|---------|-----------|------|
| `process_monitor` | `sched/sched_process_exec` | Emit `EVENT_EXEC` for each successful exec |
| `sched_fork` | `sched/sched_process_fork` | Record `child → parent` pid; propagate mute |

- `sched_process_fork` → store `child→parent` in `PID_PARENT`. If the parent is
  in `MUTED`, mute the child too (taints the whole subtree).
- `sched_process_exec` fires **once, on a successful exec** → look up `ppid`; if
  the pid is muted, drop; if the path is the known-noisy widget, mute and drop;
  else emit. The exec path is a `__data_loc` descriptor (offset 8): low 16 bits
  are the byte offset to the inline string, read from the kernel buffer with
  `bpf_probe_read_kernel_str_bytes`.

> **Why `sched_process_exec`, not `sys_enter_execve`?** The syscall-entry
> tracepoint fires on *every* `execve` attempt, including the failed PATH probes
> the loader makes resolving a bare command name — launching `exo-open` logged 7
> events (one per `$PATH` dir, all sharing a pid) for one real launch.
> `sched_process_exec` fires once per successful exec with the final resolved
> binary. Trade-off: failed execs are invisible from this hook (they'd need
> `sys_exit_execve` with a non-zero return).

### File (`file.rs`)

| Program | Tracepoint | Role |
|---------|-----------|------|
| `file_monitor` | `syscalls/sys_enter_openat` | Emit `EVENT_FILE` for write-intent opens |

`openat` is a firehose (every library load, config read, `.so` mmap), so the
sensor filters **kernel-side** on two axes before emitting:

1. **Write intent** — drop read-only opens; keep write/read-write mode, `O_CREAT`,
   `O_TRUNC`, `O_APPEND`. This is the security-relevant slice (dropped payloads,
   tampered configs, staged binaries) and cuts volume enormously.
2. **Pseudo-filesystem paths** — drop `/dev/*` (**except `/dev/shm/`**, a real
   payload-staging spot), `/proc/`, `/sys/`. Interactive shells hammer
   `/dev/null` with write flags on every prompt; this kills that flood.

`openat`'s `filename` is a **userspace** pointer (arg index 1 ⇒ record offset 24),
read with `bpf_probe_read_user_str_bytes` — unlike the exec path's kernel
`__data_loc`. Args are read with `ctx.read_at` (a `bpf_probe_read` under the
hood) rather than a direct ctx-struct deref, which keeps clear of the
attach-time `EACCES` (see below).

> **Known limitation:** the captured path is the raw `openat` argument, so a
> relative path (e.g. `file.py`) is stored as-is, not resolved against the
> process CWD. Absolute-path resolution needs VFS-layer probing (`d_path`) — a
> later refinement.

### Network (`network.rs`)

| Program | Tracepoint | Role |
|---------|-----------|------|
| `network_monitor` | `sock/inet_sock_set_state` | Emit `EVENT_NET` for outbound TCP connects |

`inet_sock_set_state` fires on every TCP state change; the transition **into
`TCP_SYN_SENT`** is a process actively initiating an outbound connection — the
supply-chain signal (a build tool or dropped binary phoning out). We filter to
`newstate == TCP_SYN_SENT`, `family == AF_INET`, `protocol == IPPROTO_TCP` (v4/TCP
for now) and fill `daddr/saddr/dport/sport/proto`.

Using this **stable, fixed-format tracepoint** avoids the CO-RE/BTF `struct sock`
chasing a `tcp_connect` kprobe would need. In the record, ports are already host
byte order (the kernel `ntohs`-es them) and addresses are raw network-order bytes
(transported verbatim, formatted dotted-quad in userspace).

> **Known limitation:** `sport` reads as `0`. At the `SYN_SENT` transition the
> kernel hasn't assigned the ephemeral source port yet (that happens later in
> `inet_hash_connect`). The **destination** (`daddr:dport`) — what matters for
> "where is this phoning home" — is correct. A real source port would require
> reading `struct sock` via CO-RE (avoided) or a softirq-context later state
> (wrong pid).

---

## 5. Noise handling

- **Process** — the XFCE VPN-IP widget
  (`/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh`) polled every second,
  spawning `ip`/`cut`/`head`/`grep`. Matched by path, its pid added to `MUTED`,
  and the mute propagated to all descendants **at fork time** (subshells fork but
  never execve, so exec-time muting misses them). Optionally also throttled at
  source via `~/.config/xfce4/panel/genmon-15.rc` `UpdatePeriod 1000→60000`.
- **File** — write-intent + pseudo-fs filtering (§4).

---

## 6. Problems hit & fixes (the useful part)

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| `cargo: command not found` under sudo | `sudo` resets `PATH` even with `-E` | run as `sudo -E env PATH="$PATH" cargo run` |
| No output at all | `env_logger` silent unless `RUST_LOG` set; aya-log routes through `log` | run with `RUST_LOG=info`. (`trace_pipe` is unrelated — aya-log uses a ring buffer, not ftrace) |
| Verifier: `1000001 insns (limit 1000000)` | `iter().position()` over a 256-byte buffer exploded state | use the slice the helper returns; don't hand-scan long buffers in-kernel |
| `bpf_link_create … Permission denied (EACCES)` on attach | program read tracepoint context **past the record size**; kernel check `max_ctx_offset > off` rejects at attach | match the `#[repr(C)]` struct to the real kernel layout, or read args via `ctx.read_at` (probe read) instead of a direct deref |
| Wrong fork offsets | 6.19 uses `__data_loc char[]` (4-byte descriptors), not inline `char[16]`; record is 24 B, not 48 B | `parent_pid` @12, `child_pid` @20 |
| Process filter let `ip`/`cut`/… through | bash forks **subshells that never execve**, so exec-time mute never tagged them | propagate mute in the **fork** tracepoint, not just on exec |
| `pwd` not recorded | `pwd` is a shell **builtin** — no execve happens | expected; use `command pwd` / `/usr/bin/pwd` to force an exec |
| One launch logged 7× (`exo-open` at 7 paths, same pid) | `sys_enter_execve` fires on every PATH-probe attempt | hook `sched/sched_process_exec` — once per successful exec, resolved path |
| File sensor flooded by `/dev/null` (hundreds/sec from `zsh`) | shells open `/dev/null` with write flags every prompt; write-intent filter alone passes them | drop pseudo-fs paths kernel-side (`/dev/*` except `/dev/shm/`, `/proc/`, `/sys/`) |
| Union tail could leak kernel memory | ring-buffer slot is uninitialized; writing a small variant leaves the rest undefined | zero the whole `Event` (`mem::zeroed`) before filling |
| Net events show `sport=0` | at the `SYN_SENT` transition the ephemeral source port isn't assigned yet (happens later in `inet_hash_connect`) | accepted — destination (`daddr:dport`) is what matters and is correct |

### Key kernel insight
A tracepoint BPF program is rejected **at attach time** (not load) with `EACCES`
if it reads the context buffer beyond that tracepoint's record size. Either match
the `#[repr(C)]` struct to the live
`/sys/kernel/tracing/events/<cat>/<name>/format`, or read fields with
`ctx.read_at` (which goes through `bpf_probe_read` and sidesteps the direct-deref
bound check).

Live formats on this kernel:
```
sched_process_fork                       sched_process_exec
  0  common header (8)                     0  common header (8)
  8  __data_loc parent_comm (4)            8  __data_loc filename (4)  low16 = str off
 12  parent_pid (4)                       12  pid (4)
 16  __data_loc child_comm (4)            16  old_pid (4)   -> record = 20 B
 20  child_pid (4)   -> record = 24 B

sys_enter_openat  (syscall-enter: 8-byte arg slots from offset 16)
  8  __syscall_nr (4)
 16  dfd            24  filename (ptr)     32  flags     40  mode

inet_sock_set_state  (all fields inline, not __data_loc)
 16  oldstate(i32)  20  newstate(i32)  24  sport(u16, host order)  26  dport(u16)
 28  family(u16)    30  protocol(u16)  32  saddr[4]  36  daddr[4]  -> record = 72 B
```

---

## 7. Build & run

```bash
cd sensors
cargo build                                   # builds eBPF object + userspace (no root)
RUST_LOG=info sudo -E env PATH="$PATH" cargo run
```

Generate events in a second terminal (`ls`; `echo hi > /tmp/x`; `curl google.com`).
Stop with Ctrl-C. Events are JSON on **stdout**; status/errors on **stderr** (so
`… | jq .` works cleanly).

Sample output — note the exec→connect chain on one pid (the correlation payoff):
```json
{"ts":14817878347036,"type":"exec","pid":132429,"ppid":17781,"uid":1000,"comm":"curl","path":"/usr/bin/curl"}
{"ts":14817970034810,"type":"net","pid":132429,"ppid":17781,"uid":1000,"comm":"curl","saddr":"192.168.159.128","sport":0,"daddr":"142.250.67.46","dport":80,"proto":6}
{"ts":14818181744654,"type":"file","pid":17781,"ppid":0,"uid":1000,"comm":"zsh","path":"/tmp/x","flags":833}
```

`ppid=0` for a process that already existed before the sensor started (no fork
record); lineage is populated only for processes spawned after attach.

### Inspect the loaded programs
```bash
sudo bpftool prog show     # progs: process_monitor / sched_fork / file_monitor / network_monitor
sudo bpftool link show     # links to sched_process_exec, sched_process_fork, sys_enter_openat, inet_sock_set_state
sudo bpftool map show      # EVENTS (ringbuf), PID_PARENT (hash), MUTED (lru_hash)
```

---

## 8. Status & next steps

**Working:** the full sensor triad — process + file + network — in one BPF
object, unified `Event` schema, ring-buffer transport, JSON-normalizing loader,
per-sensor kernel-side noise filtering, verifier-clean on kernel 6.19. Lineage
(`pid`/`ppid`) already links events across sensors (e.g. exec→connect on one pid).

**Not done yet:**
1. **Correlation + detection** — suspicious lineage (build tool → downloader →
   shell), exec/write in `/tmp` or `/dev/shm`, unexpected `uid=0`, exec-then-
   connect chains. This is where the unified stream pays off, and the next
   milestone.
2. **Path resolution** for the file sensor (absolute paths via `d_path`).
3. **Real source port** for the network sensor (currently `sport=0`).
4. **Persistence/collector** — the JSON stream currently prints to stdout.
