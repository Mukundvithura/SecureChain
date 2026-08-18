# Sensors — Design & Build Notes

eBPF sensor suite for the SecRisk supply-chain attack detection project. All
sensors live in one BPF object, emit a single unified event type into one ring
buffer, and are drained by one userspace loader that normalizes and enriches
each event into a JSON line. This document summarises what was built, the
problems hit along the way, and how to run/verify it.

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
sensor programs ──> EVENTS ring buffer ──> loader ──> normalizer ──> JSON line / event
(process, file,     (256 KiB, shared)      (tokio    (clock, /proc,   (stdout + capture)
 network)                                  AsyncFd)   path resolution)
```

The split is deliberate: the kernel side captures only what it can capture
cheaply and safely, and everything that needs context — a wall clock, a process
table, a working directory — happens in userspace, where it costs nothing in
the verifier and nothing in the hot path of a traced syscall. §7 covers that
half.

**Shared schema** (`sensors-common`): every sensor emits the same fixed-size
`#[repr(C)]` `Event` — a common `EventHeader` (`timestamp, pid, ppid, uid, kind,
comm`) plus a tagged `Payload` union selected by `kind`:

| `kind` | Payload | Fields |
|--------|---------|--------|
| `EVENT_EXEC` | `ExecPayload` | `filename[256]` |
| `EVENT_FILE` | `FilePayload` | `path[256]`, `flags`, `dfd` |
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

The path is captured **raw**, exactly as the caller passed it, along with the
directory fd from arg 0 (`dfd`, record offset 16). Resolution happens in
userspace (§7) — a BPF program would need `d_path` on a `struct file` this
tracepoint never hands it, while the loader gets the same answer for free by
reading a `/proc` link. Carrying `dfd` is what makes that resolution *correct*
rather than merely plausible: without it an open relative to some directory
other than the cwd cannot be told apart from one relative to the cwd.

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
| `BPF_PROG_LOAD … Invalid argument`, "last insn is not an exit or jmp", `processed 0 insns` | direct index (`path[off + i]`) on a **runtime-length** slice — LLVM can't prove it in bounds, emits a bounds-check panic; the panic handler diverges (`loop {}`), so that cold block ends in a `call` with no `exit`, and LLVM parked it **last** in `file_monitor` | index via `path.get(i)` — no panic path is generated at all. Verify with `llvm-objdump -d --section=tracepoint <obj>`: every program must end in `exit` or a `goto` |
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

## 7. Normalization & enrichment (`sensors/src/normalize.rs`)

A raw event carries only what a BPF program can cheaply see: a boot-relative
timestamp, a pid, a 16-byte `comm`, and whatever parent the fork map happened to
know. That is not enough to correlate on, so the loader closes three gaps before
anything is written out. Everything here is best-effort and **a field that
cannot be established is omitted** — absence means unknown, so no consumer has
to tell a real zero from a missing one.

### Time
`bpf_ktime_get_ns()` counts from boot, so a raw `ts` cannot be placed on a clock
or joined against any other log. The loader samples `CLOCK_MONOTONIC` and
`CLOCK_REALTIME` once at startup and carries that fixed offset, emitting `ts`
(epoch nanoseconds) and `time` (RFC 3339, local).

The offset is sampled **once**, not per event: re-sampling would track NTP steps
and resumes more accurately, but it could also give a later event an earlier
timestamp than one already emitted, and every consumer that sorts or windows
events depends on `ts` being monotonic. The cost is drift from true wall-clock
if the machine suspends mid-capture.

### Identity
On an exec the loader learns a process firsthand and records it; for anything
that predates the capture it reads `/proc`, and caches either way (4096 pids,
oldest evicted). That gives every event:

| Field | Source |
|-------|--------|
| `ppid` | the event, else backfilled from `/proc/<pid>/stat` |
| `user` | `/etc/passwd`, read once |
| `exe` | the exec event itself, else `/proc/<pid>/exe` |
| `cmdline` | `/proc/<pid>/cmdline`, NUL-joined, capped at 512 chars |
| `container` | 12-hex id parsed out of `/proc/<pid>/cgroup` |
| `ancestry` | `[{pid, comm}, …]`, walked up to 8 levels |

The cache is what makes `ancestry` worth having: once `npm` has exited, `/proc`
can no longer say that the payload descended from it, but an entry recorded at
its exec still can. `comm` stays exactly as the kernel reported it — for a
threaded process that is the *thread* name (`Cache2 I/O`, not `firefox`), which
says which part of a process acted; `exe` carries the process identity.

### Paths
`openat` records its path argument verbatim, so a relative open reaches
userspace as `credentials.txt` with no indication of where that is. The loader
resolves it against whichever directory the syscall actually named —
`/proc/<pid>/cwd` for `AT_FDCWD`, otherwise `/proc/<pid>/fd/<dfd>` — then cleans
`.`/`..`/`//` **lexically**. Not `canonicalize()`: by the time the event is read
the path may be gone, or be a symlink to somewhere other than it was. The
original is kept as `path_raw` whenever resolution changed it.

Honouring `dfd` is not a nicety. The first live capture after this landed caught
`sudo` doing `openat(<fd for /run/sudo/ts>, "1000", …)`; resolved against the cwd
that becomes `/home/mukunda/SecRisk/sensors/1000`, a path nothing ever opened.
A confidently wrong absolute path is worse for a correlation rule than an
unresolved one, so when neither link can be read — the process exited first,
which for short-lived ones is common — the raw argument is returned unchanged
rather than resolved against a guess. Both links are read live and never cached:
a process can `chdir` between opens, and fd numbers are reused constantly.

### Record shape
One flat record per event: a common envelope, then the type-specific fields.
`action` flattens the per-type reasons (`exec`, `write`, `secret_read`,
`connect`) so a consumer can switch on one field.

```
ts  time  type  action  pid  ppid  uid  user  comm  exe  cmdline  container  ancestry  <typed>
```

`ts` is epoch **nanoseconds**, which exceeds JavaScript's safe integer range —
fine for the Rust/Postgres path this feeds, and lossy to ~256 ns for anything
that reads it through `JSON.parse` (the demo viewer, which only ever uses it for
ordering and deltas).

---

## 8. Build & run

```bash
cd sensors
cargo build                                   # builds eBPF object + userspace (no root)
RUST_LOG=info sudo -E env PATH="$PATH" cargo run
```

Generate events in a second terminal (`ls`; `echo hi > /tmp/x`; `curl google.com`).
Stop with Ctrl-C. Events are JSON on **stdout**; status/errors on **stderr** (so
`… | jq .` works cleanly).

Sample output — note the exec→connect chain on one pid, and that both events
name the same ancestry (the correlation payoff):
```json
{"ts":1787047040487878347,"time":"2026-08-18T15:27:20.487878347+05:30","type":"exec","action":"exec","pid":41761,"ppid":41760,"uid":1000,"user":"mukunda","comm":"curl","exe":"/usr/bin/curl","cmdline":"curl -s -o /dev/null --max-time 5 http://example.com/","ancestry":[{"pid":41760,"comm":"sh"},{"pid":41758,"comm":"npm-install.sh"}],"path":"/usr/bin/curl"}
{"ts":1787047040579034810,"time":"2026-08-18T15:27:20.579034810+05:30","type":"net","action":"connect","pid":41761,"ppid":41760,"uid":1000,"user":"mukunda","comm":"curl","exe":"/usr/bin/curl","cmdline":"curl -s -o /dev/null --max-time 5 http://example.com/","ancestry":[{"pid":41760,"comm":"sh"},{"pid":41758,"comm":"npm-install.sh"}],"saddr":"192.168.159.128","sport":0,"daddr":"93.184.216.34","dport":80,"proto":6}
{"ts":1787047040118181744,"time":"2026-08-18T15:27:20.118181744+05:30","type":"file","action":"secret_read","pid":41759,"ppid":41758,"uid":1000,"user":"mukunda","comm":"cat","exe":"/usr/bin/cat","cmdline":"cat /tmp/secrisk-demo/home/.ssh/id_rsa","ancestry":[{"pid":41758,"comm":"npm-install.sh"}],"path":"/tmp/secrisk-demo/home/.ssh/id_rsa","flags":0}
```

`ppid=0` now means genuinely unattributable: the loader backfills a parent from
`/proc` for processes that predate the capture, so only one that also exited
before it could be read stays unlinked.

### Inspect the loaded programs
```bash
sudo bpftool prog show     # progs: process_monitor / sched_fork / file_monitor / network_monitor
sudo bpftool link show     # links to sched_process_exec, sched_process_fork, sys_enter_openat, inet_sock_set_state
sudo bpftool map show      # EVENTS (ringbuf), PID_PARENT (hash), MUTED (lru_hash)
```

---

## 9. Status & next steps

**Working:** the full sensor triad — process + file + network — in one BPF
object, unified `Event` schema, ring-buffer transport, per-sensor kernel-side
noise filtering, verifier-clean on kernel 6.19; and in userspace the normalizer
of §7 — wall-clock timestamps, `/proc` enrichment (`user`, `exe`, `cmdline`,
`container`), ppid backfill, multi-level `ancestry`, and `dfd`-correct absolute
paths. Lineage links events across sensors (e.g. exec→connect on one pid), and
now survives the ancestor exiting.

**Not done yet:**
1. **Correlation + detection** — suspicious lineage (build tool → downloader →
   shell), exec/write in `/tmp` or `/dev/shm`, unexpected `uid=0`, exec-then-
   connect chains. This is where the unified stream pays off, and the next
   milestone. The demo viewer prototypes the grouping in JS; the engine itself
   is unwritten.
2. **Real source port** for the network sensor (currently `sport=0`).
3. **IPv6** — `NetPayload` is v4-only; the union has room for a `family` field
   and v6 addresses without disturbing the other variants.
4. **Persistence/collector** — events go to stdout and a JSONL capture file;
   nothing writes them to PostgreSQL yet.
