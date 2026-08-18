#![no_std]

//! Shared event schema for the SecRisk eBPF sensors.
//!
//! Every sensor — process (`sched_process_exec`), file (`openat`), network
//! (`tcp_connect`) — emits the **same** [`Event`] type into a single ring
//! buffer, so the userspace reader has one code path to deserialize and
//! normalize regardless of source. That single normalizer is the whole point:
//! correlation reasons over a uniform event stream.
//!
//! An [`Event`] is a fixed-size `#[repr(C)]` value — a common [`EventHeader`]
//! plus a tagged [`Payload`] union selected by [`EventHeader::kind`]. Fixed size
//! (a union rather than variable-length records) keeps both the kernel writer
//! and the userspace reader trivial; the bytes wasted on small events (e.g. a
//! net event carrying a 264-byte payload slot) are irrelevant at prototype
//! scale.
//!
//! ## Kernel writer contract
//! The ring-buffer slot is **uninitialized** kernel memory. Sensors MUST zero
//! the whole `Event` before filling it — writing only the small `Net` variant
//! would otherwise leak the uninitialized tail of the union (kernel stack/heap
//! bytes) to userspace. Build a zeroed `Event` on the stack, fill it, then
//! submit. `size_of::<Event>()` is ~304 B, well within the 512 B BPF stack.

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

// `EventHeader::kind` discriminants. Deliberately a plain `u8` with associated
// consts rather than a Rust enum: the value is written kernel-side and
// reinterpreted from raw bytes userside, and an out-of-range enum discriminant
// would be undefined behaviour — a `u8` never is.
pub const EVENT_EXEC: u8 = 0;
pub const EVENT_FILE: u8 = 1;
pub const EVENT_NET: u8 = 2;

// `FilePayload::reason` — why the file open was emitted. A write is the common
// case; a secret read is a read of a watchlisted sensitive path (credential/key
// theft), which the sensor otherwise drops along with the read firehose.
pub const FILE_WRITE: u8 = 0;
pub const FILE_SECRET_READ: u8 = 1;

/// `FilePayload::dfd` when the open resolves against the process's cwd — the
/// value the plain `open`/`openat(AT_FDCWD, …)` path passes.
pub const AT_FDCWD: i32 = -100;

/// Fields common to every event, filled the same way by every sensor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    /// `bpf_ktime_get_ns()` at capture (monotonic, nanoseconds).
    pub timestamp: u64,
    /// Thread-group id (the "pid" userspace means) of the acting process.
    pub pid: u32,
    /// Parent pid from the fork-tracked `PID_PARENT` map; `0` if unknown.
    pub ppid: u32,
    pub uid: u32,
    /// One of the `EVENT_*` consts; selects the active [`Payload`] variant.
    pub kind: u8,
    pub _pad: [u8; 3],
    /// `bpf_get_current_comm()` — NUL-padded, not guaranteed NUL-terminated.
    pub comm: [u8; COMM_LEN],
}

/// `sched_process_exec`: a successful exec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecPayload {
    /// Resolved binary path, NUL-terminated (truncated if longer than the buf).
    pub filename: [u8; PATH_LEN],
}

/// `openat`/`openat2`: a file open.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilePayload {
    /// Path argument, NUL-terminated (truncated if longer than the buf). Raw —
    /// `openat` records whatever the caller passed, so this is relative
    /// whenever the caller's was; `dfd` says what it is relative *to*.
    pub path: [u8; PATH_LEN],
    /// Open flags (`O_WRONLY`, `O_CREAT`, …).
    pub flags: i32,
    /// The directory fd `path` resolves against when `path` is relative:
    /// [`AT_FDCWD`] for the process's cwd, otherwise an fd userspace resolves
    /// through `/proc/<pid>/fd/<dfd>`. Carried rather than resolved in-kernel —
    /// walking a path in BPF means `d_path` on a `struct file` the tracepoint
    /// does not hand us, and userspace can read the link for free.
    pub dfd: i32,
    /// One of the `FILE_*` consts: why this open was emitted (write vs secret read).
    pub reason: u8,
    pub _pad: [u8; 3],
}

/// `tcp_connect`: an outbound connection attempt. IPv4 for now; a `family`
/// field / v6 addresses can be added without disturbing the other variants.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetPayload {
    /// Destination address, network byte order.
    pub daddr: u32,
    /// Source address, network byte order.
    pub saddr: u32,
    /// Destination port, host byte order.
    pub dport: u16,
    /// Source port, host byte order.
    pub sport: u16,
    /// `IPPROTO_*`.
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Payload selected by [`EventHeader::kind`]. Reading the wrong variant is
/// unsafe (it's a union) — always branch on `kind` first.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Payload {
    pub exec: ExecPayload,
    pub file: FilePayload,
    pub net: NetPayload,
}

/// One record in the ring buffer, from any sensor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub header: EventHeader,
    pub payload: Payload,
}

impl Event {
    /// Decode a ring-buffer sample into an owned `Event`, or `None` if the
    /// sample is too small. Uses an unaligned read so it's sound regardless of
    /// the sample's alignment; the caller then branches on `header.kind` before
    /// touching `payload`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Event> {
        if bytes.len() < core::mem::size_of::<Event>() {
            return None;
        }
        // SAFETY: length checked above; every field is an integer or byte array
        // so all bit patterns are valid, and `read_unaligned` needs no alignment.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) })
    }
}

/// The meaningful prefix of a NUL-padded fixed buffer (`comm`, `filename`,
/// `path`) — everything up to the first NUL, or the whole buffer if unterminated.
/// Userspace-only; not called from eBPF (a scan like this over `PATH_LEN` bytes
/// blows the verifier's instruction budget).
pub fn cstr(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(i) => &buf[..i],
        None => buf,
    }
}

// Assert `aya::Pod` for typed userspace access (e.g. if events are ever stashed
// in an aya map). Sound because `Event` is `#[repr(C)]`, `Copy`, and every field
// is plain-old-data with explicit padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
