//! File sensor: file opens with write intent (`EVENT_FILE`), hooked to
//! `syscalls/sys_enter_openat`.
//!
//! `openat` is a firehose — every library load, config read and `.so` mmap goes
//! through it — so emitting every call would drown the other sensors. We filter
//! to **write-intent** opens (write/read-write mode, create, truncate or
//! append), which is both far lower volume and the security-relevant slice:
//! dropped payloads, tampered configs, staged binaries.

use aya_ebpf::{helpers, macros::tracepoint, programs::TracePointContext};
use sensors_common::{EVENT_FILE, Event};

use crate::{EVENTS, MUTED, PID_PARENT};

// open(2) flags we care about (x86 Linux ABI).
const O_ACCMODE: i32 = 0o3; // mask for the read/write mode bits
const O_RDONLY: i32 = 0o0;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const O_APPEND: i32 = 0o2000;

#[inline(always)]
fn is_write(flags: i32) -> bool {
    (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0
}

#[inline(always)]
fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

// Pseudo-filesystem churn — shells hammer /dev/null on every prompt, and
// /proc//sys are constant background reads/writes with no supply-chain value.
// Dropped kernel-side so they never hit the ring buffer. /dev/shm is kept
// deliberately: it's a real place attackers stage payloads.
#[inline(always)]
fn is_noise_path(path: &[u8]) -> bool {
    (starts_with(path, b"/dev/") && !starts_with(path, b"/dev/shm/"))
        || starts_with(path, b"/proc/")
        || starts_with(path, b"/sys/")
}

#[tracepoint]
pub fn file_monitor(ctx: TracePointContext) -> u32 {
    match try_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// sys_enter_openat(dfd, filename, flags, mode). Syscall-enter tracepoints store
// each arg as an 8-byte slot starting at offset 16, so: dfd@16, filename@24,
// flags@32. We pull them with read_at (a bpf_probe_read under the hood) rather
// than dereferencing the ctx struct directly, which keeps us clear of the
// attach-time EACCES that a past-record-size read triggers.
fn try_open(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;

    // Same subtree mute as the process sensor (shared MUTED map).
    if unsafe { MUTED.get(&pid) }.is_some() {
        return Ok(0);
    }

    let flags = unsafe { ctx.read_at::<i64>(32) }.unwrap_or(0) as i32;
    if !is_write(flags) {
        return Ok(0);
    }

    let filename_ptr = match unsafe { ctx.read_at::<u64>(24) } {
        Ok(p) => p as *const u8,
        Err(_) => return Ok(0),
    };

    let uid = helpers::bpf_get_current_uid_gid() as u32;
    let ppid = unsafe { PID_PARENT.get(&pid) }.copied().unwrap_or(0);

    // Zero first (schema kernel-writer contract: no uninitialized union tail
    // leaks to userspace), then read the path straight into the payload field.
    let mut event: Event = unsafe { core::mem::zeroed() };
    event.header.timestamp = unsafe { helpers::bpf_ktime_get_ns() };
    event.header.pid = pid;
    event.header.ppid = ppid;
    event.header.uid = uid;
    event.header.kind = EVENT_FILE;
    if let Ok(comm) = helpers::bpf_get_current_comm() {
        event.header.comm = comm;
    }
    event.payload.file.flags = flags;

    // filename is a userspace pointer here (not a kernel __data_loc like exec).
    let path = match unsafe {
        helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut event.payload.file.path)
    } {
        Ok(p) => p,
        Err(_) => return Ok(0),
    };

    // Drop pseudo-filesystem noise before it reaches userspace.
    if is_noise_path(path) {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(0)
}
