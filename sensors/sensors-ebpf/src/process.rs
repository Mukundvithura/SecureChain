//! Process sensor: successful execs (`EVENT_EXEC`) plus the fork tracepoint that
//! maintains the shared `PID_PARENT` lineage map and propagates muting.

use aya_ebpf::{EbpfContext, helpers, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use sensors_common::{EVENT_EXEC, Event};

use crate::{EVENTS, MUTED, PID_PARENT};

// Known-benign periodic widget that polls every second and spawns ip/cut/head/grep.
const VPNIP: &[u8] = b"/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh";

// kernel 6.19 layout: comm fields are __data_loc descriptors (4 bytes each).
//   0: common(8)  8: parent_comm  12: parent_pid  16: child_comm  20: child_pid
#[repr(C)]
struct SchedProcessForkArgs {
    _common: [u8; 8],
    parent_comm: u32,
    parent_pid: i32,
    child_comm: u32,
    child_pid: i32,
}

#[inline(always)]
fn is_vpnip(path: &[u8]) -> bool {
    if path.len() != VPNIP.len() {
        return false;
    }
    let mut i = 0;
    while i < VPNIP.len() {
        if path[i] != VPNIP[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[tracepoint]
pub fn process_monitor(ctx: TracePointContext) -> u32 {
    match try_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// Hooked to sched/sched_process_exec: fires once per *successful* exec (unlike
// sys_enter_execve, which fires on every PATH-probe attempt). One event per
// launch, always the final resolved binary.
fn try_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = helpers::bpf_get_current_uid_gid() as u32;
    let ppid = unsafe { PID_PARENT.get(&pid) }.copied().unwrap_or(0);

    // This pid is in a muted subtree (mute is propagated at fork time, so even
    // non-exec'ing subshells taint their descendants). Drop the event.
    if unsafe { MUTED.get(&pid) }.is_some() {
        return Ok(0);
    }

    // `filename` is a __data_loc descriptor at offset 8: the low 16 bits are the
    // byte offset (within this record) to the inline string. Read it via the
    // bpf_probe_read helpers rather than a direct ctx deref to stay inside the
    // record bounds the verifier enforces at attach time.
    let desc = match unsafe { ctx.read_at::<u32>(8) } {
        Ok(d) => d,
        Err(_) => return Ok(0),
    };
    let str_off = (desc & 0xffff) as usize;
    let src = (ctx.as_ptr() as usize + str_off) as *const u8;

    // Build a fully-zeroed Event on the stack, then read the exec path straight
    // into its filename field. Zeroing first satisfies the schema's kernel-writer
    // contract (no uninitialized union tail leaks to userspace); reading in place
    // avoids a second 256-byte buffer — Event alone is ~304 B against a 512 B
    // BPF stack.
    let mut event: Event = unsafe { core::mem::zeroed() };
    event.header.timestamp = unsafe { helpers::bpf_ktime_get_ns() };
    event.header.pid = pid;
    event.header.ppid = ppid;
    event.header.uid = uid;
    event.header.kind = EVENT_EXEC;
    if let Ok(comm) = helpers::bpf_get_current_comm() {
        event.header.comm = comm;
    }

    let filename = match unsafe {
        helpers::bpf_probe_read_kernel_str_bytes(src, &mut event.payload.exec.filename)
    } {
        Ok(f) => f,
        Err(_) => {
            info!(&ctx, "exec pid={} ppid={} uid={} path=<unreadable>", pid, ppid, uid);
            return Ok(0);
        }
    };

    // Mute the widget itself and drop its event.
    if is_vpnip(filename) {
        let _ = MUTED.insert(&pid, &1u8, 0);
        return Ok(0);
    }

    // Emit into the ring buffer; if it's full, drop rather than block.
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(0)
}

#[tracepoint]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    match try_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let args = unsafe { &*(ctx.as_ptr() as *const SchedProcessForkArgs) };
    let parent_pid = args.parent_pid as u32;
    let child_pid = args.child_pid as u32;
    let _ = PID_PARENT.insert(&child_pid, &parent_pid, 0);

    // Propagate muting down the whole subtree: if the parent is muted, so is
    // the child. This catches subshells that fork but never execve.
    if unsafe { MUTED.get(&parent_pid) }.is_some() {
        let _ = MUTED.insert(&child_pid, &1u8, 0);
    }
    Ok(0)
}
