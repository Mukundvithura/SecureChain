#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, helpers,
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

// child_pid -> parent_pid, populated by the sched_process_fork tracepoint.
#[map]
static PID_PARENT: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

// pids whose execve events we suppress: the noisy vpnip panel widget and any
// process descended from it. LRU so old entries self-evict (no leak).
#[map]
static MUTED: LruHashMap<u32, u8> = LruHashMap::with_max_entries(1024, 0);

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

    let mut buf = [0u8; 64];
    let filename = match unsafe { helpers::bpf_probe_read_kernel_str_bytes(src, &mut buf) } {
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

    info!(
        &ctx,
        "exec pid={} ppid={} uid={} path={}",
        pid,
        ppid,
        uid,
        unsafe { core::str::from_utf8_unchecked(filename) }
    );
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
