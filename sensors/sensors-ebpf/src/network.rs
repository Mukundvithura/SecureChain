//! Network sensor: outbound TCP connect attempts (`EVENT_NET`), hooked to
//! `sock/inet_sock_set_state`.
//!
//! That tracepoint fires on every TCP state change; the transition **into
//! `TCP_SYN_SENT`** is a process actively initiating an outbound connection —
//! exactly the supply-chain signal we want (a build tool or dropped binary
//! phoning out). Using the tracepoint (stable, fixed-format record) avoids the
//! CO-RE/BTF `struct sock` chasing a `tcp_connect` kprobe would need.

use aya_ebpf::{helpers, macros::tracepoint, programs::TracePointContext};
use sensors_common::{EVENT_NET, Event};

use crate::{EVENTS, MUTED, PID_PARENT};

const TCP_SYN_SENT: i32 = 2;
const AF_INET: u16 = 2;
const IPPROTO_TCP: u16 = 6;

#[tracepoint]
pub fn network_monitor(ctx: TracePointContext) -> u32 {
    match try_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// inet_sock_set_state record (see the live format): newstate@20, sport@24,
// dport@26, family@28, protocol@30, saddr@32, daddr@36. Ports are already host
// byte order here (the kernel ntohs-es them); addresses are raw network-order
// bytes, transported verbatim. Read via read_at (bpf_probe_read) to stay clear
// of the attach-time EACCES.
fn try_connect(ctx: TracePointContext) -> Result<u32, u32> {
    // Only the transition into SYN_SENT (an outbound connect being initiated).
    let newstate = unsafe { ctx.read_at::<i32>(20) }.unwrap_or(0);
    if newstate != TCP_SYN_SENT {
        return Ok(0);
    }

    // IPv4/TCP only for now (NetPayload is v4).
    let family = unsafe { ctx.read_at::<u16>(28) }.unwrap_or(0);
    let protocol = unsafe { ctx.read_at::<u16>(30) }.unwrap_or(0);
    if family != AF_INET || protocol != IPPROTO_TCP {
        return Ok(0);
    }

    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { MUTED.get(&pid) }.is_some() {
        return Ok(0);
    }
    let uid = helpers::bpf_get_current_uid_gid() as u32;
    let ppid = unsafe { PID_PARENT.get(&pid) }.copied().unwrap_or(0);

    let sport = unsafe { ctx.read_at::<u16>(24) }.unwrap_or(0);
    let dport = unsafe { ctx.read_at::<u16>(26) }.unwrap_or(0);
    let saddr = unsafe { ctx.read_at::<u32>(32) }.unwrap_or(0);
    let daddr = unsafe { ctx.read_at::<u32>(36) }.unwrap_or(0);

    // Zero first (schema kernel-writer contract), then fill.
    let mut event: Event = unsafe { core::mem::zeroed() };
    event.header.timestamp = unsafe { helpers::bpf_ktime_get_ns() };
    event.header.pid = pid;
    event.header.ppid = ppid;
    event.header.uid = uid;
    event.header.kind = EVENT_NET;
    if let Ok(comm) = helpers::bpf_get_current_comm() {
        event.header.comm = comm;
    }
    event.payload.net.saddr = saddr;
    event.payload.net.daddr = daddr;
    event.payload.net.sport = sport;
    event.payload.net.dport = dport;
    event.payload.net.proto = protocol as u8;

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(0)
}
