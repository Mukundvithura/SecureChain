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

use crate::{EVENTS, MUTED, PENDING_SOCK, PID_PARENT, UDP_SOCKS};

const TCP_SYN_SENT: i32 = 2;
const AF_INET: u16 = 2;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u8 = 17;
/// `socket(2)` type argument, once `SOCK_CLOEXEC`/`SOCK_NONBLOCK` are masked off.
const SOCK_DGRAM: i64 = 2;
const SOCK_TYPE_MASK: i64 = 0xf;

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

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------
//
// `inet_sock_set_state` is a TCP state machine, so it says nothing about UDP —
// and that left DNS invisible. A payload resolving its C2 domain produced no
// event at all, even though the name it looks up is often the most identifying
// thing it does.
//
// There is no send-side tracepoint for UDP, and the kprobe that would give one
// (`udp_sendmsg`) means walking a `struct sock` through CO-RE/BTF — exactly what
// the TCP sensor avoids. So the destination is taken from the `sockaddr` the
// *syscall* was handed, which is stable ABI.
//
// **The event is emitted on send, never on connect.** `connect(2)` on a datagram
// socket transmits nothing; it only asks the kernel to fix a default peer. glibc
// leans on that hard: `getaddrinfo` sorts candidate addresses (RFC 3484) by
// connecting a throwaway UDP socket to each one purely to learn which route and
// source address the kernel would pick. A single `curl http://example.com`
// produces three such connects to port 80 without a byte leaving the host, and
// reporting them made the capture claim outbound UDP traffic that never existed.
//
// So `connect` only records where the socket points, and the send hooks emit:
//
//   * `sendto` — unconnected datagrams (`dig`, `nslookup`, `nc -u`), address in
//     the syscall's own argument.
//   * `sendmsg` / `sendmmsg` — glibc's resolver sends its A and AAAA queries
//     with one `sendmmsg` on a connected socket, so this is the path an ordinary
//     name lookup actually takes. The address comes from `msg_name` when it is
//     set, and otherwise from what `connect` recorded.
//
// All three hooks also fire for TCP sockets, which is what `UDP_SOCKS` is for:
// only an fd created as `AF_INET`/`SOCK_DGRAM` reaches the emit path.

/// What is remembered about a datagram socket between `connect(2)` and its
/// sends. `#[repr(C)]` because the verifier sees this as raw map-value bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpSock {
    /// Destination from `connect(2)`, or the last one reported. 0 when unknown.
    pub daddr: u32,
    pub dport: u16,
    /// 1 once a datagram to `daddr:dport` has been reported. A socket that sends
    /// continuously — an NTP client, a game — then costs one event per
    /// destination rather than one per packet.
    pub reported: u8,
    pub _pad: u8,
}

impl UdpSock {
    const EMPTY: UdpSock = UdpSock { daddr: 0, dport: 0, reported: 0, _pad: 0 };
}

/// `sockaddr_in`: `sin_family` u16, `sin_port` u16 (network order), `sin_addr`
/// u32 (network order). Read from *user* memory — this is the caller's buffer,
/// and the read helper faults gracefully rather than trusting the pointer.
#[inline(always)]
fn read_sockaddr_in(addr: *const u8) -> Option<(u32, u16)> {
    let family = unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u16>(addr as *const u16) };
    if family.ok()? != AF_INET {
        return None;
    }
    let port = unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u16>(addr.add(2) as *const u16) };
    let ip = unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u32>(addr.add(4) as *const u32) };
    // `sin_port` is network order; `NetPayload::dport` is host order, matching
    // what the TCP tracepoint hands us already ntohs-ed.
    Some((ip.ok()?, u16::from_be(port.ok()?)))
}

/// Emit one outbound-UDP event. Mirrors `try_connect`'s record except for
/// `proto`, so a consumer needs no special case. `saddr`/`sport` stay zero: the
/// syscall has not yet been through the stack that assigns them.
#[inline(always)]
fn submit_udp(pid: u32, daddr: u32, dport: u16) {
    let uid = helpers::bpf_get_current_uid_gid() as u32;
    let ppid = unsafe { PID_PARENT.get(&pid) }.copied().unwrap_or(0);

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
    event.payload.net.daddr = daddr;
    event.payload.net.dport = dport;
    event.payload.net.proto = IPPROTO_UDP;

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

/// `(pid, fd)` flattened into the `UDP_SOCKS` key. An fd number alone is not
/// unique — every process has its own fd 3.
#[inline(always)]
fn sock_key(pid: u32, fd: i64) -> u64 {
    ((pid as u64) << 32) | (fd as u32 as u64)
}

#[tracepoint]
pub fn socket_enter(ctx: TracePointContext) -> u32 {
    // socket(family, type, protocol): family@16, type@24. The type argument
    // carries SOCK_CLOEXEC/SOCK_NONBLOCK alongside the socket type.
    let family = unsafe { ctx.read_at::<i64>(16) }.unwrap_or(0);
    let ty = unsafe { ctx.read_at::<i64>(24) }.unwrap_or(0);
    if family != AF_INET as i64 || (ty & SOCK_TYPE_MASK) != SOCK_DGRAM {
        return 0;
    }
    // Keyed by tid, not pid: two threads can be inside socket() at once and
    // would otherwise overwrite each other's answer.
    let tid = helpers::bpf_get_current_pid_tgid() as u32;
    let _ = PENDING_SOCK.insert(&tid, &1u8, 0);
    0
}

#[tracepoint]
pub fn socket_exit(ctx: TracePointContext) -> u32 {
    let tid = helpers::bpf_get_current_pid_tgid() as u32;
    let is_dgram = unsafe { PENDING_SOCK.get(&tid) }.is_some();
    if is_dgram {
        let _ = PENDING_SOCK.remove(&tid);
    }
    // sys_exit_*: the return value sits at offset 16. A negative one is a failed
    // socket() and there is no fd to record either way.
    let fd = unsafe { ctx.read_at::<i64>(16) }.unwrap_or(-1);
    if fd < 0 {
        return 0;
    }
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let key = sock_key(pid, fd);
    if is_dgram {
        let _ = UDP_SOCKS.insert(&key, &UdpSock::EMPTY, 0);
    } else {
        // A non-datagram socket has just taken this fd number. Clear anything a
        // datagram socket left behind: fd reuse is immediate, and a stale entry
        // would make this socket's sends look like UDP.
        let _ = UDP_SOCKS.remove(&key);
    }
    0
}

/// `close(fd)`. fd numbers are reused the moment they are freed, so an entry
/// that outlives its socket is not a leak but a correctness bug.
#[tracepoint]
pub fn close_enter(ctx: TracePointContext) -> u32 {
    let fd = unsafe { ctx.read_at::<i64>(16) }.unwrap_or(-1);
    if fd < 0 {
        return 0;
    }
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = UDP_SOCKS.remove(&sock_key(pid, fd));
    0
}

/// `connect(fd, addr, addrlen)` — fd@16, addr@24. Records the peer; emits
/// nothing, because no datagram has been sent yet.
#[tracepoint]
pub fn udp_connect(ctx: TracePointContext) -> u32 {
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let fd = unsafe { ctx.read_at::<i64>(16) }.unwrap_or(-1);
    if fd < 0 {
        return 0;
    }
    let key = sock_key(pid, fd);
    if unsafe { UDP_SOCKS.get(&key) }.is_none() {
        return 0; // not a datagram socket we are tracking
    }
    let addr = match unsafe { ctx.read_at::<u64>(24) } {
        Ok(0) | Err(_) => return 0,
        Ok(p) => p as *const u8,
    };
    // A connect to AF_UNSPEC dissolves the association — glibc uses it between
    // its route probes. `read_sockaddr_in` returns None for it, which resets the
    // remembered peer, exactly as the kernel does.
    let next = match read_sockaddr_in(addr) {
        Some((daddr, dport)) => UdpSock { daddr, dport, reported: 0, _pad: 0 },
        None => UdpSock::EMPTY,
    };
    let _ = UDP_SOCKS.insert(&key, &next, 0);
    0
}

/// `sendto(fd, buff, len, flags, addr, addrlen)` — fd@16, addr@48.
#[tracepoint]
pub fn udp_sendto(ctx: TracePointContext) -> u32 {
    let addr = unsafe { ctx.read_at::<u64>(48) }.unwrap_or(0);
    udp_send(&ctx, addr as *const u8)
}

/// `sendmsg(fd, msghdr, flags)` — fd@16, msghdr@24. `msg_name` is the first
/// member of `struct msghdr`, so it sits at offset 0 of that buffer.
#[tracepoint]
pub fn udp_sendmsg(ctx: TracePointContext) -> u32 {
    udp_send(&ctx, msg_name(unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0)))
}

/// `sendmmsg(fd, mmsghdr, vlen, flags)` — fd@16, mmsghdr@24. `struct mmsghdr`
/// begins with its `msg_hdr`, so the offsets match `sendmsg` and the first
/// message's address is read the same way. One event per call, not per message:
/// glibc's resolver puts its A and AAAA queries in a single `sendmmsg` to the
/// same server.
#[tracepoint]
pub fn udp_sendmmsg(ctx: TracePointContext) -> u32 {
    udp_send(&ctx, msg_name(unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0)))
}

/// `msghdr.msg_name`, or null if there is no header to read it from. Null is
/// the normal case for a connected socket, and the caller falls back to the
/// peer `connect` recorded.
#[inline(always)]
fn msg_name(msghdr: u64) -> *const u8 {
    if msghdr == 0 {
        return core::ptr::null();
    }
    match unsafe { aya_ebpf::helpers::bpf_probe_read_user::<u64>(msghdr as *const u64) } {
        Ok(name) => name as *const u8,
        Err(_) => core::ptr::null(),
    }
}

/// Shared body of the three send hooks. Emits at most one event per socket per
/// destination — a send to the peer already reported adds nothing.
#[inline(always)]
fn udp_send(ctx: &TracePointContext, addr: *const u8) -> u32 {
    let pid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { MUTED.get(&pid) }.is_some() {
        return 0;
    }
    let fd = unsafe { ctx.read_at::<i64>(16) }.unwrap_or(-1);
    if fd < 0 {
        return 0;
    }
    let key = sock_key(pid, fd);
    let Some(sock) = (unsafe { UDP_SOCKS.get(&key) }).copied() else {
        return 0; // a TCP socket, or one created before we attached
    };

    // An explicit address wins; otherwise the socket is connected and the peer
    // is whatever `udp_connect` recorded.
    let (daddr, dport) = if addr.is_null() {
        (sock.daddr, sock.dport)
    } else {
        match read_sockaddr_in(addr) {
            Some(dest) => dest,
            None => (sock.daddr, sock.dport),
        }
    };
    if daddr == 0 {
        return 0; // nothing worth reporting a destination we never learned
    }
    if sock.reported == 1 && sock.daddr == daddr && sock.dport == dport {
        return 0; // already reported this destination for this socket
    }

    let _ = UDP_SOCKS.insert(&key, &UdpSock { daddr, dport, reported: 1, _pad: 0 }, 0);
    submit_udp(pid, daddr, dport);
    0
}
