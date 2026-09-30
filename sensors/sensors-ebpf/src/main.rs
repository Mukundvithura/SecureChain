#![no_std]
#![no_main]

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, RingBuf},
};

// One module per sensor. Each contributes its own tracepoint program(s) but they
// all share the maps declared below and emit into the single `EVENTS` ring
// buffer, so userspace has one stream to drain.
mod file;
mod network;
mod process;

// Single ring buffer carrying every sensor's events to userspace. 256 KiB
// (power-of-2 multiple of the page size, as the kernel requires).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// child_pid -> parent_pid, populated by the sched_process_fork tracepoint;
// every sensor consults it to attach parent lineage to its events.
#[map]
static PID_PARENT: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

// (pid<<32 | fd) for sockets created as AF_INET/SOCK_DGRAM. `connect` and
// `sendto` carry only an fd, and a syscall tracepoint cannot ask the kernel what
// protocol sits behind it — so the answer is recorded at socket() time and
// looked up later. Without this the UDP hooks would also fire on every TCP
// connect and duplicate what the inet_sock_set_state sensor already reports.
// Entries are removed on close(2) and whenever a non-datagram socket takes an
// fd number, because fd reuse is immediate: a stale entry does not merely leak,
// it makes the next TCP connect on that number emit a bogus UDP event. LRU on
// top of that, for the fds that change hands through paths nothing here watches.
#[map]
static UDP_SOCKS: LruHashMap<u64, network::UdpSock> = LruHashMap::with_max_entries(8192, 0);

// tid -> "the socket() now in flight is AF_INET/SOCK_DGRAM". socket() reports
// its family and type on entry but its fd only on exit, so the two halves are
// bridged here. Keyed by tid, not pid: two threads can be inside socket() at
// once, and they would overwrite each other's answer.
#[map]
static PENDING_SOCK: LruHashMap<u32, u8> = LruHashMap::with_max_entries(1024, 0);

// pids whose events we suppress: the noisy vpnip panel widget and any process
// descended from it. LRU so old entries self-evict (no leak).
#[map]
static MUTED: LruHashMap<u32, u8> = LruHashMap::with_max_entries(1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
