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
mod process;

// Single ring buffer carrying every sensor's events to userspace. 256 KiB
// (power-of-2 multiple of the page size, as the kernel requires).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// child_pid -> parent_pid, populated by the sched_process_fork tracepoint;
// every sensor consults it to attach parent lineage to its events.
#[map]
static PID_PARENT: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

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
