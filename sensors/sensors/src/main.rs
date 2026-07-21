use aya::maps::RingBuf;
use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use sensors_common::{EVENT_EXEC, EVENT_FILE, Event, cstr};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sensors"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    // Track parent PIDs first so forks are recorded before we observe execve.
    let fork_prog: &mut TracePoint = ebpf.program_mut("sched_fork").unwrap().try_into()?;
    fork_prog.load()?;
    fork_prog.attach("sched", "sched_process_fork")?;

    let program: &mut TracePoint = ebpf.program_mut("process_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let file_prog: &mut TracePoint = ebpf.program_mut("file_monitor").unwrap().try_into()?;
    file_prog.load()?;
    file_prog.attach("syscalls", "sys_enter_openat")?;

    // Drain the shared ring buffer: decode each sample into an `Event` and emit
    // it as one normalized JSON line. The BPF ring buffer fd is epoll-able, so
    // we poll it with the same tokio AsyncFd pattern the logger uses.
    let events = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?;
    let ring = RingBuf::try_from(events)?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;
    tokio::task::spawn(async move {
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                if let Some(event) = Event::from_bytes(&item) {
                    emit(&event);
                }
            }
            guard.clear_ready();
        }
    });

    let ctrl_c = signal::ctrl_c();
    eprintln!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    eprintln!("Exiting...");

    Ok(())
}

// Print one normalized JSON line per event. Manual formatting keeps the loader
// dependency-free; switch to serde_json if the schema grows.
fn emit(event: &Event) {
    let h = &event.header;
    let comm = String::from_utf8_lossy(cstr(&h.comm));
    match h.kind {
        EVENT_EXEC => {
            // SAFETY: kind == EVENT_EXEC guarantees the `exec` union variant.
            let path = String::from_utf8_lossy(cstr(unsafe { &event.payload.exec.filename }));
            println!(
                "{{\"ts\":{},\"type\":\"exec\",\"pid\":{},\"ppid\":{},\"uid\":{},\"comm\":{},\"path\":{}}}",
                h.timestamp,
                h.pid,
                h.ppid,
                h.uid,
                json_str(&comm),
                json_str(&path),
            );
        }
        EVENT_FILE => {
            // SAFETY: kind == EVENT_FILE guarantees the `file` union variant.
            let file = unsafe { &event.payload.file };
            let path = String::from_utf8_lossy(cstr(&file.path));
            println!(
                "{{\"ts\":{},\"type\":\"file\",\"pid\":{},\"ppid\":{},\"uid\":{},\"comm\":{},\"path\":{},\"flags\":{}}}",
                h.timestamp,
                h.pid,
                h.ppid,
                h.uid,
                json_str(&comm),
                json_str(&path),
                file.flags,
            );
        }
        // net variant lands here until that sensor exists.
        other => eprintln!("unknown event kind {other}"),
    }
}

// A JSON string literal (quoted, with the mandatory escapes) for `s`.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
