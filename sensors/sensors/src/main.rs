use std::{
    ffi::CString,
    fs,
    io::{BufWriter, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use aya::{maps::RingBuf, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use sensors_common::Event;
use tokio::signal;

mod normalize;
use normalize::Normalizer;

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

    let net_prog: &mut TracePoint = ebpf.program_mut("network_monitor").unwrap().try_into()?;
    net_prog.load()?;
    net_prog.attach("sock", "inet_sock_set_state")?;

    // Every event is written to a capture file as well as stdout, so a session
    // is always recoverable without having remembered to pipe stdout somewhere.
    // Buffered — the flush happens on the way out of the shutdown path below.
    let capture_path = capture_path();
    if let Some(dir) = capture_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
        chown_to_sudo_user(dir);
    }
    let mut capture = BufWriter::new(fs::File::create(&capture_path)?);
    chown_to_sudo_user(&capture_path);
    eprintln!("Capturing to {}", capture_path.display());

    // Drain the shared ring buffer: decode each sample into an `Event` and emit
    // it as one normalized JSON line. The BPF ring buffer fd is epoll-able, so
    // we poll it with the same tokio AsyncFd pattern the logger uses.
    let events = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?;
    let ring = RingBuf::try_from(events)?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;

    // Enrichment state lives across the whole session: the process table the
    // normalizer builds is what lets an event name a parent that has already
    // exited.
    let mut normalizer = Normalizer::new();

    // Drain and wait for the shutdown signal in the *same* task rather than
    // spawning the drain: at shutdown we still own the ring buffer, so we can
    // take one last pass over it before flushing instead of losing whatever
    // landed after the final readable wakeup. `readable_mut()` is cancel-safe,
    // so losing the select race costs nothing.
    //
    // SIGTERM as well as Ctrl-C: a `kill` from a script or a service manager
    // should still flush the capture rather than truncate it mid-buffer.
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut ctrl_c = Box::pin(signal::ctrl_c());
    let mut written = 0u64;
    eprintln!("Waiting for Ctrl-C...");
    loop {
        tokio::select! {
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                written += drain(guard.get_inner_mut(), &mut capture, &mut normalizer);
                guard.clear_ready();
            }
            res = &mut ctrl_c => {
                res?;
                break;
            }
            _ = sigterm.recv() => break,
        }
    }
    eprintln!("Exiting...");

    written += drain(async_fd.get_mut(), &mut capture, &mut normalizer);
    capture.flush()?;
    eprintln!("Wrote {written} events to {}", capture_path.display());

    Ok(())
}

/// Emit every sample currently in the ring buffer to stdout and the capture
/// file, returning how many were written. A capture-file write error is
/// reported once per event and otherwise ignored: losing the log is not a
/// reason to stop monitoring.
fn drain(
    ring: &mut RingBuf<aya::maps::MapData>,
    capture: &mut impl Write,
    normalizer: &mut Normalizer,
) -> u64 {
    let mut written = 0;
    while let Some(item) = ring.next() {
        let Some(event) = Event::from_bytes(&item) else {
            continue;
        };
        let Some(line) = normalizer.normalize(&event) else {
            warn!("unknown event kind {}", event.header.kind);
            continue;
        };
        println!("{line}");
        if let Err(e) = writeln!(capture, "{line}") {
            warn!("capture write failed: {e}");
        }
        written += 1;
    }
    written
}

/// Where the capture lands: `$SECRISK_CAPTURE` if set, else a timestamped file
/// under `captures/` in the working directory.
fn capture_path() -> PathBuf {
    match std::env::var_os("SECRISK_CAPTURE") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from("captures").join(format!("sensors-{}.jsonl", local_timestamp())),
    }
}

/// `YYYYmmdd-HHMMSS` in local time, via libc — the tree has no date/time crate
/// and this is the only wall-clock the loader needs.
fn local_timestamp() -> String {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid time_t and `tm` is a live, writable `struct tm`.
    unsafe { libc::localtime_r(&now, &mut tm) };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// The sensor runs under `sudo`, so anything it creates is root-owned. Hand the
/// capture back to the invoking user, otherwise reading, deleting or pasting it
/// into the viewer all need sudo too. Best-effort: not running under sudo, or a
/// chown failure, is not worth aborting a capture over.
fn chown_to_sudo_user(path: &Path) {
    let uid = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
    let gid = std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok());
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        debug!("chown of {} to {uid}:{gid} failed", path.display());
    }
}
