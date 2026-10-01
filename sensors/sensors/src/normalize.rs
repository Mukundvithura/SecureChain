//! Normalization and enrichment: one raw ring-buffer [`Event`] in, one
//! self-contained JSON record out.
//!
//! The sensors deliberately do almost nothing in-kernel beyond capture — the
//! verifier makes anything else expensive, and the kernel has no business
//! walking `/proc`. So the raw stream has three gaps that make it hard to
//! correlate, and this module closes them:
//!
//! 1. **Time.** `bpf_ktime_get_ns()` counts nanoseconds since boot, so a raw
//!    event cannot be placed on a clock or joined against any other log. We
//!    sample `CLOCK_MONOTONIC`/`CLOCK_REALTIME` once at startup and carry that
//!    fixed offset, turning every event into an epoch timestamp.
//! 2. **Identity.** A sensor sees a pid, a 16-byte `comm` (which for a threaded
//!    process is the *thread* name), and whatever parent the fork map knew. It
//!    does not know the binary, the argv, the user, or the container. Those come
//!    from `/proc`, cached per pid.
//! 3. **Paths.** `openat` records the path argument verbatim, so a relative
//!    open lands in the stream as `credentials.txt` with no indication of where
//!    that is. We resolve it against the directory the syscall named.
//!
//! Everything beyond the kernel's own facts is best-effort: a process can exit
//! before we get to `/proc`, and short-lived execs frequently do. A field we
//! could not establish is **omitted** rather than guessed — absence means
//! unknown, and no consumer has to distinguish a real zero from a missing one.

use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    fs,
};

use log::debug;
use sensors_common::{AT_FDCWD, EVENT_EXEC, EVENT_FILE, EVENT_NET, Event, FILE_SECRET_READ, cstr};

/// Enrichment cached per pid. Bounded because a busy host churns through pids
/// and nothing in this process ever learns that one exited.
const PROC_CACHE_CAP: usize = 4096;
/// How far up the parent chain to walk. Deep enough for a package-manager →
/// shell → hook → payload chain, bounded so a cycle or a pathological tree
/// cannot stall the drain loop.
const ANCESTRY_MAX: usize = 8;
/// Long argv (a linker line, a `find` invocation) is truncated rather than
/// dropped — the head is the part that identifies the command.
const CMDLINE_MAX: usize = 512;

pub struct Normalizer {
    clock: Clock,
    users: HashMap<u32, String>,
    procs: ProcTable,
    /// Our own pid, so the sensor does not report on itself.
    self_pid: u32,
    /// Extra substrings from `$SECRISK_MUTE`, suppressed alongside the built-in
    /// patterns. Keeping the site-specific half in configuration is what lets
    /// the compiled-in list stay short and defensible.
    extra_mutes: Vec<String>,
}

impl Normalizer {
    pub fn new() -> Self {
        Normalizer {
            clock: Clock::capture(),
            users: load_users(),
            procs: ProcTable::default(),
            self_pid: std::process::id(),
            extra_mutes: load_extra_mutes(),
        }
    }

    /// One JSON line for `event`, or `None` for an event kind we don't know.
    pub fn normalize(&mut self, event: &Event) -> Option<String> {
        let h = &event.header;
        let pid = h.pid;
        // The event's `comm` is the *thread* name (`bpf_get_current_comm`), which
        // for something like Firefox reads `Cache2 I/O` rather than `firefox`.
        // It is kept verbatim — it says which part of a process acted — while
        // `exe` below carries the process identity.
        let comm = String::from_utf8_lossy(cstr(&h.comm)).into_owned();

        // The sensor's own activity — the capture file it is writing, most
        // obviously — is not telemetry about the host. Without this every run
        // observes itself.
        if pid == self.self_pid {
            return None;
        }
        let type_name = match kind_name(h.kind) {
            Some(name) => name,
            None => {
                debug!("unknown event kind {}", h.kind);
                return None;
            }
        };

        // Resolve the file payload before anything else, so a suppressed write
        // costs one readlink and nothing more — no /proc enrichment, no ancestry
        // walk, no allocation for a record that is about to be dropped.
        let file_path = if h.kind == EVENT_FILE {
            // SAFETY: kind == EVENT_FILE guarantees the `file` union variant.
            let file = unsafe { &event.payload.file };
            let raw = String::from_utf8_lossy(cstr(&file.path)).into_owned();
            let path = resolve_path(pid, file.dfd, &raw);
            if file.reason != FILE_SECRET_READ && self.is_noise(&path) {
                return None;
            }
            Some((path, raw))
        } else {
            None
        };

        // An exec is the one point where we learn a process's identity firsthand,
        // and it replaces whatever the pid was before. Record it before anything
        // else reads the table.
        let exec_path = if h.kind == EVENT_EXEC {
            // SAFETY: kind == EVENT_EXEC guarantees the `exec` union variant.
            let path =
                String::from_utf8_lossy(cstr(unsafe { &event.payload.exec.filename })).into_owned();
            let ppid = if h.ppid != 0 {
                h.ppid
            } else {
                read_stat(pid).map_or(0, |(ppid, _)| ppid)
            };
            self.procs.insert(
                pid,
                ProcInfo {
                    ppid,
                    comm: comm.clone(),
                    exe: Some(path.clone()),
                    cmdline: read_cmdline(pid),
                    container: read_container(pid),
                },
            );
            Some(path)
        } else {
            None
        };

        // Backfill the parent the fork tracepoint never saw. `ppid == 0` in a raw
        // event means "this process already existed when we attached", which is
        // most of a capture's first seconds and every long-running daemon —
        // exactly the processes a chain is likely to be rooted at.
        let info = self.procs.get(pid).cloned();
        let ppid = match (h.ppid, &info) {
            (0, Some(info)) => info.ppid,
            (ppid, _) => ppid,
        };

        let mut rec = Json::new();
        let epoch_ns = self.clock.epoch_ns(h.timestamp);
        rec.num("ts", epoch_ns);
        rec.str("time", &rfc3339_local(epoch_ns));
        rec.str("type", type_name);
        rec.str("action", action_name(event)?);
        rec.num("pid", pid);
        rec.num("ppid", ppid);
        rec.num("uid", h.uid);
        if let Some(user) = self.users.get(&h.uid) {
            rec.str("user", user);
        }
        rec.str("comm", &comm);
        if let Some(info) = &info {
            if let Some(exe) = &info.exe {
                rec.str("exe", exe);
            }
            if let Some(cmdline) = &info.cmdline {
                rec.str("cmdline", cmdline);
            }
            if let Some(container) = &info.container {
                rec.str("container", container);
            }
        }
        // The lineage the correlation engine groups on. Walking it here rather
        // than leaving it to a consumer matters because ancestors exit: once
        // `npm` is gone, only this cache can still say the payload descended
        // from it.
        let ancestry = self.ancestry(ppid);
        if !ancestry.is_empty() {
            let mut arr = String::from("[");
            for (i, (apid, acomm)) in ancestry.iter().enumerate() {
                if i > 0 {
                    arr.push(',');
                }
                arr.push_str(&format!(
                    "{{\"pid\":{},\"comm\":{}}}",
                    apid,
                    json_str(acomm)
                ));
            }
            arr.push(']');
            rec.raw("ancestry", &arr);
        }

        match h.kind {
            EVENT_EXEC => rec.str("path", exec_path.as_deref().unwrap_or_default()),
            EVENT_FILE => {
                // SAFETY: kind == EVENT_FILE guarantees the `file` union variant.
                let file = unsafe { &event.payload.file };
                let (path, raw) = file_path?;
                rec.str("path", &path);
                if path != raw {
                    rec.str("path_raw", &raw);
                }
                rec.num("flags", file.flags);
            }
            EVENT_NET => {
                // SAFETY: kind == EVENT_NET guarantees the `net` union variant.
                let net = unsafe { &event.payload.net };
                rec.str("saddr", &ipv4(net.saddr));
                rec.num("sport", net.sport);
                rec.str("daddr", &ipv4(net.daddr));
                rec.num("dport", net.dport);
                rec.num("proto", net.proto);
            }
            _ => return None,
        }
        Some(rec.finish())
    }

    /// Whether a resolved write path is background churn rather than telemetry.
    ///
    /// Applied to writes only — a `secret_read` is never suppressed, because the
    /// watchlist's `/proc/<pid>/environ` entry would be the first casualty.
    ///
    /// This runs *after* path resolution, which is the point: the kernel-side
    /// filter in `file.rs` only ever sees the raw `openat` argument, so an open
    /// made relative to a directory fd (`openat(dfd, "uid_map", …)`) slips past
    /// its `/proc/` prefix check and can only be recognised here. The two tiers
    /// are complementary, not redundant — the kernel drops what it can identify
    /// cheaply, and this catches what only resolution makes visible.
    fn is_noise(&self, path: &str) -> bool {
        let base = path.rsplit('/').next().unwrap_or(path);

        // Pseudo-filesystems, re-checked on the resolved path. `/dev/shm` stays
        // in: it is a real payload staging ground.
        if path.starts_with("/proc/")
            || path.starts_with("/sys/")
            || (path.starts_with("/dev/") && !path.starts_with("/dev/shm/"))
        {
            return true;
        }

        // Desktop-session churn. Every one of these is produced continuously by
        // a graphical session regardless of what the user is doing, which is
        // exactly what makes it useless for detection: it has the same rate in a
        // compromised session as in a clean one. Opening a single terminal
        // window generated 209 of the thumbnail temporaries alone.
        let desktop = base.starts_with("gdk-pixbuf-")          // thumbnail decode temporaries
            || path.contains("/gvfs-metadata/")                // GVFS bookkeeping
            || path.ends_with("/dconf/user")                   // settings store
            || path.contains("/.mozilla/")                     // browser profile + telemetry
            || path.contains("/.cache/mozilla/")               // browser disk cache
            || path.starts_with("/run/systemd/journal/")       // journal stream sockets
            || path.starts_with("/var/lib/xkb/"); // compiled keymaps

        desktop || self.extra_mutes.iter().any(|m| path.contains(m.as_str()))
    }

    /// `pid` and its parents, nearest first. Stops at pid 0 (the walk ran off the
    /// top), at a pid `/proc` no longer knows and the cache never saw, or at
    /// [`ANCESTRY_MAX`].
    fn ancestry(&mut self, mut pid: u32) -> Vec<(u32, String)> {
        let mut chain = Vec::new();
        while pid != 0 && chain.len() < ANCESTRY_MAX {
            let Some(info) = self.procs.get(pid) else {
                break;
            };
            let (ppid, comm) = (info.ppid, info.comm.clone());
            chain.push((pid, comm));
            if ppid == pid {
                break; // defensive: a self-parent would spin
            }
            pid = ppid;
        }
        chain
    }
}

fn kind_name(kind: u8) -> Option<&'static str> {
    match kind {
        EVENT_EXEC => Some("exec"),
        EVENT_FILE => Some("file"),
        EVENT_NET => Some("net"),
        _ => None,
    }
}

/// What the process did, flattened across event kinds so a consumer can switch
/// on one field instead of on `type` and then on a per-type reason.
fn action_name(event: &Event) -> Option<&'static str> {
    match event.header.kind {
        EVENT_EXEC => Some("exec"),
        // SAFETY: kind == EVENT_FILE guarantees the `file` union variant.
        EVENT_FILE => Some(
            if unsafe { event.payload.file.reason } == FILE_SECRET_READ {
                "secret_read"
            } else {
                "write"
            },
        ),
        EVENT_NET => Some("connect"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// clock
// ---------------------------------------------------------------------------

/// Fixed offset from the kernel's monotonic clock to the wall clock.
///
/// Sampled once, deliberately: re-sampling would track NTP steps and resumes
/// more accurately, but it could also make a later event carry an earlier
/// timestamp than one already emitted. A single offset keeps `ts` monotonic —
/// which every consumer that sorts or windows events depends on — at the cost
/// of drifting from true wall-clock if the machine suspends mid-capture.
struct Clock {
    offset_ns: i128,
}

impl Clock {
    fn capture() -> Clock {
        Clock {
            offset_ns: clock_now(libc::CLOCK_REALTIME) - clock_now(libc::CLOCK_MONOTONIC),
        }
    }

    fn epoch_ns(&self, ktime_ns: u64) -> i128 {
        ktime_ns as i128 + self.offset_ns
    }
}

fn clock_now(clk: libc::clockid_t) -> i128 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a live, writable `struct timespec`.
    unsafe { libc::clock_gettime(clk, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// RFC 3339 in local time, e.g. `2026-08-18T19:04:21.123456789+05:30`. Local
/// rather than UTC to match the capture filenames and what the operator's own
/// shell history shows.
fn rfc3339_local(epoch_ns: i128) -> String {
    // Euclidean division so a pre-epoch timestamp (a badly skewed clock) still
    // yields a nanosecond part in 0..1e9 rather than a negative one.
    let secs = epoch_ns.div_euclid(1_000_000_000) as libc::time_t;
    let nanos = epoch_ns.rem_euclid(1_000_000_000) as u32;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `secs` is a valid time_t and `tm` is a live, writable `struct tm`.
    unsafe { libc::localtime_r(&secs, &mut tm) };
    let off_min = tm.tm_gmtoff / 60;
    let (sign, off_min) = if off_min < 0 {
        ('-', -off_min)
    } else {
        ('+', off_min)
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}{}{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        nanos,
        sign,
        off_min / 60,
        off_min % 60,
    )
}

// ---------------------------------------------------------------------------
// process table
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProcInfo {
    ppid: u32,
    comm: String,
    exe: Option<String>,
    cmdline: Option<String>,
    container: Option<String>,
}

/// pid → enrichment, filled from exec events (firsthand, and still correct after
/// the process exits) and from `/proc` for anything that predates the capture.
///
/// Entries are never invalidated, so a pid reused after the kernel's counter
/// wraps would read stale until its next exec overwrites it. Over a capture
/// that is far shorter than a wrap of `pid_max`, that is not reachable.
#[derive(Default)]
struct ProcTable {
    map: HashMap<u32, ProcInfo>,
    /// Insertion order, for evicting the oldest entry once the cache is full.
    order: VecDeque<u32>,
}

impl ProcTable {
    fn insert(&mut self, pid: u32, info: ProcInfo) {
        if self.map.insert(pid, info).is_none() {
            self.order.push_back(pid);
            while self.order.len() > PROC_CACHE_CAP {
                if let Some(evicted) = self.order.pop_front() {
                    self.map.remove(&evicted);
                }
            }
        }
    }

    /// Cached info for `pid`, reading `/proc` on a miss. `None` once the process
    /// is gone and we never saw it exec — the honest answer, and the caller omits
    /// the fields rather than inventing them.
    fn get(&mut self, pid: u32) -> Option<&ProcInfo> {
        if !self.map.contains_key(&pid) {
            let (ppid, comm) = read_stat(pid)?;
            let info = ProcInfo {
                ppid,
                comm,
                exe: read_exe(pid),
                cmdline: read_cmdline(pid),
                container: read_container(pid),
            };
            self.insert(pid, info);
        }
        self.map.get(&pid)
    }
}

/// `(ppid, comm)` from `/proc/<pid>/stat`.
fn read_stat(pid: u32) -> Option<(u32, String)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 2 is the comm, wrapped in parens and *not* escaped — it can contain
    // spaces and even ')' (`(sd-pam)`, `(sessionclean)`). Splitting on whitespace
    // from the left therefore mis-parses; anchor on the last ')' instead, after
    // which the fields are fixed: state, then ppid.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let mut rest = stat.get(close + 1..)?.split_whitespace();
    let _state = rest.next()?;
    let ppid = rest.next()?.parse().ok()?;
    Some((ppid, comm))
}

/// The running binary. A binary unlinked after launch — a dropped payload
/// deleting itself is the textbook case — reads as `/path/to/it (deleted)`,
/// which is kept verbatim because that suffix is itself a signal.
fn read_exe(pid: u32) -> Option<String> {
    Some(
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()?
            .to_string_lossy()
            .into_owned(),
    )
}

fn read_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let mut line = raw
        .split(|&b| b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if line.is_empty() {
        return None; // kernel threads have no argv
    }
    if line.len() > CMDLINE_MAX {
        let mut cut = CMDLINE_MAX;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
        line.push('\u{2026}');
    }
    Some(line)
}

/// Container id from `/proc/<pid>/cgroup`, shortened to the 12 hex chars every
/// container runtime's own tooling displays. Handles cgroup v2 (`0::/path`) and
/// v1 alike since only the trailing path is inspected, and the systemd-managed
/// spellings (`docker-<id>.scope`, `crio-<id>.scope`, …) as well as the bare id.
/// `None` for anything on the host, which is the common case.
fn read_container(pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in cgroup.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        for segment in path.split('/') {
            let id = segment.trim_end_matches(".scope");
            let id = id.rsplit('-').next().unwrap_or(id);
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(id[..12].to_string());
            }
        }
    }
    None
}

/// Extra noise substrings from `$SECRISK_MUTE`, comma-separated. Site-specific
/// suppression belongs in configuration rather than in the binary: the built-in
/// list covers what any Linux desktop produces, and this covers what *your* host
/// produces (an editor's session log, a CI agent's scratch directory).
///
///     SECRISK_MUTE=/.claude/,/node_modules/.cache/ sudo -E ./sensors
fn load_extra_mutes() -> Vec<String> {
    std::env::var("SECRISK_MUTE")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}

/// uid → name, read once from `/etc/passwd`. First entry wins, so a uid shared
/// by several names resolves to the canonical one.
fn load_users() -> HashMap<u32, String> {
    let mut users = HashMap::new();
    let Ok(passwd) = fs::read_to_string("/etc/passwd") else {
        return users;
    };
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let (Some(name), Some(_passwd), Some(uid)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if let Ok(uid) = uid.parse() {
            users.entry(uid).or_insert_with(|| name.to_string());
        }
    }
    users
}

// ---------------------------------------------------------------------------
// paths
// ---------------------------------------------------------------------------

/// An absolute, lexically clean path for a raw `openat` argument.
///
/// A relative path is resolved against whichever directory the syscall named:
/// the process's cwd for `AT_FDCWD`, otherwise the directory behind `dfd`.
/// Honouring `dfd` is not a detail — `sudo` opening its timestamp file as
/// `openat(<fd for /run/sudo/ts>, "1000", …)` resolves against the cwd to a path
/// that was never opened, and a confidently wrong absolute path is worse for a
/// correlation rule than an unresolved one.
///
/// Both links are read live rather than cached: a process can `chdir` between
/// opens, and an fd number is reused constantly. If the directory cannot be read
/// — the process has already exited, which for a short-lived one is the common
/// case — the raw argument is returned unchanged rather than resolved against a
/// guess. The original is preserved as `path_raw` whenever resolution changed
/// it, so nothing is lost either way.
fn resolve_path(pid: u32, dfd: i32, raw: &str) -> String {
    if raw.is_empty() {
        return raw.to_string();
    }
    if raw.starts_with('/') {
        return lexical_clean(raw);
    }
    let base = if dfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dfd}")
    };
    let Ok(dir) = fs::read_link(base) else {
        return raw.to_string(); // gone before we could look; the argument is all we have
    };
    lexical_clean(&format!("{}/{}", dir.to_string_lossy(), raw))
}

/// Collapse `.`, `..` and repeated separators. Purely lexical — deliberately not
/// `canonicalize()`, which touches the filesystem: by the time we see the event
/// the path may be gone, may be a symlink to somewhere else than it was, or may
/// not resolve in our mount namespace at all.
fn lexical_clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::with_capacity(path.len());
    for part in parts {
        out.push('/');
        out.push_str(part);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// A raw network-order IPv4 address as a dotted quad. The bytes arrive in wire
/// order, so they are taken as-is.
fn ipv4(addr: u32) -> String {
    let octets = addr.to_ne_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

// ---------------------------------------------------------------------------
// json
// ---------------------------------------------------------------------------

/// A minimal ordered object writer. Ordered because these lines are read by
/// people as often as by programs, and `ts` belongs first; hand-written because
/// the alternative — pulling in serde_json — buys nothing for a record this
/// shape and would reorder the fields alphabetically without another dependency
/// on top.
struct Json {
    buf: String,
    empty: bool,
}

impl Json {
    fn new() -> Json {
        Json {
            buf: String::from("{"),
            empty: true,
        }
    }

    /// `value` must already be valid JSON.
    fn raw(&mut self, key: &str, value: &str) {
        if !self.empty {
            self.buf.push(',');
        }
        self.empty = false;
        self.buf.push_str(&json_str(key));
        self.buf.push(':');
        self.buf.push_str(value);
    }

    fn str(&mut self, key: &str, value: &str) {
        let quoted = json_str(value);
        self.raw(key, &quoted);
    }

    fn num<T: Display>(&mut self, key: &str, value: T) {
        self.raw(key, &value.to_string());
    }

    fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// A JSON string literal (quoted, with the mandatory escapes) for `s`.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed event of `kind` attributed to this test process, so the /proc
    /// enrichment has something real to find.
    fn event_for_self(kind: u8) -> Event {
        let mut event: Event = unsafe { core::mem::zeroed() };
        event.header.timestamp = 1_000;
        event.header.pid = std::process::id();
        event.header.uid = 1000;
        event.header.kind = kind;
        event.header.comm[..4].copy_from_slice(b"test");
        event
    }

    /// A normalizer that will not filter the test process's own events.
    /// `event_for_self` attributes events to us on purpose, so that the /proc
    /// enrichment has something real to read; the self-pid guard would drop
    /// every one of them.
    fn normalizer() -> Normalizer {
        let mut n = Normalizer::new();
        n.self_pid = 0;
        n
    }

    /// One field out of a record, as text. Naive about escapes, which no value
    /// in these tests contains.
    fn field(record: &str, key: &str) -> Option<String> {
        let at = record.find(&format!("\"{key}\":"))? + key.len() + 3;
        let rest = &record[at..];
        match rest.strip_prefix('"') {
            Some(quoted) => Some(quoted[..quoted.find('"')?].to_string()),
            None => Some(rest[..rest.find(',').unwrap_or(rest.len() - 1)].to_string()),
        }
    }

    #[test]
    fn exec_record_carries_identity_and_lineage() {
        let mut event = event_for_self(EVENT_EXEC);
        let path = b"/usr/bin/curl";
        unsafe { event.payload.exec.filename[..path.len()].copy_from_slice(path) };

        let record = normalizer().normalize(&event).unwrap();
        assert_eq!(field(&record, "type").as_deref(), Some("exec"));
        assert_eq!(field(&record, "action").as_deref(), Some("exec"));
        assert_eq!(field(&record, "path").as_deref(), Some("/usr/bin/curl"));
        // Taken from the event, so it is right even once the process is gone.
        assert_eq!(field(&record, "exe").as_deref(), Some("/usr/bin/curl"));
        // ppid was 0 on the wire (no fork observed) and is backfilled from /proc.
        assert_ne!(field(&record, "ppid").as_deref(), Some("0"));
        // Wall clock, not the raw 1000ns since boot the event carried.
        assert!(field(&record, "ts").unwrap().len() > 15, "{record}");
        assert!(record.contains("\"time\":\"20"), "{record}");
        assert!(record.contains("\"cmdline\":"), "{record}");
        assert!(record.contains("\"ancestry\":[{"), "{record}");
    }

    #[test]
    fn file_record_resolves_a_relative_path_and_keeps_the_original() {
        let mut event = event_for_self(EVENT_FILE);
        let path = b"credentials.txt";
        unsafe {
            event.payload.file.path[..path.len()].copy_from_slice(path);
            event.payload.file.reason = FILE_SECRET_READ;
            event.payload.file.dfd = AT_FDCWD;
        }

        let record = normalizer().normalize(&event).unwrap();
        assert_eq!(field(&record, "action").as_deref(), Some("secret_read"));
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            field(&record, "path"),
            Some(format!("{}/credentials.txt", cwd.display())),
        );
        assert_eq!(
            field(&record, "path_raw").as_deref(),
            Some("credentials.txt")
        );
    }

    #[test]
    fn absolute_file_path_is_not_duplicated_into_path_raw() {
        let mut event = event_for_self(EVENT_FILE);
        let path = b"/tmp/staged";
        unsafe { event.payload.file.path[..path.len()].copy_from_slice(path) };

        let record = normalizer().normalize(&event).unwrap();
        assert_eq!(field(&record, "action").as_deref(), Some("write"));
        assert_eq!(field(&record, "path").as_deref(), Some("/tmp/staged"));
        assert!(!record.contains("path_raw"), "{record}");
    }

    #[test]
    fn net_record_renders_wire_order_addresses() {
        let mut event = event_for_self(EVENT_NET);
        // Writing a union field is safe; only reading one needs `unsafe`.
        event.payload.net.saddr = u32::from_ne_bytes([192, 168, 159, 128]);
        event.payload.net.daddr = u32::from_ne_bytes([93, 184, 216, 34]);
        event.payload.net.dport = 443;
        event.payload.net.proto = 6;

        let record = normalizer().normalize(&event).unwrap();
        assert_eq!(field(&record, "action").as_deref(), Some("connect"));
        assert_eq!(field(&record, "saddr").as_deref(), Some("192.168.159.128"));
        assert_eq!(field(&record, "daddr").as_deref(), Some("93.184.216.34"));
        assert_eq!(field(&record, "dport").as_deref(), Some("443"));
    }

    #[test]
    fn unknown_event_kind_is_dropped() {
        let event = event_for_self(99);
        assert!(normalizer().normalize(&event).is_none());
    }

    #[test]
    fn suppresses_namespace_setup_opened_through_a_directory_fd() {
        // The bwrap case: `openat(<fd for /proc/self>, "uid_map", …)`. The raw
        // argument carries no `/proc/` prefix, so the kernel-side filter cannot
        // see what it is — only the resolved path gives it away.
        assert!(normalizer().is_noise("/proc/1234/uid_map"));
        assert!(normalizer().is_noise("/proc/1234/setgroups"));
    }

    #[test]
    fn suppresses_desktop_churn_but_not_payload_staging() {
        let n = normalizer();
        assert!(n.is_noise("/tmp/gdk-pixbuf-glycin-tmp.RYQ5T3"));
        assert!(n.is_noise("/home/u/.local/share/gvfs-metadata/root"));
        assert!(n.is_noise("/run/user/1000/dconf/user"));
        assert!(n.is_noise("/home/u/.mozilla/firefox/p.default/datareporting/x"));
        // /dev/shm is where payloads actually get staged — it must survive the
        // /dev/ rule, and an ordinary /tmp write must survive the desktop rules.
        assert!(!n.is_noise("/dev/shm/.update-cache"));
        assert!(!n.is_noise("/tmp/staged-implant"));
        assert!(!n.is_noise("/home/u/node_modules/left-pad/postinstall.sh"));
    }

    #[test]
    fn secret_reads_are_never_suppressed() {
        // /proc/<pid>/environ is both a watchlisted secret and a pseudo-fs path.
        // The suppression must not reach it, or env-var theft goes unseen.
        let mut event = event_for_self(EVENT_FILE);
        let path = b"/proc/1/environ";
        unsafe {
            event.payload.file.path[..path.len()].copy_from_slice(path);
            event.payload.file.reason = FILE_SECRET_READ;
        }
        let record = normalizer().normalize(&event).unwrap();
        assert_eq!(field(&record, "action").as_deref(), Some("secret_read"));
        // …while a *write* to the same place is dropped.
        let mut write = event_for_self(EVENT_FILE);
        let path = b"/proc/1/uid_map";
        unsafe {
            write.payload.file.path[..path.len()].copy_from_slice(path);
            write.payload.file.flags = 1; // O_WRONLY
        }
        assert!(normalizer().normalize(&write).is_none());
    }

    #[test]
    fn the_sensor_does_not_report_on_itself() {
        let mut event = event_for_self(EVENT_EXEC);
        let path = b"/usr/bin/curl";
        unsafe { event.payload.exec.filename[..path.len()].copy_from_slice(path) };
        // A real Normalizer, whose self_pid is this process — the event is ours.
        assert!(Normalizer::new().normalize(&event).is_none());
    }

    #[test]
    fn extra_mutes_are_substring_matches() {
        let mut n = normalizer();
        n.extra_mutes = vec!["/.claude/".to_string()];
        assert!(n.is_noise("/home/u/.claude/history.jsonl"));
        assert!(!n.is_noise("/home/u/claude/history.jsonl"));
    }

    #[test]
    fn parses_the_mute_list_from_the_environment() {
        unsafe { std::env::set_var("SECRISK_MUTE", " /a/ , ,/b/ ") };
        assert_eq!(load_extra_mutes(), vec!["/a/", "/b/"]);
        unsafe { std::env::remove_var("SECRISK_MUTE") };
        assert!(load_extra_mutes().is_empty());
    }

    #[test]
    fn cleans_relative_and_redundant_segments() {
        assert_eq!(lexical_clean("/tmp/./x"), "/tmp/x");
        assert_eq!(lexical_clean("/tmp/a/../b"), "/tmp/b");
        assert_eq!(lexical_clean("/tmp//a///b"), "/tmp/a/b");
        assert_eq!(lexical_clean("/"), "/");
        // A `..` that walks off the root stops there rather than escaping it.
        assert_eq!(lexical_clean("/../../etc"), "/etc");
    }

    #[test]
    fn absolute_paths_need_no_process() {
        // pid 0 never exists, so this also proves no /proc lookup happened.
        assert_eq!(resolve_path(0, AT_FDCWD, "/etc/passwd"), "/etc/passwd");
        // An unresolvable relative path stays raw rather than being guessed at.
        assert_eq!(resolve_path(0, AT_FDCWD, "relative"), "relative");
    }

    #[test]
    fn resolves_relative_paths_against_cwd() {
        let pid = std::process::id();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_path(pid, AT_FDCWD, "credentials.txt"),
            format!("{}/credentials.txt", cwd.display()),
        );
    }

    #[test]
    fn resolves_relative_paths_against_a_directory_fd() {
        use std::os::fd::AsRawFd;

        // The case that made this necessary: an open relative to a directory fd
        // that is not the cwd. Resolving against the cwd would invent a path.
        let dir = fs::File::open("/usr/bin").unwrap();
        let pid = std::process::id();
        assert_eq!(resolve_path(pid, dir.as_raw_fd(), "curl"), "/usr/bin/curl",);
        assert_ne!(
            resolve_path(pid, dir.as_raw_fd(), "curl"),
            resolve_path(pid, AT_FDCWD, "curl"),
        );
    }

    #[test]
    fn reads_own_stat() {
        // Our own process is the one /proc entry guaranteed to be readable.
        let (ppid, comm) = read_stat(std::process::id()).unwrap();
        assert!(ppid != 0);
        assert!(!comm.is_empty());
    }

    #[test]
    fn escapes_json_control_characters() {
        assert_eq!(json_str("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(json_str("tab\there"), r#""tab\there""#);
        assert_eq!(json_str("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn writes_fields_in_insertion_order() {
        let mut json = Json::new();
        json.num("ts", 1);
        json.str("type", "exec");
        assert_eq!(json.finish(), r#"{"ts":1,"type":"exec"}"#);
    }

    #[test]
    fn formats_epoch_nanoseconds_as_rfc3339() {
        // Nanoseconds are carried through in full, and the offset is rendered as
        // ±HH:MM regardless of the local zone.
        let formatted = rfc3339_local(1_755_523_461_123_456_789);
        assert!(formatted.contains(".123456789"), "{formatted}");
        let tail = &formatted[formatted.len() - 6..];
        assert!(
            (tail.starts_with('+') || tail.starts_with('-')) && tail.as_bytes()[3] == b':',
            "{formatted}"
        );
    }
}
