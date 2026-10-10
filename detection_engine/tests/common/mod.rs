//! A builder for hand-written events shaped like the normalizer's output,
//! shared by the scenario and per-rule tests.

#![allow(dead_code)]

use secrisk_engine::{
    Engine,
    event::Event,
    report::{Kind, Report, RuleReport},
    rules::RuleId,
};
use serde_json::{Value, json};

pub const S: u64 = 1_000_000_000;
pub const T0: u64 = 1_790_000_000 * S;

/// The terminal session every scenario starts from.
pub const SESSION: &[(u32, &str)] = &[(50, "zsh"), (10, "qterminal"), (1, "systemd")];

/// Builds a scenario's events with the lineage the normalizer would attach.
pub struct Scenario {
    pub events: Vec<Event>,
    /// pid → (ppid, comm), to rebuild each event's ancestry.
    tree: Vec<(u32, u32, String)>,
}

impl Scenario {
    pub fn new() -> Self {
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

    pub fn ancestry(&self, ppid: u32) -> Value {
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

    /// Any event from `pid`; `extra` adds or overrides fields (`uid`,
    /// `container`, …).
    pub fn push(&mut self, at: u64, pid: u32, action: &str, extra: Value) -> &mut Self {
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
        self
    }

    /// Process `pid` (child of `ppid`) execs `path` as `cmdline`. `at` is in
    /// tenths of a second.
    pub fn exec(&mut self, at: u64, pid: u32, ppid: u32, path: &str, cmdline: &str) -> &mut Self {
        let comm: String = path.rsplit('/').next().unwrap().chars().take(15).collect();
        self.tree.retain(|(p, ..)| *p != pid);
        self.tree.push((pid, ppid, comm));
        self.push(
            at,
            pid,
            "exec",
            json!({"exe": path, "cmdline": cmdline, "path": path}),
        )
    }

    pub fn write(&mut self, at: u64, pid: u32, path: &str) -> &mut Self {
        self.push(at, pid, "write", json!({"path": path}))
    }

    pub fn read_secret(&mut self, at: u64, pid: u32, path: &str) -> &mut Self {
        self.push(at, pid, "secret_read", json!({"path": path}))
    }

    pub fn connect(&mut self, at: u64, pid: u32, daddr: &str, dport: u16) -> &mut Self {
        self.push(at, pid, "connect", json!({"daddr": daddr, "dport": dport}))
    }

    /// `npm install` (pid 100) from the terminal, running its postinstall
    /// through `sh -c` (pid 101). Rules under test act from 101 or below.
    pub fn under_npm() -> Self {
        let mut s = Scenario::new();
        s.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install")
            .exec(1, 101, 100, "/usr/bin/sh", "sh -c ./postinstall.sh");
        s
    }

    /// `make` (pid 100) from the terminal, running a recipe through `sh -c`
    /// (pid 101): a build chain.
    pub fn under_make() -> Self {
        let mut s = Scenario::new();
        s.exec(0, 100, 50, "/usr/bin/make", "make").exec(
            1,
            101,
            100,
            "/usr/bin/sh",
            "/bin/sh -c ./build.sh",
        );
        s
    }

    /// Every rule that fired in any chain, counted or not.
    pub fn fired(&self) -> Vec<RuleId> {
        let mut ids: Vec<RuleId> = summaries(&self.run())
            .iter()
            .flat_map(|r| r.rules.iter().map(|x| x.id))
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// `rule`'s hit, from whichever chain it fired in.
    pub fn hit(&self, rule: RuleId) -> Option<RuleReport> {
        summaries(&self.run())
            .iter()
            .flat_map(|r| r.rules.iter())
            .find(|x| x.id == rule)
            .cloned()
    }

    pub fn run(&self) -> Vec<Report> {
        let mut engine = Engine::new(false);
        let mut out: Vec<Report> = self.events.iter().flat_map(|e| engine.process(e)).collect();
        out.extend(engine.finish());
        out
    }
}

pub fn alerts(reports: &[Report]) -> Vec<&Report> {
    reports.iter().filter(|r| r.record == Kind::Alert).collect()
}

pub fn counted(r: &Report) -> Vec<RuleId> {
    r.rules.iter().filter(|x| x.counted).map(|x| x.id).collect()
}

/// The last word on each chain: its summary.
pub fn summaries(reports: &[Report]) -> Vec<&Report> {
    reports.iter().filter(|r| r.record == Kind::Chain).collect()
}
