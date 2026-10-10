//! The engine's own view of the process tree.
//!
//! The normalizer's `ancestry` carries only pid and comm, eight levels deep.
//! Anchor matching needs more — npm runs as `node`, so the name that says
//! "package manager" is often an argument — so the table keeps what each
//! process's own events said about it, and falls back to ancestry entries for
//! processes that started before the capture and never act in it.

use std::collections::{HashMap, VecDeque};

use crate::{
    event::{Action, Event},
    rules::lists,
};

/// Processes remembered at once. Nothing tells us a process exited, so the
/// oldest entries are evicted instead.
const CAP: usize = 65_536;
/// Furthest a lineage walk goes. Deeper than any real chain; it only bounds
/// the cost of a cycle or a pathological tree.
pub const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    /// Uid seen on the process's own events; unknown for ancestry-only entries.
    pub uid: Option<u32>,
    pub container: Option<String>,
    /// When this process instance was first seen executing; 0 if it predates
    /// the capture. Part of the chain key, so a reused pid starts a new chain.
    pub start_ts: u64,
    /// Every name the process answers to, from [`names_of`].
    pub names: Vec<String>,
}

impl Proc {
    fn refresh_names(&mut self) {
        self.names = names_of(&self.comm, self.exe.as_deref(), self.cmdline.as_deref());
    }

    /// Whether any of the process's names is in `list`.
    pub fn is(&self, list: &[&str]) -> bool {
        self.names.iter().any(|n| list.contains(&n.as_str()))
    }

    pub fn is_shell(&self) -> bool {
        self.is(lists::SHELLS)
    }

    /// The first name in `list` the process answers to.
    pub fn name_in(&self, list: &[&str]) -> Option<&str> {
        self.names
            .iter()
            .map(String::as_str)
            .find(|n| list.contains(n))
    }

    /// The script an interpreter is running, if this is one.
    pub fn script(&self) -> Option<&str> {
        let mut args = self.cmdline.as_deref()?.split_whitespace();
        let interp = clean(basename(args.next()?));
        if !is_interpreter(interp) {
            return None;
        }
        args.find(|a| !a.starts_with('-'))
    }

    /// C4: an interpreter running a script that lives inside an installed
    /// dependency, which makes the process a dependency anchor of its own.
    pub fn is_runtime_dependency(&self) -> bool {
        self.script()
            .is_some_and(|s| lists::DEPENDENCY_DIRS.iter().any(|d| s.contains(d)))
    }
}

#[derive(Default)]
pub struct ProcTable {
    map: HashMap<u32, Proc>,
    order: VecDeque<u32>,
}

impl ProcTable {
    /// Fold what `ev` says about its process and ancestors into the table.
    pub fn observe(&mut self, ev: &Event) {
        // Ancestors first, so the acting process's parent exists to link to.
        for (i, a) in ev.ancestry.iter().enumerate() {
            let ppid = ev.ancestry.get(i + 1).map_or(0, |p| p.pid);
            match self.map.get_mut(&a.pid) {
                Some(p) if p.ppid == 0 => p.ppid = ppid,
                Some(_) => {}
                None => self.insert(Proc {
                    pid: a.pid,
                    ppid,
                    comm: a.comm.clone(),
                    exe: None,
                    cmdline: None,
                    uid: None,
                    container: None,
                    start_ts: 0,
                    names: Vec::new(),
                }),
            }
        }

        let ppid = if ev.ppid != 0 {
            ev.ppid
        } else {
            ev.ancestry.first().map_or(0, |a| a.pid)
        };
        let exe = ev.exe.clone().or_else(|| match ev.action {
            Action::Exec => ev.path.clone(),
            _ => None,
        });
        match self.map.get_mut(&ev.pid) {
            Some(p) if ev.action == Action::Exec => {
                // A new image in the same process (`env node …` re-execs) keeps
                // its identity; a different parent means the pid was reused.
                if p.ppid != 0 && ppid != 0 && p.ppid != ppid {
                    p.start_ts = ev.ts;
                }
                if ppid != 0 {
                    p.ppid = ppid;
                }
                p.comm = ev.comm.clone();
                p.exe = exe;
                p.cmdline = ev.cmdline.clone();
                p.uid = Some(ev.uid);
                p.container = ev.container.clone();
                p.refresh_names();
            }
            Some(p) => {
                if p.ppid == 0 {
                    p.ppid = ppid;
                }
                p.uid = Some(ev.uid);
                let mut changed = false;
                if p.exe.is_none() && exe.is_some() {
                    p.exe = exe;
                    changed = true;
                }
                if p.cmdline.is_none() && ev.cmdline.is_some() {
                    p.cmdline = ev.cmdline.clone();
                    changed = true;
                }
                if p.container.is_none() {
                    p.container = ev.container.clone();
                }
                if changed {
                    p.refresh_names();
                }
            }
            None => self.insert(Proc {
                pid: ev.pid,
                ppid,
                comm: ev.comm.clone(),
                exe,
                cmdline: ev.cmdline.clone(),
                uid: Some(ev.uid),
                container: ev.container.clone(),
                start_ts: if ev.action == Action::Exec { ev.ts } else { 0 },
                names: Vec::new(),
            }),
        }
    }

    /// `pid` and its known ancestors, nearest first.
    pub fn lineage(&self, pid: u32) -> Vec<&Proc> {
        let mut chain: Vec<&Proc> = Vec::new();
        let mut cur = pid;
        while chain.len() < MAX_DEPTH {
            let Some(p) = self.map.get(&cur) else {
                break;
            };
            chain.push(p);
            if p.ppid == 0 || chain.iter().any(|q| q.pid == p.ppid) {
                break;
            }
            cur = p.ppid;
        }
        chain
    }

    fn insert(&mut self, mut proc: Proc) {
        proc.refresh_names();
        let pid = proc.pid;
        if self.map.insert(pid, proc).is_none() {
            self.order.push_back(pid);
            while self.order.len() > CAP {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

/// Every name a process answers to, deduplicated: its binary, its `argv[0]`,
/// the script an interpreter runs (`node /usr/bin/npm` is npm), and its comm.
pub fn names_of(comm: &str, exe: Option<&str>, cmdline: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut push = |n: &str| {
        let n = clean(n);
        if !n.is_empty() && !names.iter().any(|m| m == n) {
            names.push(n.to_string());
        }
    };
    if let Some(exe) = exe {
        push(basename(exe));
    }
    if let Some(cmdline) = cmdline {
        let mut args = cmdline.split_whitespace();
        if let Some(argv0) = args.next() {
            let argv0 = basename(argv0);
            push(argv0);
            if is_interpreter(clean(argv0))
                && let Some(script) = args.find(|a| !a.starts_with('-'))
            {
                let script = basename(script);
                let script = [".js", ".cjs", ".mjs", ".py"]
                    .iter()
                    .find_map(|ext| script.strip_suffix(ext))
                    .unwrap_or(script);
                push(script.strip_suffix("-cli").unwrap_or(script));
            }
        }
    }
    // A comm set through process.title can be a whole command line.
    if let Some(first) = comm.split_whitespace().next() {
        push(first);
    }
    names
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A login shell's argv[0] is `-zsh`.
fn clean(name: &str) -> &str {
    name.trim_start_matches('-')
}

fn is_interpreter(name: &str) -> bool {
    lists::INTERPRETERS.contains(&name)
        || name.starts_with("python3.")
        || name.starts_with("python2.")
}
