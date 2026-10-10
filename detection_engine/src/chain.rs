//! Chains: an anchor process plus everything beneath it.

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

use crate::{
    mitre::Tactic,
    proctable::Proc,
    rules::{RuleId, lists},
    score::Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// A package manager or build tool.
    Dependency,
    /// C4: an interpreter running a script from inside an installed dependency.
    RuntimeDependency,
    /// Neither: the command the user (or a daemon) started.
    User,
}

/// Where in `lineage` (acting process first) the chain's anchor is.
///
/// 1. The *outermost* package manager, build tool or C4 runtime dependency.
///    **Decision:** outermost rather than nearest, so npm → node-gyp → make
///    stays one chain instead of splitting the install's evidence.
/// 2. Otherwise the command started by the nearest session shell: the first
///    shell walking up whose own parent is not a shell (a terminal, sshd,
///    cron). Shell scripts count as shells — their argv[0] is the interpreter.
/// 3. Otherwise, with no shell above it, the topmost ancestor running the
///    same binary, so a browser's content processes join the browser.
pub fn find_anchor(lineage: &[&Proc]) -> (usize, AnchorKind) {
    for (i, p) in lineage.iter().enumerate().rev() {
        if p.is(lists::DEPENDENCY_TOOLS) {
            return (i, AnchorKind::Dependency);
        }
        if p.is_runtime_dependency() {
            return (i, AnchorKind::RuntimeDependency);
        }
    }
    for (i, p) in lineage.iter().enumerate() {
        if p.is_shell() && !lineage.get(i + 1).is_some_and(|q| q.is_shell()) {
            return (i.saturating_sub(1), AnchorKind::User);
        }
    }
    let exe = &lineage[0].exe;
    let mut idx = 0;
    if exe.is_some() {
        while lineage.get(idx + 1).is_some_and(|q| q.exe == *exe) {
            idx += 1;
        }
    }
    (idx, AnchorKind::User)
}

#[derive(Debug, Clone, Serialize)]
pub struct Anchor {
    pub pid: u32,
    pub kind: AnchorKind,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    #[serde(skip)]
    pub uid: Option<u32>,
}

impl Anchor {
    pub fn of(p: &Proc, kind: AnchorKind) -> Self {
        let name = match kind {
            AnchorKind::Dependency => p.name_in(lists::DEPENDENCY_TOOLS),
            _ => None,
        }
        .or(p.names.first().map(String::as_str))
        .unwrap_or(&p.comm)
        .to_string();
        Anchor {
            pid: p.pid,
            kind,
            name,
            exe: p.exe.clone(),
            cmdline: p.cmdline.clone(),
            uid: p.uid,
        }
    }

    /// Pick up what the anchor's own later events reveal about it.
    pub fn refresh(&mut self, p: &Proc) {
        self.exe = self.exe.take().or_else(|| p.exe.clone());
        self.cmdline = self.cmdline.take().or_else(|| p.cmdline.clone());
        self.uid = self.uid.or(p.uid);
    }
}

/// The first time a rule fired in a chain.
#[derive(Debug, Clone)]
pub struct Hit {
    pub ts: u64,
    pub time: String,
    pub pid: u32,
    pub comm: String,
    pub detail: String,
    pub technique: &'static str,
    pub tactic: Option<Tactic>,
}

pub struct Chain {
    pub id: u64,
    pub anchor: Anchor,
    /// Set once a build tool shows up anywhere above an acting process.
    pub build: bool,
    pub hits: BTreeMap<RuleId, Hit>,
    /// Paths written in the chain, for L1.
    pub written: HashSet<String>,
    /// First counted secret access (F1 or L8), for N2.
    pub first_secret: Option<u64>,
    /// Highest severity already alerted on.
    pub alerted: Severity,
    pub first_ts: u64,
    pub last_ts: u64,
    pub last_time: String,
    pub events: u64,
}

impl Chain {
    pub fn new(id: u64, anchor: Anchor, ts: u64) -> Self {
        Chain {
            id,
            anchor,
            build: false,
            hits: BTreeMap::new(),
            written: HashSet::new(),
            first_secret: None,
            alerted: Severity::Low,
            first_ts: ts,
            last_ts: ts,
            last_time: String::new(),
            events: 0,
        }
    }

    /// Record a rule's first hit. Returns whether it was new.
    pub fn record(&mut self, rule: RuleId, hit: Hit) -> bool {
        if self.hits.contains_key(&rule) {
            return false;
        }
        self.hits.insert(rule, hit);
        true
    }
}
