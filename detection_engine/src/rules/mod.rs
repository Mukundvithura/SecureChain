//! The 25 rules of "SecRisk Detection Rules", plus C3.
//!
//! Each rule is a plain predicate over one event, its process lineage and the
//! state its chain has built up. A rule fires at most once per chain; the
//! engine records the first hit and ignores the rest. Gating (C1, N3) and the
//! caps live in `score`, not here, so a rule never needs to know what else
//! fired except through chain state.

pub mod lists;

mod context;
mod file;
mod network;
mod process;

use serde::Serialize;

use crate::{
    chain::{AnchorKind, Chain},
    event::{Action, Event},
    mitre::Tactic,
    proctable::Proc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RuleId {
    P1,
    P2,
    P3,
    L1,
    L3,
    L5,
    L12,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    L6,
    L7,
    L8,
    L10,
    L11,
    N1,
    N2,
    N3,
    L2,
    C1,
    C2,
    L9,
    C3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    Process,
    File,
    Network,
    Context,
}

pub struct RuleInfo {
    pub component: Component,
    pub points: u32,
    pub technique: &'static str,
    pub tactic: Option<Tactic>,
}

/// Points, component and ATT&CK mapping per rule. Tactics follow the plan's
/// map; context rules carry none because C3 does not count them.
pub fn info(id: RuleId) -> RuleInfo {
    use Component::*;
    use RuleId::*;
    use Tactic::*;
    let (component, points, technique, tactic) = match id {
        P1 => (Process, 10, "T1059.004", Some(Execution)),
        P2 => (Process, 10, "T1105", Some(CommandAndControl)),
        P3 => (Process, 15, "heuristic", None),
        L1 => (Process, 15, "T1105", Some(CommandAndControl)),
        L3 => (Process, 10, "T1140", Some(DefenseEvasion)),
        L5 => (Process, 15, "T1140", Some(DefenseEvasion)),
        L12 => (Process, 30, "T1554", Some(Persistence)),
        F1 => (File, 25, "T1552.001", Some(CredentialAccess)),
        F2 => (File, 10, "T1074.001", Some(Collection)),
        F3 => (File, 20, "T1546.004", Some(Persistence)),
        F4 => (File, 20, "T1053.003", Some(Persistence)),
        F5 => (File, 20, "T1543.002", Some(Persistence)),
        F6 => (File, 20, "T1098.004", Some(Persistence)),
        L6 => (File, 20, "T1195.002", Some(InitialAccess)),
        L7 => (File, 20, "T1554", Some(Persistence)),
        L8 => (File, 20, "T1552.001", Some(CredentialAccess)),
        L10 => (File, 20, "T1136.001", Some(Persistence)),
        L11 => (File, 20, "T1195.001", Some(InitialAccess)),
        N1 => (Network, 5, "T1071", Some(CommandAndControl)),
        N2 => (Network, 20, "T1041", Some(Exfiltration)),
        N3 => (Network, 5, "T1571", Some(CommandAndControl)),
        L2 => (Network, 20, "T1059.004", Some(Execution)),
        C1 => (Context, 15, "T1195.002", None),
        C2 => (Context, 10, "T1548.003", None),
        L9 => (Context, 15, "T1611", None),
        C3 => (Context, 10, "kill-chain progression", None),
    };
    RuleInfo {
        component,
        points,
        technique,
        tactic,
    }
}

/// A rule matching one event. `technique` and `tactic` start as the rule's
/// own and are overridden where the rule doc maps by target (F1, L10).
pub struct Finding {
    pub rule: RuleId,
    pub detail: String,
    pub technique: &'static str,
    pub tactic: Option<Tactic>,
}

impl Finding {
    pub fn new(rule: RuleId, detail: impl Into<String>) -> Self {
        let i = info(rule);
        Finding {
            rule,
            detail: detail.into(),
            technique: i.technique,
            tactic: i.tactic,
        }
    }

    fn mapped(mut self, technique: &'static str, tactic: Option<Tactic>) -> Self {
        self.technique = technique;
        self.tactic = tactic;
        self
    }
}

/// Everything a rule may look at.
pub struct Ctx<'a> {
    pub ev: &'a Event,
    /// The acting process first, then its ancestors.
    pub lineage: &'a [&'a Proc],
    /// Index of the chain's anchor in `lineage`.
    pub anchor_idx: usize,
    pub chain: &'a Chain,
}

impl Ctx<'_> {
    pub fn proc(&self) -> &Proc {
        self.lineage[0]
    }

    pub fn is_anchor(&self) -> bool {
        self.anchor_idx == 0
    }

    /// Under a package manager, build tool or C4 runtime dependency.
    pub fn in_dependency_chain(&self) -> bool {
        self.chain.anchor.kind != AnchorKind::User
    }

    pub fn in_build_chain(&self) -> bool {
        self.chain.build
    }

    pub fn path(&self) -> &str {
        self.ev.path.as_deref().unwrap_or("")
    }

    pub fn anchor_name(&self) -> &str {
        &self.chain.anchor.name
    }
}

/// Every rule `ctx.ev` matches.
pub fn evaluate(ctx: &Ctx) -> Vec<Finding> {
    let mut found = Vec::new();
    match ctx.ev.action {
        Action::Exec => process::check(ctx, &mut found),
        Action::Write => file::check_write(ctx, &mut found),
        Action::SecretRead => file::check_secret(ctx, &mut found),
        Action::Connect => network::check(ctx, &mut found),
    }
    context::check(ctx, &mut found);
    found
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
