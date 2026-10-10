//! Scoring: gates, per-component caps, C3's tactic progression and the bands.
//!
//! ```text
//! score = Σ over components of min(cap, Σ points of counted hits)
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    chain::Hit,
    mitre::Tactic,
    rules::{Component, RuleId, info},
};

pub const CAP_PROCESS: u32 = 30;
pub const CAP_FILE: u32 = 25;
pub const CAP_NETWORK: u32 = 25;
pub const CAP_CONTEXT: u32 = 20;

/// C3 fires once this many tactics appear in kill-chain order.
const PROGRESSION_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn of(score: u32) -> Self {
        match score {
            0..=30 => Severity::Low,
            31..=60 => Severity::Medium,
            61..=80 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Score {
    pub total: u32,
    pub process: u32,
    pub file: u32,
    pub network: u32,
    pub context: u32,
    #[serde(skip)]
    pub counted: BTreeSet<RuleId>,
}

impl Score {
    pub fn of(hits: &BTreeMap<RuleId, Hit>) -> Self {
        // N3 is a modifier: it counts only beside N1 or N2.
        let mut counted: BTreeSet<RuleId> = hits
            .keys()
            .copied()
            .filter(|r| match r {
                RuleId::N3 => hits.contains_key(&RuleId::N1) || hits.contains_key(&RuleId::N2),
                RuleId::C1 => false,
                _ => true,
            })
            .collect();
        // C1 counts only when another rule does, so a clean install scores 0.
        if hits.contains_key(&RuleId::C1) && !counted.is_empty() {
            counted.insert(RuleId::C1);
        }

        let mut s = Score {
            counted,
            ..Score::default()
        };
        for &r in &s.counted {
            let i = info(r);
            match i.component {
                Component::Process => s.process += i.points,
                Component::File => s.file += i.points,
                Component::Network => s.network += i.points,
                Component::Context => s.context += i.points,
            }
        }
        s.process = s.process.min(CAP_PROCESS);
        s.file = s.file.min(CAP_FILE);
        s.network = s.network.min(CAP_NETWORK);
        s.context = s.context.min(CAP_CONTEXT);
        s.total = s.process + s.file + s.network + s.context;
        s
    }
}

/// C3: the longest run of tactics, ordered by when each was first seen, that
/// also rises in ATT&CK order — if it is at least three long. Only counted,
/// non-context hits take part. **Decision:** context rules are left out,
/// because C1 alone would hand every package chain Initial Access.
pub fn progression(
    hits: &BTreeMap<RuleId, Hit>,
    counted: &BTreeSet<RuleId>,
) -> Option<Vec<Tactic>> {
    let mut first: BTreeMap<Tactic, u64> = BTreeMap::new();
    for r in counted {
        if info(*r).component == Component::Context {
            continue;
        }
        let hit = &hits[r];
        if let Some(t) = hit.tactic {
            let ts = first.entry(t).or_insert(hit.ts);
            *ts = (*ts).min(hit.ts);
        }
    }
    let mut seq: Vec<(u64, Tactic)> = first.into_iter().map(|(t, ts)| (ts, t)).collect();
    seq.sort();

    // Longest strictly increasing subsequence; n is at most nine tactics.
    let n = seq.len();
    let mut len = vec![1usize; n];
    let mut prev = vec![usize::MAX; n];
    for i in 0..n {
        for j in 0..i {
            if seq[j].1 < seq[i].1 && len[j] + 1 > len[i] {
                len[i] = len[j] + 1;
                prev[i] = j;
            }
        }
    }
    let (mut end, &best) = len.iter().enumerate().max_by_key(|&(_, l)| *l)?;
    if best < PROGRESSION_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(best);
    loop {
        out.push(seq[end].1);
        if prev[end] == usize::MAX {
            break;
        }
        end = prev[end];
    }
    out.reverse();
    Some(out)
}
