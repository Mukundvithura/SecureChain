//! The engine's output: one JSON object per line, either an alert (a chain's
//! score entered a new band at Medium or above) or a chain summary (written
//! when a chain expires, for evaluation).

use serde::Serialize;

use crate::{
    chain::{Anchor, Chain},
    mitre::Tactic,
    rules::{RuleId, info},
    score::{Score, Severity},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Alert,
    Chain,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub record: Kind,
    pub time: String,
    pub chain: u64,
    pub anchor: Anchor,
    pub score: u32,
    pub severity: Severity,
    pub components: Score,
    pub rules: Vec<RuleReport>,
    /// Distinct ATT&CK techniques among the counted rules.
    pub techniques: Vec<&'static str>,
    pub events: u64,
    pub first_ts: u64,
    pub last_ts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleReport {
    pub id: RuleId,
    pub points: u32,
    /// False when a gate (C1, N3) held the rule back or it never counts.
    pub counted: bool,
    pub technique: &'static str,
    pub tactic: Option<Tactic>,
    pub ts: u64,
    pub time: String,
    pub pid: u32,
    pub comm: String,
    pub detail: String,
}

impl Report {
    pub fn new(kind: Kind, chain: &Chain, score: &Score, time: &str) -> Self {
        let rules: Vec<RuleReport> = chain
            .hits
            .iter()
            .map(|(&id, h)| RuleReport {
                id,
                points: info(id).points,
                counted: score.counted.contains(&id),
                technique: h.technique,
                tactic: h.tactic,
                ts: h.ts,
                time: h.time.clone(),
                pid: h.pid,
                comm: h.comm.clone(),
                detail: h.detail.clone(),
            })
            .collect();
        let mut techniques: Vec<&'static str> = rules
            .iter()
            .filter(|r| r.counted && r.technique.starts_with('T'))
            .map(|r| r.technique)
            .collect();
        techniques.sort_unstable();
        techniques.dedup();
        Report {
            record: kind,
            time: time.to_string(),
            chain: chain.id,
            anchor: chain.anchor.clone(),
            score: score.total,
            severity: Severity::of(score.total),
            components: score.clone(),
            rules,
            techniques,
            events: chain.events,
            first_ts: chain.first_ts,
            last_ts: chain.last_ts,
        }
    }

    /// One line for a person: `[High 70] chain 3 npm (pid 812): P1 P2 F1 N2`.
    pub fn headline(&self) -> String {
        let fired: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.counted)
            .map(|r| format!("{:?}", r.id))
            .collect();
        format!(
            "[{:?} {}] chain {} {} (pid {}): {}",
            self.severity,
            self.score,
            self.chain,
            self.anchor.name,
            self.anchor.pid,
            fired.join(" ")
        )
    }
}
