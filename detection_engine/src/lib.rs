//! SecRisk correlation engine.
//!
//! Reads the normalizer's events, groups each into the chain of its anchor
//! process, runs the detection rules against it and scores the chain. A chain
//! alerts when its score enters a band at Medium (31) or above that it has not
//! alerted in before, and writes a summary when it goes 60 s without events.

pub mod chain;
pub mod event;
pub mod mitre;
pub mod proctable;
pub mod report;
pub mod rules;
pub mod score;

use std::collections::HashMap;

use chain::{Anchor, AnchorKind, Chain, Hit};
use event::{Action, Event};
use proctable::ProcTable;
use report::{Kind, Report};
use rules::{Ctx, Finding, RuleId, lists};
use score::{Score, Severity};

/// A chain closes after this long with no events.
pub const IDLE_NS: u64 = 60_000_000_000;
/// How often, in event time, to look for idle chains.
const SWEEP_NS: u64 = 1_000_000_000;

pub struct Engine {
    procs: ProcTable,
    /// Keyed by the anchor's pid and start time, so a reused pid is a new chain.
    chains: HashMap<(u32, u64), Chain>,
    next_id: u64,
    last_sweep: u64,
    /// Summarize every chain, not only those where a rule fired.
    all_chains: bool,
    pub events: u64,
    pub chains_seen: u64,
    pub alerts: u64,
}

impl Engine {
    pub fn new(all_chains: bool) -> Self {
        Engine {
            procs: ProcTable::default(),
            chains: HashMap::new(),
            next_id: 0,
            last_sweep: 0,
            all_chains,
            events: 0,
            chains_seen: 0,
            alerts: 0,
        }
    }

    /// Feed one event; returns the alerts it raised and the summaries of any
    /// chains that went idle before it.
    pub fn process(&mut self, ev: &Event) -> Vec<Report> {
        let mut out = Vec::new();
        self.expire(ev.ts, &mut out);
        self.events += 1;

        self.procs.observe(ev);
        let lineage = self.procs.lineage(ev.pid);
        if lineage.is_empty() {
            return out;
        }
        let (idx, kind) = chain::find_anchor(&lineage);
        let anchor = lineage[idx];
        let key = (anchor.pid, anchor.start_ts);

        let is_new = !self.chains.contains_key(&key);
        if is_new {
            self.next_id += 1;
            self.chains_seen += 1;
            self.chains.insert(
                key,
                Chain::new(self.next_id, Anchor::of(anchor, kind), ev.ts),
            );
        }
        let chain = self.chains.get_mut(&key).expect("inserted above");
        chain.anchor.refresh(anchor);
        if lineage[..=idx].iter().any(|p| p.is(lists::BUILD_TOOLS)) {
            chain.build = true;
        }

        let mut new_hit = false;
        if is_new && kind != AnchorKind::User {
            let f = Finding::new(RuleId::C1, format!("anchor is {}", chain.anchor.name));
            new_hit |= chain.record(RuleId::C1, hit(ev, &lineage[0].comm, f));
        }

        let findings = rules::evaluate(&Ctx {
            ev,
            lineage: &lineage,
            anchor_idx: idx,
            chain,
        });
        let mut secret = false;
        for f in findings {
            secret |= matches!(f.rule, RuleId::F1 | RuleId::L8);
            let rule = f.rule;
            new_hit |= chain.record(rule, hit(ev, &lineage[0].comm, f));
        }
        if secret && chain.first_secret.is_none() {
            chain.first_secret = Some(ev.ts);
        }
        if ev.action == Action::Write
            && let Some(p) = &ev.path
        {
            chain.written.insert(p.clone());
        }
        chain.last_ts = ev.ts;
        chain.last_time.clone_from(&ev.time);
        chain.events += 1;

        if new_hit && let Some(alert) = rescore(chain, ev) {
            self.alerts += 1;
            out.push(alert);
        }
        out
    }

    /// Close every open chain, oldest first, at the end of the input.
    pub fn finish(&mut self) -> Vec<Report> {
        let mut chains: Vec<Chain> = self.chains.drain().map(|(_, c)| c).collect();
        chains.sort_by_key(|c| c.id);
        chains
            .into_iter()
            .filter_map(|c| self.summary(&c))
            .collect()
    }

    fn expire(&mut self, now: u64, out: &mut Vec<Report>) {
        if now < self.last_sweep + SWEEP_NS {
            return;
        }
        self.last_sweep = now;
        let idle: Vec<(u32, u64)> = self
            .chains
            .iter()
            .filter(|(_, c)| c.last_ts + IDLE_NS < now)
            .map(|(k, _)| *k)
            .collect();
        let mut closed: Vec<Chain> = idle.iter().filter_map(|k| self.chains.remove(k)).collect();
        closed.sort_by_key(|c| c.id);
        out.extend(closed.iter().filter_map(|c| self.summary(c)));
    }

    fn summary(&self, chain: &Chain) -> Option<Report> {
        if chain.hits.is_empty() && !self.all_chains {
            return None;
        }
        let score = Score::of(&chain.hits);
        Some(Report::new(Kind::Chain, chain, &score, &chain.last_time))
    }
}

fn hit(ev: &Event, comm: &str, f: Finding) -> Hit {
    Hit {
        ts: ev.ts,
        time: ev.time.clone(),
        pid: ev.pid,
        comm: comm.to_string(),
        detail: f.detail,
        technique: f.technique,
        tactic: f.tactic,
    }
}

/// Rescore after a new hit: add C3 if the tactics now progress, and alert if
/// the chain entered a higher band at Medium or above.
fn rescore(chain: &mut Chain, ev: &Event) -> Option<Report> {
    let mut score = Score::of(&chain.hits);
    if !chain.hits.contains_key(&RuleId::C3)
        && let Some(tactics) = score::progression(&chain.hits, &score.counted)
    {
        let names: Vec<&str> = tactics.iter().map(|t| t.name()).collect();
        let f = Finding::new(RuleId::C3, names.join(" -> "));
        chain.record(RuleId::C3, hit(ev, &ev.comm, f));
        score = Score::of(&chain.hits);
    }
    let severity = Severity::of(score.total);
    if severity >= Severity::Medium && severity > chain.alerted {
        chain.alerted = severity;
        return Some(Report::new(Kind::Alert, chain, &score, &ev.time));
    }
    None
}
