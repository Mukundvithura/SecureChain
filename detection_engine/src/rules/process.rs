//! Process rules: unexpected programs running inside a chain. All fire on exec.

use super::{Ctx, Finding, RuleId::*, lists::*};

pub fn check(ctx: &Ctx, found: &mut Vec<Finding>) {
    let p = ctx.proc();
    let path = ctx.path();
    let dependency = ctx.in_dependency_chain() && !ctx.is_anchor();

    if dependency && let Some(shell) = p.name_in(SHELLS) {
        found.push(Finding::new(
            P1,
            format!("{shell} under {}", ctx.anchor_name()),
        ));
    }
    if dependency && let Some(tool) = p.name_in(DOWNLOADERS) {
        found.push(Finding::new(
            P2,
            format!("{tool} under {}", ctx.anchor_name()),
        ));
    }
    if STAGING_DIRS.iter().any(|d| path.starts_with(d)) {
        found.push(Finding::new(P3, format!("exec {path}")));
    }
    if ctx.chain.written.contains(path) {
        found.push(Finding::new(
            L1,
            format!("exec of {path}, written earlier in the chain"),
        ));
    }

    let cmdline = p.cmdline.as_deref().unwrap_or("");
    if ctx.in_dependency_chain()
        && let Some(pattern) = DECODE_AND_RUN
            .iter()
            .find(|pat| cmdline.contains(*pat))
            .copied()
            .or_else(|| {
                cmdline
                    .split_whitespace()
                    .any(|w| w == "eval")
                    .then_some("eval")
            })
    {
        found.push(Finding::new(L3, format!("\"{pattern}\" in: {cmdline}")));
    }
    if ctx.in_build_chain()
        && let Some(tool) = p.name_in(DECOMPRESSORS)
        && cmdline.split_whitespace().any(|a| a.contains("tests/"))
    {
        found.push(Finding::new(L5, format!("{tool} on test data: {cmdline}")));
    }
    if (ctx.in_dependency_chain() || ctx.in_build_chain())
        && let Some(tool) = p.name_in(ENV_DUMPERS)
    {
        found.push(Finding::new(
            L8,
            format!("{tool} under {}", ctx.anchor_name()),
        ));
    }
    // L12 (pre-authentication sshd execution) is not implemented: the plan
    // holds it until a real SSH login is captured to tell the sshd listener
    // from its per-session processes.
}
