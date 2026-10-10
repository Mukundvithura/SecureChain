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
    // L12: a command running directly under the sshd listener rather than a
    // per-session process is pre-authentication execution — the shape of the
    // xz/liblzma backdoor, which ran its payload inside the privileged sshd
    // before any login. On OpenSSH 9.8+ (this host is 10.4) a normal login
    // reaches the user's shell through sshd-session / sshd-auth, so the
    // listener directly spawning an ordinary command is the anomaly.
    // **Decision:** the parent must be the listener and not a session worker,
    // and the child must not itself be an sshd helper, so the listener
    // forking its own session process does not match. Limitation: on pre-9.8
    // sshd the privsep child also reports comm `sshd`, so this would need an
    // argv check (`sshd: user@…`) there — out of scope for the modern target.
    if let Some(parent) = ctx.parent()
        && parent.is(SSHD_LISTENER)
        && !parent.is(SSHD_SESSION)
        && !p.is(SSHD_LISTENER)
        && !p.is(SSHD_SESSION)
    {
        found.push(Finding::new(
            L12,
            format!("{} ran directly under the sshd listener", name_of(p)),
        ));
    }
}

fn name_of(p: &crate::proctable::Proc) -> &str {
    p.names.first().map_or(p.comm.as_str(), String::as_str)
}
