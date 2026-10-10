//! Network rules: a chain reaching out, most heavily after it touched a secret.

use super::{Ctx, Finding, RuleId::*, lists::*};

pub fn check(ctx: &Ctx, found: &mut Vec<Finding>) {
    let ev = ctx.ev;
    if ev.is_loopback() {
        return;
    }
    let dest = format!(
        "{}:{}",
        ev.daddr.as_deref().unwrap_or("?"),
        ev.dport.map_or_else(|| "?".to_string(), |p| p.to_string())
    );
    let p = ctx.proc();

    if (ctx.in_dependency_chain() || ctx.in_build_chain()) && !ctx.is_anchor() {
        found.push(Finding::new(N1, format!("{} connected to {dest}", p.comm)));
    }
    if ctx.chain.first_secret.is_some_and(|t| t <= ev.ts) {
        found.push(Finding::new(
            N2,
            format!("{} connected to {dest} after a secret read", p.comm),
        ));
    }
    if ev.dport.is_some_and(|port| !SAFE_PORTS.contains(&port)) {
        found.push(Finding::new(N3, format!("connect to {dest}")));
    }
    if let Some(shell) = p.name_in(SHELLS) {
        found.push(Finding::new(
            L2,
            format!("{shell} itself connected to {dest}"),
        ));
    }
}
