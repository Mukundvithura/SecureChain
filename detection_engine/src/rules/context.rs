//! Context rules that look at every event. C1 is recorded when a dependency
//! chain opens and C3 after scoring; both live in the engine.

use super::{Ctx, Finding, RuleId::*, lists::*};
use crate::event::Action;

pub fn check(ctx: &Ctx, found: &mut Vec<Finding>) {
    let ev = ctx.ev;
    if ev.uid == 0 && ctx.chain.anchor.uid.is_some_and(|u| u != 0) {
        found.push(Finding::new(
            C2,
            format!("{} ran as root under a non-root anchor", ev.comm),
        ));
    }
    if ev.action == Action::Exec
        && (ev.container.is_some() || ctx.proc().container.is_some())
        && let Some(tool) = ctx.proc().name_in(CONTAINER_TOOLS)
    {
        found.push(Finding::new(L9, format!("{tool} inside a container")));
    }
}
