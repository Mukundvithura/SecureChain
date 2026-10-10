//! File rules: credential theft, staging, persistence, build and system tampering.

use super::{Ctx, Finding, RuleId::*, basename, lists::*};
use crate::{mitre::Tactic, proctable::Proc};

pub fn check_write(ctx: &Ctx, found: &mut Vec<Finding>) {
    let path = ctx.path();
    let base = basename(path);

    if path.starts_with("/dev/shm/")
        || ((path.starts_with("/tmp/") || path.starts_with("/var/tmp/")) && base.starts_with('.'))
    {
        found.push(Finding::new(F2, format!("write {path}")));
    }
    if [".bashrc", ".zshrc", ".profile", ".bash_profile"].contains(&base) {
        found.push(Finding::new(F3, format!("write {path}")));
    }
    if path.starts_with("/etc/cron") || path.starts_with("/var/spool/cron/") {
        found.push(Finding::new(F4, format!("write {path}")));
    }
    if path.starts_with("/etc/systemd/system/") || path.contains("/.config/systemd/user/") {
        found.push(Finding::new(F5, format!("write {path}")));
    }
    if base == "authorized_keys" || base == "authorized_keys2" {
        found.push(Finding::new(F6, format!("write {path}")));
    }

    let p = ctx.proc();
    if ctx.in_build_chain() && OBJECT_SUFFIXES.iter().any(|s| path.ends_with(s)) && !is_compiler(p)
    {
        found.push(Finding::new(L6, format!("{} wrote {path}", name(p))));
    }
    if (ctx.in_dependency_chain() || ctx.in_build_chain())
        && !ctx.is_anchor()
        && SYSTEM_BIN_DIRS.iter().any(|d| path.starts_with(d))
    {
        found.push(Finding::new(L7, format!("{} wrote {path}", name(p))));
    }
    if ctx.in_dependency_chain() {
        let target = SYSTEM_FILES
            .iter()
            .find(|(f, ..)| path == *f)
            .copied()
            .or_else(|| {
                path.starts_with("/etc/sudoers.d/").then_some((
                    "/etc/sudoers.d/",
                    "T1548.003",
                    Some(Tactic::PrivilegeEscalation),
                ))
            });
        if let Some((_, technique, tactic)) = target {
            found.push(Finding::new(L10, format!("write {path}")).mapped(technique, tactic));
        }
    }
    if PACKAGE_CACHES.iter().any(|c| path.contains(c)) && !owns_cache(ctx) {
        found.push(Finding::new(L11, format!("{} wrote {path}", name(p))));
    }
}

pub fn check_secret(ctx: &Ctx, found: &mut Vec<Finding>) {
    let path = ctx.path();
    let p = ctx.proc();

    if let Some(target) = environ_of(path) {
        if target != ctx.ev.pid {
            found.push(Finding::new(L8, format!("{} read {path}", name(p))));
        }
        return;
    }
    if PUBLIC_CERT_DIRS.iter().any(|d| path.starts_with(d)) {
        return;
    }
    let Some(secret) = SECRETS
        .iter()
        .find(|s| s.suffixes.iter().any(|x| path.ends_with(x)))
    else {
        return;
    };
    let normal_reader = p.is(secret.readers)
        || p.names
            .iter()
            .any(|n| secret.reader_prefixes.iter().any(|x| n.starts_with(x)));
    if normal_reader {
        return;
    }
    if secret.dependency_only && !(ctx.in_dependency_chain() || ctx.in_build_chain()) {
        return;
    }
    found.push(
        Finding::new(F1, format!("{} read {path}", name(p)))
            .mapped(secret.technique, Some(Tactic::CredentialAccess)),
    );
}

/// `/proc/<pid>/environ` → pid. `self` and `thread-self` are the reader's own.
fn environ_of(path: &str) -> Option<u32> {
    path.strip_prefix("/proc/")?
        .strip_suffix("/environ")?
        .parse()
        .ok()
}

fn is_compiler(p: &Proc) -> bool {
    p.is(COMPILERS)
        || p.names
            .iter()
            .any(|n| COMPILER_PREFIXES.iter().any(|x| n.starts_with(x)))
        || p.exe.as_deref().is_some_and(|e| e.contains(GO_TOOL_DIR))
}

/// L11's exemption: the package manager writing its own cache.
fn owns_cache(ctx: &Ctx) -> bool {
    let p = ctx.proc();
    ctx.is_anchor()
        || p.is(DEPENDENCY_TOOLS)
        || p.cmdline
            .as_deref()
            .is_some_and(|c| CACHE_OWNER_MARKERS.iter().any(|m| c.contains(m)))
}

fn name(p: &Proc) -> &str {
    p.names.first().map_or(p.comm.as_str(), String::as_str)
}
