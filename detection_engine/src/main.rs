//! `secrisk-engine`: score normalized sensor events.
//!
//!     sudo ./sensors/target/debug/sensors | secrisk-engine        # live
//!     secrisk-engine replay sensors/captures/demo-<ts>.jsonl      # a capture
//!
//! Alerts and chain summaries go to stdout as JSON lines; a one-line headline
//! per alert and a closing tally go to stderr.

use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
};

use anyhow::{Context, bail};
use secrisk_engine::{Engine, event::Event, report::Kind};

const USAGE: &str = "\
usage: secrisk-engine [replay] [--all-chains] [FILE...]

Reads normalized SecRisk events (JSON lines) from each FILE, or from stdin when
none is given, and writes alerts and chain summaries as JSON lines.

  --all-chains   also summarize chains where no rule fired";

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "replay") {
        args.remove(0);
    }
    let mut all_chains = false;
    let mut files = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--all-chains" => all_chains = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            flag if flag.starts_with('-') => bail!("unknown option {flag}\n\n{USAGE}"),
            _ => files.push(arg),
        }
    }

    let mut out = io::stdout().lock();
    if files.is_empty() {
        run(io::stdin().lock(), "stdin", all_chains, &mut out)?;
    }
    for path in &files {
        let file = File::open(path).with_context(|| format!("opening {path}"))?;
        run(BufReader::new(file), path, all_chains, &mut out)?;
    }
    Ok(())
}

/// Score one input from start to end. Each file is its own capture, so each
/// gets a fresh engine.
fn run(
    input: impl BufRead,
    name: &str,
    all_chains: bool,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let mut engine = Engine::new(all_chains);
    let mut bad = 0u64;
    for (n, line) in input.lines().enumerate() {
        let line = line.with_context(|| format!("reading {name}"))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(&line) {
            Ok(ev) => {
                for report in engine.process(&ev) {
                    emit(&report, out)?;
                }
            }
            Err(e) => {
                bad += 1;
                if bad <= 3 {
                    eprintln!("{name}:{}: skipped: {e}", n + 1);
                }
            }
        }
    }
    for report in engine.finish() {
        emit(&report, out)?;
    }
    eprintln!(
        "{name}: {} events, {} chains, {} alerts{}",
        engine.events,
        engine.chains_seen,
        engine.alerts,
        if bad > 0 {
            format!(", {bad} unreadable lines skipped")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn emit(report: &secrisk_engine::report::Report, out: &mut impl Write) -> anyhow::Result<()> {
    if report.record == Kind::Alert {
        eprintln!("{}", report.headline());
    }
    writeln!(out, "{}", serde_json::to_string(report)?)?;
    // Live, an alert is only useful the moment it happens.
    out.flush()?;
    Ok(())
}
