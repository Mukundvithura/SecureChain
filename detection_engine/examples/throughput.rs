//! Per-event cost of the engine, measured in isolation from the sensors.
//!
//!     cargo run --release --example throughput [events]
//!
//! Builds a synthetic stream that mixes the compromised-install chain with
//! benign churn, parses it to events once, then times only `Engine::process`
//! over the stream. Reports ns per event and events per second — the engine's
//! own cost, with sensor capture and JSON parsing excluded.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use secrisk_engine::{Engine, event::Event};

/// One attack chain plus benign noise, at distinct pids so each `base` makes a
/// fresh set of chains. Mirrors the shape the normalizer emits.
fn block(base: u32, t0: u64) -> Vec<String> {
    let npm = base;
    let sh = base + 1;
    let cat = base + 2;
    let curl = base + 3;
    let ls = base + 4;
    let home = "/home/u";
    let mut t = t0;
    let mut next = || {
        t += 1_000_000;
        t
    };
    let exec = |ts: u64, pid: u32, ppid: u32, comm: &str, exe: &str, cmd: &str| {
        format!(
            r#"{{"ts":{ts},"time":"t","action":"exec","pid":{pid},"ppid":{ppid},"uid":1000,"comm":"{comm}","exe":"{exe}","cmdline":"{cmd}","ancestry":[{{"pid":{ppid},"comm":"zsh"}}]}}"#
        )
    };
    vec![
        exec(
            next(),
            npm,
            50,
            "npm",
            "/usr/bin/npm",
            "node /usr/bin/npm install x",
        ),
        exec(
            next(),
            sh,
            npm,
            "sh",
            "/usr/bin/sh",
            "sh -c ./postinstall.sh",
        ),
        exec(next(), cat, sh, "cat", "/usr/bin/cat", "cat id_rsa"),
        format!(
            r#"{{"ts":{},"time":"t","action":"secret_read","pid":{cat},"ppid":{sh},"uid":1000,"comm":"cat","path":"{home}/.ssh/id_rsa","ancestry":[{{"pid":{sh},"comm":"sh"}}]}}"#,
            next()
        ),
        format!(
            r#"{{"ts":{},"time":"t","action":"write","pid":{sh},"ppid":{npm},"uid":1000,"comm":"sh","path":"/dev/shm/.implant","ancestry":[{{"pid":{npm},"comm":"npm"}}]}}"#,
            next()
        ),
        exec(next(), curl, sh, "curl", "/usr/bin/curl", "curl http://h/"),
        format!(
            r#"{{"ts":{},"time":"t","action":"connect","pid":{curl},"ppid":{sh},"uid":1000,"comm":"curl","daddr":"93.184.216.34","dport":4444,"ancestry":[{{"pid":{sh},"comm":"sh"}}]}}"#,
            next()
        ),
        // Benign churn under the terminal: its own chain, no rules.
        exec(next(), ls, 50, "ls", "/usr/bin/ls", "ls -la"),
    ]
}

fn main() {
    let target: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1_000_000);

    // Build and parse the stream once; timing covers only engine work.
    let mut lines = Vec::new();
    let mut base = 1000u32;
    let mut t0 = 1_790_000_000_000_000_000u64;
    while lines.len() < target {
        lines.extend(block(base, t0));
        base += 10;
        t0 += 100_000_000; // 100 ms between chains, so they expire and free state
    }
    lines.truncate(target);
    let events: Vec<Event> = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("valid synthetic event"))
        .collect();

    // Warm up, then measure; take the best of a few runs to cut scheduler noise.
    let mut best = Duration::MAX;
    for run in 0..4 {
        let mut engine = Engine::new(false);
        let start = Instant::now();
        for ev in &events {
            black_box(engine.process(black_box(ev)));
        }
        black_box(engine.finish());
        let elapsed = start.elapsed();
        if run > 0 {
            best = best.min(elapsed);
        }
    }

    let n = events.len() as f64;
    let ns = best.as_nanos() as f64 / n;
    println!("events:            {}", events.len());
    println!("best wall time:    {:.3} ms", best.as_secs_f64() * 1e3);
    println!("per event:         {ns:.1} ns");
    println!(
        "throughput:        {:.2} M events/s",
        n / best.as_secs_f64() / 1e6
    );
}
