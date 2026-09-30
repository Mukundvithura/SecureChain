# Implementation Plan

## Overview

SecRisk is developed across five phases. Each phase builds directly on the previous one, with clearly defined deliverables that can be demonstrated and reviewed independently.

The implementation is Rust throughout: eBPF programs and the userspace loader are both written with [Aya](https://github.com/aya-rs/aya), in the `sensors/` workspace. Design and build notes for everything implemented so far are in [`ebpf/sensors_design.md`](ebpf/sensors_design.md).

| Phase | Focus | Status |
|-------|-------|--------|
| 0 | Research, architecture, feasibility | Done |
| 1 | eBPF process sensor, noise filtering | Done |
| 2 | Unified event schema; file + network sensors; normalization & enrichment | Done |
| 3 | Correlation engine, risk scoring, alerting | Planned |
| 4 | Evaluation, benchmarking, documentation | Planned |

---

## Phase 0 — Research, Architecture, and Feasibility Validation

**Goal:** Establish a solid foundation before writing any production code.

### Tasks
- [x] Review existing eBPF-based security tools (Falco, Tracee, Tetragon)
- [x] Study Linux kernel eBPF subsystem and CO-RE (Compile Once, Run Everywhere)
- [x] Identify target kernel events for process, file, and network activity
- [x] Define threat taxonomy and behavioral attack chain patterns
- [x] Design system architecture (layered pipeline)
- [x] Design AWS deployment topology
- [x] Validate eBPF feasibility on the development kernel (6.19)
- [x] Set up development environment (Kali, Rust stable + nightly, Aya, bpf-linker)

### Deliverables
- `docs/problem_statement.md`
- `docs/threat_taxonomy.md`
- `docs/literature_survey.md`
- `docs/risk_analysis.md`
- `docs/architecture/system_architecture.md`
- `docs/architecture/aws_architecture.md`
- `docs/architecture/core_design.md`

---

## Phase 1 — eBPF Process Sensor

**Goal:** Capture process execution from the kernel with enough lineage to tell who started what.

### Tasks
- [x] Hook `sched/sched_process_exec` for process execution
- [x] Hook `sched/sched_process_fork` to track parent–child lineage in a BPF map
- [x] Capture PID, PPID, UID, process name, executable path
- [x] Transport events to userspace over the BPF ring buffer
- [x] Filter kernel-thread and desktop noise in-kernel

### Deliverables
- `sensors/sensors-ebpf/src/process.rs`
- `sensors/sensors/` — userspace loader emitting JSON

---

## Phase 2 — File and Network Sensors, Normalization, and Enrichment

**Goal:** Extend telemetry to file and network activity, carried in one event stream that a correlation engine can consume without further lookups.

### Tasks

#### Unified event stream
- [x] Define a shared `Event` schema (`sensors-common`) used by all sensors
- [x] Build all sensors into one BPF object sharing one ring buffer

#### File sensor
- [x] Hook `syscalls/sys_enter_openat`
- [x] Report writes, and reads of watchlisted secrets (`secret_read`)
- [x] Drop pseudo-filesystem and user-namespace churn in-kernel

#### Network sensor
- [x] Outbound TCP via `sock/inet_sock_set_state` (transition into `SYN_SENT`)
- [x] Outbound UDP (incl. DNS) via `sys_enter_connect` / `sys_enter_sendto`, gated on sockets created as `AF_INET`/`SOCK_DGRAM`

#### Normalization & enrichment
- [x] Wall-clock timestamps from the kernel's boot-relative clock
- [x] `/proc` enrichment: user, exe, cmdline, container id, backfilled ppid
- [x] Multi-level ancestry that survives an ancestor exiting
- [x] Absolute path resolution against cwd or the `openat` directory fd
- [x] Userspace noise suppression on the resolved path, plus `SECRISK_MUTE`
- [x] Capture every run to a JSONL file
- [x] Unit tests for the normalizer

#### Demo
- [x] Simulated compromised npm postinstall (`demo/supply_chain_demo.sh`)
- [x] One-command demo that runs sensors + attack and prints the chain (`demo/run_demo.sh`)
- [x] Browser viewer for captures (`demo/event_viewer.html`)

### Deliverables
- `sensors/` — process, file, and network sensors with normalizing loader
- `demo/` — end-to-end demo of a captured attack chain

### Known gaps carried forward
- Network `sport` is always `0` (not yet assigned at `SYN_SENT`)
- IPv4 only
- Events go to stdout and JSONL; nothing persists them to a database yet

---

## Phase 3 — Correlation, Risk Scoring, and Alerting

**Goal:** Turn the event stream into scored, MITRE-mapped attack chains and notify on critical findings.

### Tasks

#### Behavioral Correlation Engine
- [ ] Group events into chains by process lineage (`ancestry`) within a time window (default: 60 s)
- [ ] Define an attack chain pattern library (e.g. package manager → shell → secret read → network)
- [ ] Implement pattern matching over the live stream and over captures
- [ ] Integration tests replaying captured attack runs

#### Storage
- [ ] PostgreSQL schema for `events`, `chains`, and `alerts`
- [ ] Persist events and matched chains

#### Risk Scoring Engine
- [ ] Implement weighted risk score formula: `Process + File + Network + Context`
- [ ] Define scoring weights per event type and severity category
- [ ] Map scored alerts to MITRE ATT&CK techniques
- [ ] Apply severity thresholds (Low / Medium / High / Critical)

#### Dashboard
- [ ] Live event stream, active alerts, risk score timeline
- [ ] MITRE ATT&CK technique heatmap

#### Alerting
- [ ] Slack webhook notifier for High and Critical alerts
- [ ] Alert payload with chain summary, score, MITRE tag, and hostname
- [ ] Deduplicate repeat alerts within a 5-minute window

### Deliverables
- `detection_engine/` — correlation engine, pattern library, risk scorer, MITRE mapper
- PostgreSQL schema
- `dashboard/`
- Slack alert integration
- End-to-end demo: simulated attack → alert → Slack notification

---

## Phase 4 — Evaluation, Benchmarking, and Documentation

**Goal:** Validate the system against realistic scenarios and produce final project documentation.

### Tasks

#### Evaluation
- [ ] Simulate known supply chain attack scenarios:
  - Malicious npm postinstall script
  - Python package with reverse shell
  - Compromised build script reading credentials
- [ ] Measure detection rate and false positive rate
- [ ] Compare against Falco with equivalent ruleset

#### Benchmarking
- [ ] Measure CPU overhead: idle vs. monitored system
- [ ] Measure memory usage of eBPF maps and userspace process
- [ ] Measure event processing latency (kernel capture → alert generation)
- [ ] Document results in a benchmarking report

#### Documentation
- [ ] Finalize all `docs/` files
- [ ] Document attack chain pattern format for extensibility
- [ ] Write project report / academic paper draft

### Deliverables
- Evaluation report with detection results
- Performance benchmarking report
- Final `docs/` documentation suite
- Project report / paper draft
- Recorded demo of end-to-end detection

---

## Milestone Summary

| Phase | Key Milestone                                      | Status |
|-------|----------------------------------------------------|--------|
| 0     | Architecture reviewed, eBPF feasible on target kernel | Done |
| 1     | Process events captured with lineage               | Done |
| 2     | Process, file, and network events in one enriched stream; demo attack captured end to end | Done |
| 3     | Attack chains correlated, scored, and alerted      | Planned |
| 4     | System evaluated, benchmarked, and documented      | Planned |
