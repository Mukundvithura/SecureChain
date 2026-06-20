# Implementation Plan

## Overview

SecRisk is developed across five phases. Each phase builds directly on the previous one, with clearly defined deliverables that can be demonstrated and reviewed independently.

---

## Phase 0 — Research, Architecture, and Feasibility Validation

**Goal:** Establish a solid foundation before writing any production code.

### Tasks
- [ ] Review existing eBPF-based security tools (Falco, Tracee, Tetragon)
- [ ] Study Linux kernel eBPF subsystem and CO-RE (Compile Once, Run Everywhere)
- [ ] Identify target syscalls: `execve()`, `openat()`, `tcp_connect()`
- [ ] Define threat taxonomy and behavioral attack chain patterns
- [ ] Design system architecture (layered pipeline)
- [ ] Design AWS deployment topology
- [ ] Validate eBPF feasibility on target kernel version (5.15+)
- [ ] Set up development environment (Kali/Ubuntu, libbpf, clang, Go)

### Deliverables
- `docs/problem_statement.md`
- `docs/threat_taxonomy.md`
- `docs/literature_survey.md`
- `docs/risk_analysis.md`
- `docs/architecture/system_architecture.md`
- `docs/architecture/aws_architecture.md`
- `docs/architecture/core_design.md`
- Working eBPF "hello world" probe (proof of concept)

---

## Phase 1 — eBPF Process Monitor, Event Collection, and Storage

**Goal:** Capture process execution events from the kernel and persist them.

### Tasks
- [ ] Write eBPF C program hooking `execve()` syscall
- [ ] Capture: PID, PPID, UID, process name, command line, timestamp
- [ ] Use BPF ring buffer for kernel-to-userspace event transport
- [ ] Write Go userspace collector to read and parse ring buffer events
- [ ] Normalize event structs into a common Go data model
- [ ] Define PostgreSQL schema (`events` table)
- [ ] Implement event writer to persist to PostgreSQL
- [ ] Write unit tests for collector and storage layer
- [ ] Benchmark: measure CPU and memory overhead of process monitoring

### Deliverables
- `ebpf/process_monitor/` — eBPF C program + Makefile
- `collector/` — Go collector with ring buffer reader
- PostgreSQL `events` table schema
- Phase 1 benchmark report

---

## Phase 2 — File Monitoring, Network Monitoring, and Correlation Engine

**Goal:** Extend telemetry to file and network activity, then correlate events into attack chains.

### Tasks

#### File Monitoring
- [ ] Write eBPF C program hooking `openat()` syscall
- [ ] Capture: filename, PID, access type (read/write), timestamp
- [ ] Integrate file events into collector and storage pipeline

#### Network Monitoring
- [ ] Write eBPF C program hooking `tcp_connect()` kprobe
- [ ] Capture: destination IP, destination port, PID, timestamp
- [ ] Integrate network events into collector and storage pipeline

#### Behavioral Correlation Engine
- [ ] Design process ancestry tracker (link PIDs to parent processes)
- [ ] Implement time-windowed event grouping (default: 60-second window)
- [ ] Define attack chain pattern library (e.g., package-manager → shell → network → credential access)
- [ ] Implement pattern matching engine
- [ ] Persist matched chains to PostgreSQL `chains` table
- [ ] Write integration tests simulating known attack patterns

### Deliverables
- `ebpf/file_monitor/` — eBPF C program
- `ebpf/network_monitor/` — eBPF C program
- `detection_engine/` — correlation engine with pattern library
- PostgreSQL `chains` table schema
- Phase 2 test report with matched chain examples

---

## Phase 3 — Risk Scoring, Dashboard, and Alerting

**Goal:** Score detected attack chains, visualize results, and notify on critical findings.

### Tasks

#### Risk Scoring Engine
- [ ] Implement weighted risk score formula: `Process + File + Network + Context`
- [ ] Define scoring weights per event type and severity category
- [ ] Map scored alerts to MITRE ATT&CK techniques
- [ ] Persist alerts to PostgreSQL `alerts` table
- [ ] Apply severity thresholds (Low / Medium / High / Critical)

#### Dashboard
- [ ] Set up Grafana connected to PostgreSQL (or custom web UI)
- [ ] Build panels: live event stream, active alerts, risk score timeline
- [ ] Build MITRE ATT&CK technique heatmap
- [ ] Expose dashboard on port 3000

#### Alerting
- [ ] Implement Slack webhook notifier
- [ ] Trigger Slack notification for High and Critical severity alerts
- [ ] Format alert payload with chain summary, score, MITRE tag, and hostname
- [ ] Add alert deduplication (suppress repeat alerts within 5-minute window)

### Deliverables
- `detection_engine/` — risk scoring module + MITRE mapper
- `dashboard/` — dashboard configuration and server
- PostgreSQL `alerts` table schema
- Slack alert integration with example notifications
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
- [ ] Write `README.md` setup and usage guide
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

| Phase | Key Milestone                                      |
|-------|----------------------------------------------------|
| 0     | Architecture reviewed and eBPF probe running       |
| 1     | Process events captured, stored, and queryable     |
| 2     | Attack chains correlated from multi-source events  |
| 3     | Scored alerts appearing in dashboard and Slack     |
| 4     | System evaluated, benchmarked, and documented      |
