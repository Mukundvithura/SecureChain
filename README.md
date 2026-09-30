# Behavioral Runtime Detection of Software Supply Chain Attacks using eBPF

## Overview

SecRisk is a lightweight, eBPF-based runtime monitoring framework designed to detect software supply chain attacks in real time. Unlike traditional security tools that rely on signatures or static analysis, SecRisk observes actual runtime behavior — process execution, file access, network activity — and correlates events across telemetry sources to identify attack chains specific to supply chain threats.

Motivated by real-world incidents such as SolarWinds, Codecov, and XZ Utils, this project targets a critical gap: most existing runtime security tools generate generic alerts from isolated events. SecRisk aims to detect behavioral attack chains and produce risk-scored, MITRE ATT&CK-mapped alerts with minimal performance overhead.

---

## Objectives

1. Develop a custom eBPF-based monitoring framework for Linux environments.
2. Capture runtime process, file, and network telemetry at the kernel level.
3. Correlate events across telemetry sources into behavioral attack chains.
4. Detect patterns characteristic of software supply chain attacks.
5. Generate risk scores and actionable alerts mapped to MITRE ATT&CK techniques.
6. Deliver a functional prototype with measurable low overhead.

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│              Kernel Space                   │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Process  │ │  File    │ │   Network   │ │
│  │ Monitor  │ │ Monitor  │ │   Monitor   │ │
│  └────┬─────┘ └────┬─────┘ └──────┬──────┘ │
│       └────────────┼───────────────┘        │
│               BPF Maps / Ring Buffer        │
└───────────────────┬─────────────────────────┘
                    ↓
       Userspace Loader (Rust / Aya)
                    ↓
    Normalization + Enrichment (wall clock,
     /proc identity, lineage, path resolution)
                    ↓
       Behavioral Correlation Engine
                    ↓
          Risk Scoring Engine
                    ↓
     ┌──────────────┴──────────────┐
     │         Alert System        │
     │  PostgreSQL │ Dashboard     │
     │  Slack Notifications        │
     └─────────────────────────────┘
```

See [`docs/architecture/system_architecture.md`](docs/architecture/system_architecture.md) for the full layer-by-layer breakdown and [`docs/architecture/aws_architecture.md`](docs/architecture/aws_architecture.md) for the deployment design.

---

## Quick Start

The demo runs the whole pipeline — sensors, a simulated compromised package,
and the reconstructed attack chain — in one command:

```shell
./demo/run_demo.sh
```

It asks for sudo once (loading eBPF programs needs root), builds the sensors on
first run, and prints the chain it caught:

```
  00:05:57.258  EXEC         /tmp/secrisk-demo/npm-install.sh
  00:05:57.264  EXEC         /usr/bin/sh
  00:05:57.272  EXEC         /usr/bin/cat
  00:05:57.276  SECRET_READ  /tmp/secrisk-demo/home/.ssh/id_rsa
  00:05:57.277  WRITE        /dev/shm/.update-cache
  00:05:57.283  EXEC         /usr/bin/curl
  00:05:57.350  CONNECT      104.20.23.154:80
```

Every step shares one process lineage — that link is what the correlation engine
will consume. The capture is kept at `sensors/captures/demo-<timestamp>.jsonl`;
open [`demo/event_viewer.html`](demo/event_viewer.html) and drop the file on it
for a readable view.

To watch a real workload instead, run the sensors on their own and use the
machine normally — see [`sensors/README.md`](sensors/README.md).

---

## Technology Stack

| Layer                  | Technology                        |
|------------------------|-----------------------------------|
| Kernel Instrumentation | eBPF (CO-RE)                      |
| eBPF + userspace       | Rust ([Aya](https://github.com/aya-rs/aya)) |
| Event transport        | BPF ring buffer → unified `Event` schema |
| Normalization          | userspace loader: wall-clock time, `/proc` enrichment, path resolution |
| Behavioral Engine      | Rust *(planned)*                  |
| Event Storage          | PostgreSQL *(planned)*            |
| Dashboard              | custom web UI *(planned)*         |
| Alerting               | Slack Webhook *(planned)*         |
| Deployment             | AWS EC2 (prototype), Kubernetes (future) |
| Threat Mapping         | MITRE ATT&CK                      |

---

## Project Roadmap

| Phase | Focus                              | Status      |
|-------|------------------------------------|-------------|
| 0     | Research, architecture, feasibility | Done |
| 1     | eBPF process sensor (exec + fork lineage), noise filtering | Done |
| 2     | Unified event schema + ring-buffer transport; file + network sensors; normalization & enrichment | Done |
| 3     | Correlation engine, risk scoring, alerting | Planned |
| 4     | Evaluation, benchmarking, documentation | Planned |

See [`docs/implementation_plan.md`](docs/implementation_plan.md) for detailed phase breakdown with deliverables and milestones.

---

## Repository Structure

```
SecRisk/
│
├── demo/
│   ├── run_demo.sh                # one-command demo: sensors + attack + chain
│   ├── supply_chain_demo.sh       # the simulated compromised npm postinstall
│   └── event_viewer.html          # drop a capture on it to read it
│
├── docs/
│   ├── problem_statement.md       # Problem definition and objectives
│   ├── threat_taxonomy.md         # Runtime-detectable supply chain attack categories
│   ├── literature_survey.md       # Review of existing tools and research gaps
│   ├── risk_analysis.md           # Technical and operational risks with mitigations
│   ├── implementation_plan.md     # Phased development roadmap
│   ├── ebpf/
│   │   └── sensors_design.md      # Sensor suite design & build notes (start here)
│   └── architecture/
│       ├── core_design.md         # eBPF engine design and scoring framework
│       ├── system_architecture.md # Full system layer architecture
│       └── aws_architecture.md    # Cloud deployment architecture
│
├── sensors/                       # Rust/Aya workspace — the implemented sensor suite
│   ├── sensors/                   #   userspace loader + normalizer (ring buffer → enriched JSON)
│   ├── sensors-common/            #   shared Event schema
│   └── sensors-ebpf/              #   eBPF program: process.rs, file.rs, network.rs
│
├── detection_engine/              # Behavioral correlation and risk scoring (planned)
│
├── dashboard/                     # Visualization and alerting UI (planned)
│
├── deployment/                    # Deploy configs — local / AWS / k8s (planned)
│
└── README.md
```

> The implemented sensor suite lives entirely in `sensors/` (Rust/Aya) — start
> at [`docs/ebpf/sensors_design.md`](docs/ebpf/sensors_design.md). The
> `detection_engine/`, `dashboard/`, and `deployment/` directories are
> placeholders for planned phases.
