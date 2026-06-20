# System Architecture

## Overview

SecRisk follows a layered pipeline architecture. Each layer has a single responsibility — from raw kernel-level event capture through to human-readable alerts. This separation makes the system modular: layers can be tested, replaced, or extended independently.

```
┌──────────────────────────────────────────────────────────┐
│                     Kernel Space                         │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Telemetry Collection Layer              │ │
│  │   Process Monitor │ File Monitor │ Network Monitor  │ │
│  └─────────────────────────┬───────────────────────────┘ │
│                        BPF Maps / Ring Buffer            │
└────────────────────────────┼─────────────────────────────┘
                             ↓
┌────────────────────────────────────────────────────────┐
│               Event Processing Layer                   │
│          Userspace Collector (Go)                      │
│    Parse → Normalize → Enrich → Forward                │
└────────────────────────────┬───────────────────────────┘
                             ↓
┌────────────────────────────────────────────────────────┐
│            Behavioral Correlation Layer                │
│    Sequence matching → Attack chain construction       │
└────────────────────────────┬───────────────────────────┘
                             ↓
┌────────────────────────────────────────────────────────┐
│                   Detection Layer                      │
│         Risk Scoring Engine + MITRE ATT&CK Mapping    │
└────────────────────────────┬───────────────────────────┘
                             ↓
┌────────────────────────────────────────────────────────┐
│                   Response Layer                       │
│     PostgreSQL Storage │ Dashboard │ Slack Alerts      │
└────────────────────────────────────────────────────────┘
```

---

## Telemetry Collection Layer

**Location:** Kernel space — eBPF programs attached to syscall hooks.

This is the lowest layer. Three eBPF sensor programs run inside the kernel and hook into specific syscalls to capture security-relevant events with near-zero latency.

| Sensor           | Hook            | Captured Fields                                      |
|------------------|-----------------|------------------------------------------------------|
| Process Monitor  | `execve()`      | PID, PPID, UID, process name, command line, timestamp |
| File Monitor     | `openat()`      | Filename, PID, access type (read/write), timestamp   |
| Network Monitor  | `tcp_connect()` | Destination IP, destination port, PID, timestamp     |

Events are written into **BPF ring buffers** — a high-throughput, low-overhead mechanism for streaming data from kernel space to userspace without packet loss.

---

## Event Processing Layer

**Location:** Userspace — Go collector process.

The collector continuously reads from the ring buffer and performs:

1. **Parsing** — Deserialize raw binary event structs into Go objects.
2. **Normalization** — Standardize field names, timestamps, and data formats across event types.
3. **Enrichment** — Attach contextual metadata: parent process name, process ancestry, file path classification, IP geolocation (future).
4. **Storage** — Persist normalized events to PostgreSQL.
5. **Forwarding** — Stream enriched events to the Behavioral Correlation Layer.

---

## Behavioral Correlation Layer

**Location:** Userspace — Go detection engine.

Individual events are meaningless in isolation. This layer groups related events by process ancestry and time window, then matches the resulting sequences against known attack chain patterns.

**Example — Supply Chain Attack Chain:**
```
[1] npm install             → execve(): node / npm
[2] bash spawned by npm     → execve(): /bin/bash (parent: npm)
[3] curl to unknown IP      → tcp_connect(): 185.x.x.x:443
[4] /root/.ssh/id_rsa read  → openat(): credential file
```

When this four-step sequence is matched, it is flagged as a high-confidence supply chain attack chain and passed to the Detection Layer.

**Correlation parameters:**
- Time window: configurable (default 60 seconds)
- Process ancestry depth: up to 5 generations
- Pattern library: defined in `detection_engine/patterns/`

---

## Detection Layer

**Location:** Userspace — risk scoring engine.

Each correlated event chain is scored using a weighted formula:

```
Risk Score = Process Risk + File Risk + Network Risk + Context Risk
```

| Component     | Max Score | Factors                                         |
|---------------|-----------|-------------------------------------------------|
| Process Risk  | 30        | Unexpected spawns, shell execution from packages |
| File Risk     | 25        | Credential files, config files, key material    |
| Network Risk  | 25        | Unknown IPs, non-standard ports, beaconing      |
| Context Risk  | 20        | Privilege escalation, UID changes, capabilities  |

**Severity Thresholds:**

| Score  | Severity |
|--------|----------|
| 0–30   | Low      |
| 31–60  | Medium   |
| 61–80  | High     |
| 81–100 | Critical |

Each alert is additionally mapped to a **MITRE ATT&CK technique** (e.g., T1059 — Command and Scripting Interpreter, T1552 — Unsecured Credentials).

---

## Response Layer

**Location:** Userspace — output and notification components.

Scored alerts are handled by three output channels:

| Channel       | Purpose                                                   |
|---------------|-----------------------------------------------------------|
| PostgreSQL    | Persistent storage of all events, chains, and alerts      |
| Dashboard     | Real-time visualization of events, risk scores, and trends |
| Slack Webhook | Immediate human notification for High and Critical alerts |

The dashboard provides:
- Live event stream
- Attack chain visualization
- Risk score timeline
- MITRE ATT&CK heatmap

---

## Data Flow

```
syscall event (kernel)
        ↓
eBPF program captures fields
        ↓
Written to BPF ring buffer
        ↓
Userspace collector reads & normalizes
        ↓
Stored in PostgreSQL (raw events table)
        ↓
Behavioral correlation engine groups by process tree + time window
        ↓
Pattern matching against attack chain library
        ↓
Risk score calculated
        ↓
MITRE ATT&CK technique mapped
        ↓
Alert record stored in PostgreSQL (alerts table)
        ↓
Dashboard updated (polling / websocket)
        ↓
Slack notification sent (if severity >= High)
```
