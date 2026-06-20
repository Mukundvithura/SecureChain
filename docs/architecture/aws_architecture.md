# AWS Architecture Design

## Overview

The SecRisk prototype is deployed on AWS to provide a realistic environment for testing and demonstration. The architecture is intentionally simple for the prototype phase — a single EC2 instance hosts all components — with a clear path to a distributed Kubernetes-based deployment in the future.

```
┌──────────────────────────────────────────────────────────────┐
│                        AWS Cloud                             │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  EC2 Instance (t3.medium)               │ │
│  │                                                         │ │
│  │   ┌─────────────────────────────────────────────────┐  │ │
│  │   │            SecRisk Runtime                      │  │ │
│  │   │  eBPF Sensors → Collector → Detection Engine   │  │ │
│  │   └──────────────────────┬──────────────────────────┘  │ │
│  │                          ↓                              │ │
│  │   ┌──────────────────────────────────────────────────┐ │ │
│  │   │          PostgreSQL (RDS / local)                │ │ │
│  │   │   events table │ alerts table │ chains table     │ │ │
│  │   └──────────────────────┬───────────────────────────┘ │ │
│  │                          ↓                             │ │
│  │   ┌───────────────────────────────────────────────┐   │ │
│  │   │              Dashboard                        │   │ │
│  │   │   Grafana / Web UI  (port 3000)               │   │ │
│  │   └───────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                          ↓                                   │
│              Slack Webhook (external)                        │
└──────────────────────────────────────────────────────────────┘
```

---

## Components

### EC2 Instance

| Property      | Value                                      |
|---------------|--------------------------------------------|
| Instance Type | t3.medium (2 vCPU, 4 GB RAM)               |
| OS            | Ubuntu 22.04 LTS                           |
| Kernel        | 5.15+ (required for eBPF CO-RE support)    |
| Storage       | 30 GB gp3 EBS                              |

The EC2 instance runs all SecRisk components:
- eBPF sensor programs (kernel space)
- Userspace collector (Go binary)
- Detection and correlation engine (Go binary)
- Dashboard server

Security groups restrict inbound access to:
- SSH (port 22) — authorized IP only
- Dashboard (port 3000) — authorized IP only

### PostgreSQL

Used as the central event and alert store.

| Table         | Contents                                          |
|---------------|---------------------------------------------------|
| `events`      | All normalized raw events (process, file, network) |
| `chains`      | Correlated behavioral attack chains               |
| `alerts`      | Scored and mapped alerts with MITRE ATT&CK tags   |

For the prototype, PostgreSQL runs locally on the EC2 instance. For production, this would migrate to **AWS RDS (PostgreSQL)** for managed backups, scaling, and high availability.

**Schema overview:**
```sql
events  (id, type, pid, ppid, uid, name, detail, timestamp)
chains  (id, events[], pattern_matched, start_time, end_time)
alerts  (id, chain_id, risk_score, severity, mitre_technique, notified_at)
```

### Dashboard

A real-time web dashboard for visualizing system activity and alerts.

- Built with Grafana (prototype) or a custom Go/React UI (future)
- Connects directly to PostgreSQL
- Displays:
  - Live event stream
  - Active attack chains
  - Risk score distribution
  - MITRE ATT&CK technique heatmap
  - Alert history and acknowledgment

Accessible on port 3000 of the EC2 instance.

### Slack Integration

High and Critical severity alerts trigger an immediate Slack notification via **Incoming Webhook**.

**Notification payload:**
```
[SecRisk Alert] 🔴 CRITICAL
Chain: npm → bash → curl → SSH key access
Risk Score: 91/100
MITRE: T1059.004, T1552.004
Host: ip-10-0-1-42
Time: 2026-06-21 14:32:07 UTC
```

Configuration: Slack Webhook URL stored as an environment variable on EC2 (`SECRISK_SLACK_WEBHOOK`).

---

## Deployment Flow

```
1. Provision EC2 instance (Ubuntu 22.04, kernel 5.15+)
        ↓
2. Install dependencies
   - Go toolchain
   - libbpf, clang, llvm (for eBPF compilation)
   - PostgreSQL
   - Grafana (optional)
        ↓
3. Clone SecRisk repository
        ↓
4. Compile eBPF programs
   make -C ebpf/
        ↓
5. Initialize PostgreSQL schema
   psql -f scripts/schema.sql
        ↓
6. Configure environment variables
   SECRISK_DB_URL, SECRISK_SLACK_WEBHOOK
        ↓
7. Run SecRisk collector + detection engine
   sudo ./secrisk
        ↓
8. Launch dashboard
   ./dashboard serve --port 3000
        ↓
9. Verify Slack webhook with test alert
```

---

## Future: Kubernetes Deployment

For production scale, the architecture migrates to Kubernetes with the following topology:

| Component            | Kubernetes Resource         |
|----------------------|-----------------------------|
| eBPF Collector       | DaemonSet (runs on every node) |
| Detection Engine     | Deployment (replicated)     |
| Dashboard            | Deployment + Service + Ingress |
| PostgreSQL           | AWS RDS (external managed)  |
| Secrets              | Kubernetes Secrets / AWS Secrets Manager |

The DaemonSet model ensures eBPF sensors run on every node in the cluster, providing full coverage across multi-node environments. The detection engine scales horizontally as event volume grows.
