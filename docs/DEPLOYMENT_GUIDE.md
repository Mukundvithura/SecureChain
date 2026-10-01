# SecureChain Staging Deployment & Rollback Guide

This document defines the deployment procedure, staging validation checks, and rollback strategies for the SecureChain eBPF sensor infrastructure.

---

## 1. Staging Architecture

SecureChain sensors run at kernel privilege (`root` / `CAP_BPF` / `CAP_SYS_ADMIN`). Consequently, deployments to staging instances must adhere to strict validation and containment protocols.

---

## 2. Triggering Staging Deployments

Deployments are executed manually via GitHub Actions workflow dispatch:

1. Navigate to **Actions > Deploy to Staging**.
2. Click **Run workflow**.
3. Select parameters:
   - `release_tag`: `v0.1.0` (or `latest`).
   - `dry_run`: `true` (default for validation) or `false` for live execution.

---

## 3. Post-Deployment Health Checks

Once deployed on the staging Linux host, verify sensor health:

```bash
# 1. Verify probes attached and running
sudo pgrep -x sensors

# 2. Check JSONL event capture output
head -n 5 captures/sensors-*.jsonl

# 3. Check for tracepoint attachment errors
sudo journalctl -u securechain-sensors -n 50
```

---

## 4. Rollback Procedure

If a deployed sensor binary causes kernel regressions, high CPU usage, or sensor panics:

1. **Stop Sensor Service Immediately**:
   ```bash
   sudo systemctl stop securechain-sensors
   ```
2. **Detach eBPF Programs**:
   ```bash
   sudo pkill -TERM -x sensors
   ```
3. **Restore Previous Binary**:
   ```bash
   cp /opt/securechain/bin/sensors.prev /opt/securechain/bin/sensors
   sudo systemctl start securechain-sensors
   ```
