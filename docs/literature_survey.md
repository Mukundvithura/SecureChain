# Literature Survey

## Overview

This survey reviews existing runtime security solutions and identifies research gaps relevant to software supply chain attack detection.

---

## Falco

### Technology
- eBPF
- Kernel instrumentation
- Rule-based detection

### Strengths
- Mature ecosystem
- Strong community support
- Real-time monitoring

### Limitations
- Generic detection rules
- High rule maintenance effort
- Limited supply chain specialization

---

## Tracee

### Technology
- eBPF-based runtime monitoring

### Strengths
- Deep system visibility
- Detailed event collection

### Limitations
- High event volume
- Requires extensive tuning

---

## Tetragon

### Technology
- eBPF
- Kubernetes-native monitoring

### Strengths
- Container awareness
- Strong Kubernetes integration

### Limitations
- Complex deployment
- Primarily cloud-native focused

---

## Research Gap

Current solutions focus on generic runtime threat detection and security monitoring.

- Few solutions specifically target software supply chain attacks through behavioral correlation of process, file, network, and CI/CD telemetry.
- Most systems generate alerts based on isolated events rather than correlated attack chains.

---

## Proposed Contribution

This project proposes:

1. Custom eBPF-based telemetry collection
2. Behavioral correlation engine
3. Supply chain specific threat taxonomy
4. Runtime attack chain detection
5. Risk scoring framework
6. MITRE ATT&CK mapping

These components aim to improve detection accuracy for software supply chain attacks while maintaining low system overhead.
