# Threat Taxonomy

## Purpose

This taxonomy defines runtime-detectable behaviors associated with software supply chain attacks and provides the foundation for behavioral detection rules used throughout the project.

---

## Category 1: Malicious Process Execution

### Description
Unexpected execution of processes initiated by software packages, dependencies, build scripts, or deployment artifacts.

### Examples
- npm package spawning a shell
- Python package executing system commands
- Build scripts launching unauthorized binaries

### Runtime Indicators
- `execve()`
- `fork()`
- `clone()`

### Severity
**High**

---

## Category 2: Unauthorized File Access

### Description
Processes accessing sensitive system files or modifying protected resources.

### Examples
- Access to SSH keys
- Access to Kubernetes secrets
- Access to system configuration files

### Runtime Indicators
- `openat()`
- `read()`
- `write()`

### Severity
**Medium**

---

## Category 3: Network Beaconing

### Description
Unexpected outbound communication initiated by software components.

### Examples
- Connections to unknown domains
- Communication with attacker infrastructure
- Data exfiltration attempts

### Runtime Indicators
- `connect()`
- `sendto()`
- `recvfrom()`

### Severity
**High**

---

## Category 4: Credential Access

### Description
Attempts to access or harvest credentials, secrets, or authentication tokens.

### Examples
- AWS credential access
- SSH key collection
- Service account token access

### Runtime Indicators
- Access to credential stores
- Secret file reads

### Severity
**Critical**

---

## Category 5: Privilege Escalation

### Description
Attempts to gain elevated privileges or bypass security controls.

### Examples
- setuid execution
- Capability manipulation
- Unauthorized privilege changes

### Runtime Indicators
- `setuid()`
- Capability modifications

### Severity
**Critical**

---

## Detection Priority

| Category                    | Priority |
|-----------------------------|----------|
| Credential Access           | Critical |
| Privilege Escalation        | Critical |
| Network Beaconing           | High     |
| Malicious Process Execution | High     |
| Unauthorized File Access    | Medium   |
