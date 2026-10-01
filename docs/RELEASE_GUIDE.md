# SecureChain Release Guide

This document outlines the versioning, packaging, and release procedure for SecureChain.

---

## 1. Versioning Scheme

SecureChain adheres to [Semantic Versioning 2.0.0](https://semver.org/):
- **Format**: `vMAJOR.MINOR.PATCH` (e.g., `v0.1.0`, `v1.0.0`)
- **Pre-releases**: `vMAJOR.MINOR.PATCH-rc.N` or `vMAJOR.MINOR.PATCH-beta.N`

---

## 2. Release Workflow Triggering

Releases are published automatically via [`.github/workflows/release.yml`](file:///.github/workflows/release.yml) upon pushing a valid tag:

```bash
# 1. Ensure you are on main and up to date
git checkout main
git pull origin main

# 2. Create and push a semantic version tag
git tag -a v0.1.0 -m "Release v0.1.0: Initial eBPF runtime sensor suite"
git push origin v0.1.0
```

---

## 3. Release Assets Produced

The automated release pipeline compiles the eBPF programs, links the userspace loader binary, computes SHA256 checksums, and uploads:

- `securechain-sensors-v<VERSION>-linux-x86_64.tar.gz`:
  - `sensors` (compiled binary with embedded eBPF objects)
  - `README_sensors.md`
  - `LICENSE-APACHE`, `LICENSE-MIT`, `LICENSE-GPL2`
  - `demo/` runners (`run_demo.sh`, `supply_chain_demo.sh`, `event_viewer.html`)
- `securechain-sensors-v<VERSION>-linux-x86_64.tar.gz.sha256`: Checksum for distribution integrity verification.
