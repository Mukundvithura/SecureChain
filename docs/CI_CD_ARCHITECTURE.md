# SecureChain CI/CD Architecture

This document describes the continuous integration, continuous delivery, security scanning, packaging, and deployment pipeline for the **SecureChain** project.

---

## 1. System Overview & Workflow Map

The CI/CD pipeline is designed specifically for the dual-nature architecture of SecureChain:
1. **Userspace Rust Crates (`sensors`, `sensors-common`)**: Standard Linux/multiplatform Rust binaries and libraries.
2. **In-Kernel eBPF Sensors (`sensors-ebpf`)**: Rust Aya kernel probes compiled targeting Linux eBPF using `bpf-linker` and Rust nightly `rust-src`.

```mermaid
flowchart TD
    subgraph Trigger["Triggers"]
        PR[Pull Request to main]
        Push[Push to main]
        Tag[Version Tag v*.*.*]
        Manual[workflow_dispatch]
        Cron[Weekly Schedule]
    end

    subgraph CI["Core CI (ci.yml)"]
        Fmt[Nightly Rustfmt Check]
        Clippy[Clippy Linter on Userspace]
        UnitTests[Userspace Unit Tests]
        BuildSensors[Full Build: sensors + eBPF]
        Summary[CI Summary Table]
        
        Fmt --> Summary
        Clippy --> Summary
        UnitTests --> Summary
        BuildSensors --> Summary
    end

    subgraph eBPF["eBPF Dedicated Build (ebpf-build.yml)"]
        CompileEBPF[Compile with bpf-linker & nightly]
        InspectObj[Inspect ELF Object & Symbols]
        ArtifactEBPF[Upload sensors-ebpf-bundle]
        CompileEBPF --> InspectObj --> ArtifactEBPF
    end

    subgraph Security["Security Scanning (security.yml)"]
        Gitleaks[Gitleaks Secret Scan]
        CargoAudit[Cargo Dependency Vulnerability Audit]
    end

    subgraph Integration["Integration & Replay (integration-tests.yml)"]
        Syntax[Bash Syntax Check]
        Replay[JSONL Event Schema & jq Extraction Validation]
    end

    subgraph Delivery["Delivery & Release (release.yml / package.yml)"]
        Package[Assemble Distribution Tarball + SHA256]
        GHRelease[Publish GitHub Release Assets]
    end

    subgraph Deployment["Staging Deployment (deploy-staging.yml)"]
        EnvGate[Protected Environment: staging]
        DryRunCheck{Dry Run / Live}
        DeployHost[Deploy via SSH to Staging Linux VM]
    end

    PR --> CI
    PR --> Security
    PR --> Integration
    Push --> CI
    Push --> eBPF
    Push --> Security
    Tag --> Delivery
    Delivery --> Deployment
    Cron --> Security
```

---

## 2. Workflows Implemented

| Workflow File | Triggers | Key Responsibilities |
| --- | --- | --- |
| [`.github/workflows/ci.yml`](file:///.github/workflows/ci.yml) | `push`, `pull_request` (to `main`), `workflow_dispatch` | Formatting (Nightly `rustfmt`), Clippy, userspace unit tests, release build of sensor binary + eBPF payload, and consolidated status summary. |
| [`.github/workflows/ebpf-build.yml`](file:///.github/workflows/ebpf-build.yml) | `push`/`pull_request` (on eBPF paths), `workflow_dispatch` | Dedicated compilation of eBPF programs, ELF header/symbol inspection, and raw bytecode artifact upload. |
| [`.github/workflows/security.yml`](file:///.github/workflows/security.yml) | `push`, `pull_request`, weekly cron, `workflow_dispatch` | Secret leakage scanning via `Gitleaks` and Rust vulnerability audit via `cargo-audit`. |
| [`.github/workflows/integration-tests.yml`](file:///.github/workflows/integration-tests.yml) | `push`, `pull_request`, `workflow_dispatch` | Validates demo automation shell scripts and verifies JSONL event schemas and jq attack chain extraction pipelines. |
| [`.github/workflows/package.yml`](file:///.github/workflows/package.yml) | `workflow_dispatch`, reusable workflow call | Assembles distribution tarballs (`securechain-sensors-linux-x86_64.tar.gz`) along with documentation, licenses, and SHA256 checksums. |
| [`.github/workflows/release.yml`](file:///.github/workflows/release.yml) | `push` of tags `v*.*.*` | Validates semver tags, compiles release artifacts, packages distribution tarballs with SHA256 sums, and publishes a GitHub Release. |
| [`.github/workflows/deploy-staging.yml`](file:///.github/workflows/deploy-staging.yml) | `workflow_dispatch` | Controlled staging deployment targeting Linux VMs using GitHub Environment protection rules with dry-run safety gates. |

---

## 3. Security Boundary & Permissions

- **Minimal Permissions**: All workflows enforce `permissions: contents: read` globally, except `release.yml` which explicitly requires `permissions: contents: write` to publish release releases.
- **Pull Request Isolation**: Deployment secrets and elevated environments are restricted to protected branches and environments (`staging`). Untrusted pull requests cannot access credentials.
- **Concurrency Controls**: Active pull request runs automatically cancel preceding runs to save CI runner minutes (`concurrency.cancel-in-progress: true`).
