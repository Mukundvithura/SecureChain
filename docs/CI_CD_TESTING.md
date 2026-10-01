# SecureChain CI/CD Testing & Local Validation Guide

This guide details how to locally test and validate each component of the SecureChain CI pipeline.

---

## 1. Local Prerequisites

- **Stable Rust**: `rustup toolchain install stable`
- **Nightly Rust**: `rustup toolchain install nightly --component rust-src`
- **Nightly rustfmt**: `rustup component add rustfmt --toolchain nightly`
- **bpf-linker**: `cargo install bpf-linker`
- **Linux Packages** (Ubuntu/Debian):
  ```bash
  sudo apt-get update && sudo apt-get install -y clang llvm libelf-dev jq
  ```

---

## 2. Command Reference by Workflow Stage

### 1. Code Formatting Check
Uses the repository's `sensors/rustfmt.toml` (requires nightly rustfmt for unstable options such as `group_imports` and `imports_granularity`):
```bash
cargo +nightly fmt --manifest-path sensors/Cargo.toml --all -- --check
```

### 2. Linting (Clippy)
Lints userspace and shared crates:
```bash
cargo clippy --manifest-path sensors/Cargo.toml --package sensors-common --package sensors -- -D warnings
```

### 3. Userspace Unit Tests
Runs unit tests in `sensors/src/normalize.rs` without requiring `sudo`:
```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env cargo test --manifest-path sensors/Cargo.toml --package sensors
```

### 4. Release Build (Sensor Binary + eBPF Bytecode)
Executes the full Aya compilation pipeline (requires Linux with `bpf-linker`):
```bash
cargo build --manifest-path sensors/Cargo.toml --package sensors --release
```

### 5. Dependency Audit
Scans `sensors/Cargo.lock` for advisory advisories:
```bash
cargo audit --file sensors/Cargo.lock
```

### 6. Demo Script Syntax & Replay Validation
```bash
bash -n demo/run_demo.sh
bash -n demo/supply_chain_demo.sh
```
