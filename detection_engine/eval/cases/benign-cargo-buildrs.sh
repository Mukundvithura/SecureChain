#!/usr/bin/env bash
# Benign case: cargo building a crate with a build.rs. The build script runs as
# its own process under the cargo anchor and writes generated code into
# OUT_DIR — a program the package author controls, running at build time, which
# is the same shape as a build-time supply-chain payload. It must not alert:
# cargo and rustc are exempt, the writes go to the crate's target dir, and
# there is no network. The engine should score this 0.
set -uo pipefail

command -v cargo >/dev/null 2>&1 || { echo "cargo not installed" >&2; exit 1; }

DIR=/tmp/secrisk-eval-cargo-buildrs
rm -rf "$DIR"
mkdir -p "$DIR/src"

cat > "$DIR/Cargo.toml" <<'TOML'
[package]
name = "buildrs-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
TOML

cat > "$DIR/build.rs" <<'RS'
use std::{env, fs, path::Path};
fn main() {
    // A real build.rs generates code; this writes a constant into OUT_DIR.
    let out = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out).join("generated.rs"), "pub const N: u32 = 42;\n").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
RS

cat > "$DIR/src/main.rs" <<'RS'
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
fn main() { println!("{N}"); }
RS

echo "[*] benign-cargo-buildrs: cargo build running a build.rs"
( cd "$DIR" && cargo build --offline --quiet 2>/dev/null \
    || cargo build --quiet )
rm -rf "$DIR"
