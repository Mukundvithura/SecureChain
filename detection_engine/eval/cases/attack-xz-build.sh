#!/usr/bin/env bash
# Attack case: XZ-style build tampering. make runs an injected build script
# that decompresses a "test file" from tests/files/ and writes an object file
# into the liblzma tree with a shell, not a compiler — a shell under the
# anchor (P1), a decompressor on test data (L5), a non-compiler .o write (L6).
#
# Safe: synthetic input, local build, nothing downloaded, no system file
# touched. Everything stays under /tmp/secrisk-xzsim and is removed on exit.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec "$ROOT/sim/xz-lzma/run_sim.sh"
