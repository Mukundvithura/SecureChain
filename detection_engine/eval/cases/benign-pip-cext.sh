#!/usr/bin/env bash
# Benign case: pip installing a package with a C extension. pip (the anchor)
# runs setuptools, which runs gcc to compile the extension — a build chain
# with a compiler writing a .o and an .so, and no network once the source is
# local. The engine must not alert.
#
# Needs the Python development headers (Python.h). Skips if they are missing.
set -uo pipefail

command -v gcc >/dev/null 2>&1 || { echo "gcc not installed" >&2; exit 1; }
PYINC="$(python3 -c 'import sysconfig; print(sysconfig.get_path("include"))' 2>/dev/null || true)"
if [[ -z "$PYINC" || ! -f "$PYINC/Python.h" ]]; then
    echo "[*] benign-pip-cext: Python.h not found (install python3-dev), skipping" >&2
    exit 0
fi

DIR=/tmp/secrisk-eval-pip-cext
rm -rf "$DIR"
mkdir -p "$DIR/pkg/src"

cat > "$DIR/pkg/src/fastmod.c" <<'C'
#define PY_SSIZE_T_CLEAN
#include <Python.h>
static PyObject *add(PyObject *self, PyObject *args) {
    long a, b;
    if (!PyArg_ParseTuple(args, "ll", &a, &b)) return NULL;
    return PyLong_FromLong(a + b);
}
static PyMethodDef M[] = {{"add", add, METH_VARARGS, ""}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef mod = {PyModuleDef_HEAD_INIT, "fastmod", NULL, -1, M};
PyMODINIT_FUNC PyInit_fastmod(void) { return PyModule_Create(&mod); }
C

cat > "$DIR/pkg/setup.py" <<'PY'
from setuptools import setup, Extension
setup(
    name="fastmod",
    version="1.0.0",
    ext_modules=[Extension("fastmod", ["src/fastmod.c"])],
)
PY

echo "[*] benign-pip-cext: pip building a C extension"
# --system-site-packages lets the venv see the system setuptools/wheel, so the
# build needs no network.
python3 -m venv --system-site-packages "$DIR/venv"
# --no-build-isolation keeps the build offline: it uses the visible setuptools
# instead of fetching a fresh build environment from PyPI.
"$DIR/venv/bin/pip" install --no-input --no-index --no-build-isolation "$DIR/pkg" \
    || echo "[*] benign-pip-cext: build failed (missing build deps?)" >&2
rm -rf "$DIR"
