#!/usr/bin/env bash
# Attack case: the compromised-package demo. A real `npm install` whose
# postinstall reads an SSH key, stages an implant and calls home. This is the
# one case that must alert — at Critical.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec "$ROOT/demo/supply_chain_demo.sh"
