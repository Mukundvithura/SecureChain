#!/usr/bin/env bash
# Benign case: a browser fetching a page. Firefox spawns content processes and
# connects out, but it is its own anchor (not under a package manager), so no
# dependency rule applies. The engine should score this 0.
#
# Headless so it needs no display and exits on its own. If firefox is absent
# the case is skipped — it contributes nothing but a browser's own traffic.
set -uo pipefail

if ! command -v firefox >/dev/null 2>&1; then
    echo "[*] benign-firefox: firefox not installed, skipping" >&2
    exit 0
fi

PROFILE="$(mktemp -d)"
trap 'rm -rf "$PROFILE"' EXIT

timeout 20 firefox --headless --profile "$PROFILE" \
    --screenshot /dev/null "https://example.com/" >/dev/null 2>&1 || true

echo "[*] benign-firefox: fetched a page headless"
