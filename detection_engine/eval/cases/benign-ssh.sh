#!/usr/bin/env bash
# Benign case: an SSH session. ssh reads the user's private key and connects
# out on port 22 — exactly the "secret read then network" shape an attacker
# uses, but ssh is the key's normal reader and is not a package manager, so
# F1 and N2 must not fire. The engine should score this 0.
#
# Connects to localhost's sshd if it accepts the user's key, else just makes
# ssh read the key and attempt a connection; either way the sensor sees the
# key read and the outbound connect, which is what the rules judge.
set -uo pipefail

ssh -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=5 \
    localhost true 2>/dev/null || true

echo "[*] benign-ssh: ssh read its key and connected to :22"
