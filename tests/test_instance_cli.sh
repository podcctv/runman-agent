#!/usr/bin/env bash
set -euo pipefail

bin=$1
work=$(mktemp -d)
pid=
cleanup() {
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
cat >"$work/config.toml" <<EOF
data_dir = "$work/data"
web_listen = ""
auto_update = false
[network]
bridge = "rmtestcli"
ipv4_subnet = "10.87.0.0/20"
nft_table = "runman_cli"
EOF
"$bin" --config "$work/config.toml" run >"$work/agent.log" 2>&1 &
pid=$!
for ((attempt = 0; attempt < 30; attempt++)); do
    if "$bin" instance list --json >"$work/list.json" 2>/dev/null; then break; fi
    sleep 1
done
if ! jq -e 'type == "array" and length == 0' "$work/list.json"; then
    cat "$work/agent.log"
    exit 1
fi
"$bin" instance list | grep -F 'No instances.'
test "$(stat -c '%u:%a' /run/runman-agent-cli/manage.sock)" = 0:600
if runuser -u nobody -- "$bin" instance list --json; then
    echo 'Unprivileged user unexpectedly reached the instance CLI'
    exit 1
fi
python3 - "$bin" <<'PY'
import os
import pty
import select
import subprocess
import sys
import time

master, slave = pty.openpty()
with subprocess.Popen([sys.argv[1], "instance"], stdin=slave, stdout=slave, stderr=slave) as menu:
    os.close(slave)
    output = b""
    deadline = time.monotonic() + 10
    while b"q to quit" not in output and time.monotonic() < deadline:
        if select.select([master], [], [], 1)[0]:
            output += os.read(master, 4096)
    if b"q to quit" not in output:
        menu.kill()
        raise AssertionError(output)
    os.write(master, b"q\n")
    assert menu.wait(timeout=5) == 0
os.close(master)
PY
