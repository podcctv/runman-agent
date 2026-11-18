#!/usr/bin/env bash
set -euo pipefail

bin=$1
work=$(mktemp -d)
pid=
instance=
cleanup() {
    if [ -n "$instance" ]; then "$bin" instance stop "$instance" >/dev/null 2>&1 || true; fi
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
cat >"$work/config.toml" <<EOF
data_dir = "$work/data"
web_listen = ""
auto_update = false
image_base_url = "https://github.com/narwhal-cloud/runman-agent-rs/releases/download/images"
[network]
bridge = "rmtestcli"
ipv4_subnet = "10.87.0.0/20"
nft_table = "runman_cli"
EOF
mkdir -m 700 "$work/data"
printf '%s\n' '{"down_mbps":100,"up_mbps":100,"at":1}' >"$work/data/speedtest.json"
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
if runuser -u nobody -- curl -q --noproxy '*' --fail --silent \
    --unix-socket /run/runman-agent-cli/manage.sock http://localhost/v1/instances; then
    echo 'Unprivileged user unexpectedly reached the instance CLI'
    exit 1
fi
for ((attempt = 0; attempt < 90; attempt++)); do
    if [ -e "$work/data/images/alpine/current" ]; then break; fi
    sleep 1
done
if [ ! -e "$work/data/images/alpine/current" ]; then
    cat "$work/agent.log"
    exit 1
fi
"$bin" instance create --image alpine --disk-gib 3 >"$work/created.json"
instance=$(jq -er '.id' "$work/created.json")
"$bin" instance list --json | jq -e --arg id "$instance" \
    'any(.[]; .id == $id and .status == "running")'
"$bin" instance inspect "$instance" --json | jq -e '.os_image == "alpine" and .disk_gb == 3'
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
    def expect(marker):
        output = b""
        deadline = time.monotonic() + 10
        while marker not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                output += os.read(master, 4096)
        if marker not in output:
            menu.kill()
            raise AssertionError(output)
        return output

    expect(b"q to quit")
    os.write(master, b"1\n")
    expect(b"1 Info")
    os.write(master, b"1\n")
    assert b"Disk 3 GiB" in expect(b"Press Enter")
    os.write(master, b"\n")
    expect(b"q to quit")
    os.write(master, b"q\n")
    assert menu.wait(timeout=5) == 0
os.close(master)
PY
"$bin" instance stop "$instance"
"$bin" instance inspect "$instance" --json | jq -e '.status == "stopped"'
