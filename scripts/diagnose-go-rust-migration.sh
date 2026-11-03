#!/usr/bin/env bash
# Read-only diagnostics for an incomplete Go -> Rust migration rollback.
set +e

SNAPSHOT_DIR="${1:-}"
TARGET_NAME="${2:-}"
section() { printf '\n=== %s ===\n' "$1"; }

if [ "$(id -u)" != 0 ]; then
    printf 'Run this script as root. No changes have been made.\n' >&2
    exit 1
fi
if [ -z "$SNAPSHOT_DIR" ]; then
    printf 'Usage: %s /var/backups/runman-go-to-rust-v2.* [instance-name]\n' "$0" >&2
    exit 2
fi
SNAPSHOT_DIR=$(readlink -f -- "$SNAPSHOT_DIR" 2>/dev/null || true)
case "$SNAPSHOT_DIR" in
    /var/backups/runman-go-to-rust-v2.*) ;;
    *) printf 'Refusing unexpected snapshot path.\n' >&2; exit 2 ;;
esac
if [ ! -d "$SNAPSHOT_DIR" ] || [ "$(stat -c '%u' "$SNAPSHOT_DIR" 2>/dev/null)" != 0 ]; then
    printf 'Snapshot directory is missing or not root-owned: %s\n' "$SNAPSHOT_DIR" >&2
    exit 2
fi

section 'host'
date -Is 2>/dev/null || date
hostname
. /etc/os-release 2>/dev/null && printf 'os=%s\n' "${PRETTY_NAME:-unknown}"

section 'service state'
for unit in narwhal-agent.service runman-agent.service rfw.service incus.service; do
    active=$(systemctl is-active "$unit" 2>/dev/null || true)
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    printf '%s active=%s enabled=%s\n' "$unit" "${active:-unknown}" "${enabled:-unknown}"
done

section 'Incus version and instances (name, state, init PID, process count)'
incus version 2>&1
incus list --format csv --columns n,s,p,N 2>&1

section 'migration snapshot inventory (file names and metadata only)'
find "$SNAPSHOT_DIR" -maxdepth 1 -type f -printf '%f %s bytes mode=%m\n' | sort

if [ -n "$TARGET_NAME" ]; then
    instance_names=("$TARGET_NAME")
elif [ -f "$SNAPSHOT_DIR/legacy-state.json" ]; then
    mapfile -t instance_names < <(python3 - "$SNAPSHOT_DIR/legacy-state.json" <<'PY'
import json
import pathlib
import re
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read legacy-state.json: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(rows, list):
    print("legacy-state.json is not a list", file=sys.stderr)
    raise SystemExit(1)
for row in rows:
    if not isinstance(row, dict):
        continue
    name = str(row.get("name") or "")
    if row.get("was_running") is True and re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
        print(name)
PY
)
else
    inventory=$(incus list --format csv,noheader --columns n,s,p 2>&1)
    inventory_rc=$?
    if [ "$inventory_rc" -eq 0 ]; then
        mapfile -t instance_names < <(printf '%s\n' "$inventory" | python3 -c '
import csv
import re
import sys

for row in csv.reader(sys.stdin):
    if len(row) != 3:
        continue
    status = row[1].strip().lower()
    if status in {"running", "stopped"}:
        if status == "stopped":
            continue
        try:
            if int(row[2]) > 1:
                continue
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", row[0]):
        print(row[0])
')
        if [ "${#instance_names[@]}" -gt 0 ]; then
            printf 'legacy-state.json is missing; inspecting instances with an error state or invalid/missing init PID.\n'
        else
            printf 'legacy-state.json is missing; Incus reported no error-state instance or invalid/missing init PID.\n'
        fi
    else
        instance_names=()
        printf 'legacy-state.json is missing; cannot inventory Incus instances: %s\n' "$inventory"
    fi
fi

if [ "${#instance_names[@]}" -gt 0 ]; then
    section 'previously running instances'
    for name in "${instance_names[@]}"; do
        if ! [[ "$name" =~ ^[A-Za-z0-9_.+-]{1,200}$ ]]; then
            printf 'Skipping unsupported instance name.\n'
            continue
        fi
        printf '\n--- %s: current state ---\n' "$name"
        info=$(incus info "$name" 2>&1)
        info_rc=$?
        if [ "$info_rc" -eq 0 ]; then
            printf '%s\n' "$info" | awk -F': ' '$1 == "Name" || $1 == "Status" || $1 == "Type" || $1 == "Architecture" || $1 == "Processes" { print }'
        else
            printf '%s\n' "$info" | tail -n 8
        fi
        printf '%s\n' "--- $name: instance log (last 40 lines) ---"
        instance_log=$(incus info --show-log "$name" 2>&1)
        instance_log_rc=$?
        printf '%s\n' "$instance_log" | tail -n 40
        if [ "$instance_log_rc" -ne 0 ]; then
            for logfile in lxc.log forkstart.log forkexec.log; do
                path="/var/log/incus/$name/$logfile"
                if [ -f "$path" ]; then
                    printf '%s\n' "--- $name: $logfile (last 40 lines) ---"
                    tail -n 40 "$path"
                fi
            done
        fi
    done
fi

section 'relevant journal entries (last 90 minutes)'
journalctl -u incus.service -u incus -u narwhal-agent.service \
    --since '-90 min' --no-pager -n 300 2>&1 \
    | grep -Ei 'invalid pid|context deadline exceeded|shut|stop|start|error|fail|timeout|migration|runman|narwhal|incus' \
    | tail -n 100

section 'Incus host processes (command arguments omitted)'
ps -eo pid,ppid,state,etimes,comm \
    | awk 'NR == 1 || $5 ~ /^(incusd|lxc-start|lxc-monitord)$/ { print }'

printf '\nRead-only report complete. This script did not stop/start services, change files, or alter instances.\n'
