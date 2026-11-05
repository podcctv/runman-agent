#!/usr/bin/env bash
# Runman agent installer / upgrader / uninstaller.
#
#   bash install.sh [--token TOKEN] [options]      install, or upgrade in place
#   bash install.sh --uninstall [--purge]          remove (--purge also deletes instances)
#
# Re-running it is safe: an existing configuration is kept and only the
# binaries and service units are refreshed. It never prompts.
set -euo pipefail

RELEASE_URL="${RUNMAN_RELEASE_URL:-https://github.com/podcctv/runman-agent/releases/download/continuous-rs}"
RFW_URL="${RUNMAN_RFW_URL:-https://github.com/podcctv/runman-agent/releases/download/continuous}"
PLATFORM_URL="https://hosting.fuckip.me:443"
CONFIG_DIR=/etc/runman-agent
CONFIG="$CONFIG_DIR/config.toml"
DATA_DIR=/var/lib/runman-agent
BIN=/usr/local/bin/runman-agent
RFW_BIN=/usr/local/bin/rfw
RFW_DIR=/var/lib/rfw
RFW_API=127.0.0.1:7734
MIN_KERNEL=5.19

TOKEN=""
WEB_LISTEN="0.0.0.0:8792"
IPV6="auto"
IPV6_PREFIX=""
IPV6_UPLINK=""
BANDWIDTH=0
WITH_RFW=1
RFW_IFACE=""
FROM_DIR=""
UNINSTALL=0
PURGE=0
MIGRATE_GO=0
RFW_REPAIR_ONLY=0
CLEANUP_ONLY=0
CLEANUP_RUNTIMES=0
MIGRATION_CLEANUP_RUNTIMES=0
MIGRATION_DIR=""
MIGRATION_HELPER=""
MIGRATION_BACKEND=""
MIGRATION_ACTIVE=0
MIGRATION_COMMITTED=0
MIGRATION_GO_WAS_ACTIVE=0
MIGRATION_GO_WAS_ENABLED=0
MIGRATION_LXCFS_WAS_ACTIVE=0
MIGRATION_LXCFS_WAS_ENABLED=0
MIGRATION_MODULES_CONFIG_TOUCHED=0
MIGRATION_SYSCTL_CONFIG_TOUCHED=0
MIGRATION_LXCFS_CONFIG_TOUCHED=0
MIGRATION_LXCFS_STATE_TOUCHED=0
MIGRATION_GO_STOP_ATTEMPTED=0
HOST_PACKAGES_INSTALLED=0
MIGRATION_GUESTS_PREDELETE_CONFIRMED=0
MIGRATION_GUESTS_PREDELETE_ATTEMPTED=0
MIGRATION_RFW_REPAIR_REQUIRED=0
MIGRATION_RFW_REPAIR_ATTEMPTED=0
MIGRATION_RFW_REPAIRED=0
MIGRATION_RFW_UNIT_TOUCHED=0
MIGRATION_RFW_BIN=""
MIGRATION_RFW_UNIT_PATH=""
MIGRATION_RFW_API_ADDR=""
MIGRATION_RFW_API_URL=""
MIGRATION_RFW_SERVICE_CURSOR=""
MIGRATION_RFW_KERNEL_CURSOR=""
MIGRATION_RFW_CANDIDATE=""
MIGRATION_RFW_ORIGINAL_SHA256=""
MIGRATION_RFW_CANDIDATE_SHA256=""
MIGRATION_RFW_VERSION=""
MIGRATION_MIN_FREE_BYTES=$((768 * 1024 * 1024))
WORK=""

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

apt_get() {
    # Translation indexes are optional and some Debian mirrors do not publish them.
    LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get \
        -o DPkg::Lock::Timeout=600 \
        -o Dpkg::Use-Pty=0 \
        -o Acquire::Languages=none \
        -y "$@"
}

cleanup_partial_apt_indexes() {
    local partial=/var/lib/apt/lists/partial bytes=0 available
    if [ -d "$partial" ]; then
        bytes=$(du -sb "$partial" 2>/dev/null | awk '{print $1}')
        bytes=${bytes:-0}
        find "$partial" -mindepth 1 -type f -delete
        find "$partial" -depth -mindepth 1 -type d -empty -delete
    fi
    cleanup_apt_caches
    available=$(LC_ALL=C df -PB1 /var/lib/apt | awk 'NR == 2 {print $4}')
    if [ "${bytes:-0}" -gt 0 ]; then
        log "discarded ${bytes} bytes of incomplete APT index downloads; ${available:-unknown} bytes are now available"
    fi
}

cleanup_apt_caches() {
    local before after
    before=$(du -sb /var/cache/apt 2>/dev/null | awk 'NR == 1 {print $1}')
    before=${before:-0}
    apt_get clean
    # apt-get update regenerates these indexes; they are disposable and can be
    # rebuilt on the next package operation. Remove them after package setup so
    # low-space migration does not carry the indexes into Rust image staging.
    rm -f -- /var/cache/apt/pkgcache.bin /var/cache/apt/srcpkgcache.bin
    after=$(du -sb /var/cache/apt 2>/dev/null | awk 'NR == 1 {print $1}')
    after=${after:-0}
    if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]] && [ "$before" -gt "$after" ]; then
        log "cleared regenerable APT caches and recovered $((before - after)) bytes"
    fi
}

cleanup_apt_list_indexes_for_low_space() {
    local lists=/var/lib/apt/lists before after
    [ "$MIGRATION_GUESTS_PREDELETE_CONFIRMED" = 1 ] || return 0
    [ -d "$lists" ] || return 0
    if pgrep -x apt >/dev/null 2>&1 \
        || pgrep -x apt-get >/dev/null 2>&1 \
        || pgrep -x apt-cache >/dev/null 2>&1 \
        || pgrep -x dpkg >/dev/null 2>&1 \
        || systemctl is-active --quiet apt-daily.service \
        || systemctl is-active --quiet apt-daily-upgrade.service; then
        warn "APT started another operation; keeping package-list indexes"
        return 0
    fi
    before=$(du -sb "$lists" 2>/dev/null | awk 'NR == 1 {print $1}')
    before=${before:-0}
    find "$lists" -mindepth 1 -maxdepth 1 ! -name lock ! -name partial -exec rm -rf -- {} +
    if [ -d "$lists/partial" ]; then
        find "$lists/partial" -mindepth 1 ! -name lock -delete
    fi
    after=$(du -sb "$lists" 2>/dev/null | awk 'NR == 1 {print $1}')
    after=${after:-0}
    if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]] && [ "$before" -gt "$after" ]; then
        log "cleared regenerable APT package indexes for low-space staging; recovered $((before - after)) bytes"
    fi
}

install_host_packages() {
    cleanup_partial_apt_indexes
    log "updating APT package indexes before changing container state; package-manager lock wait is capped at 10 minutes"
    apt_get update
    if [ "$MIGRATION_ACTIVE" = 1 ]; then MIGRATION_LXCFS_STATE_TOUCHED=1; fi
    log "installing required host packages"
    apt_get install --no-install-recommends --no-upgrade \
        ca-certificates curl iproute2 iptables nftables wireguard-tools e2fsprogs tar gzip zstd util-linux kmod lxcfs
    HOST_PACKAGES_INSTALLED=1
    cleanup_apt_caches
    cleanup_apt_list_indexes_for_low_space
}

migration_available_bytes() {
    local available
    available=$(LC_ALL=C df -PB1 /var/lib | awk 'NR == 2 {print $4}')
    [[ "$available" =~ ^[0-9]+$ ]] || die "could not determine available space on the Runman data filesystem"
    printf '%s\n' "$available"
}

migration_instance_count() {
    python3 - "$1" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read saved Incus ERROR state: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
    print("saved legacy state is not a list of objects", file=sys.stderr)
    raise SystemExit(1)
if any(not str(row.get("name") or "").strip() for row in rows):
    print("saved legacy state contains an instance without a name", file=sys.stderr)
    raise SystemExit(1)
print(len(rows))
PY
}

migration_confirm_low_space_cleanup() {
    local available instance_count answer
    [ "$MIGRATION_BACKEND" = incus ] || return 0
    available=$(migration_available_bytes)
    [ "$available" -lt "$MIGRATION_MIN_FREE_BYTES" ] || return 0
    instance_count=$(migration_instance_count "$MIGRATION_DIR/legacy-state.json") \
        || die "could not count Go-managed Incus guests for low-space recovery"
    [ "$instance_count" -gt 0 ] \
        || die "only ${available} bytes are free; no Go-managed Incus guests can be removed to recover space"

    printf '\nLow disk space: %s bytes are available; this migration needs at least %s bytes for Rust image staging.\n' \
        "$available" "$MIGRATION_MIN_FREE_BYTES"
    printf 'The root-only snapshot at %s preserves parameters, port forwards, and the Go database, but not old guest files.\n' \
        "$MIGRATION_DIR"
    printf 'To proceed, all %s Go-managed Incus guest(s) in this snapshot will be deleted before Rust health checks; rollback can restore Go service/configuration but not those guest files.\n' \
        "$instance_count"
    read -r -p 'Type DELETE INCUS GUESTS to continue: ' answer </dev/tty \
        || die "could not read the low-space deletion confirmation; Go remains active"
    [ "$answer" = "DELETE INCUS GUESTS" ] \
        || die "low-space guest deletion cancelled; Go and the legacy guests remain untouched"
    MIGRATION_GUESTS_PREDELETE_CONFIRMED=1
}

migration_capture_file() {
    local source="$1" saved="$MIGRATION_DIR/host-files$1"
    mkdir -p "$(dirname "$saved")"
    if [ -e "$source" ]; then
        cp -a "$source" "$saved"
        printf '1\n' > "$saved.present"
    else
        printf '0\n' > "$saved.present"
    fi
}

migration_backup_go_agent() {
    local source="$1" destination="$MIGRATION_DIR/go-agent" candidate source_size
    source_size=$(stat -c '%s' -- "$source") || { cp -a "$source" "$destination"; return; }
    for candidate in /var/backups/runman-go-to-rust-v2.*/go-agent; do
        [ -f "$candidate" ] || continue
        [ "$(stat -c '%s' -- "$candidate" 2>/dev/null || true)" = "$source_size" ] || continue
        if cmp -s -- "$source" "$candidate" && ln -- "$candidate" "$destination" 2>/dev/null; then
            log "reused an identical verified Go Agent backup binary to avoid duplicate disk use"
            return 0
        fi
    done
    cp -a "$source" "$destination"
}

migration_restore_file() {
    local target="$1" saved="$MIGRATION_DIR/host-files$1" present=0
    [ -f "$saved.present" ] && read -r present < "$saved.present"
    if [ "$present" = 1 ] && [ -e "$saved" ]; then
        rm -rf -- "$target"
        mkdir -p "$(dirname "$target")"
        cp -a "$saved" "$target"
    elif [ "$present" = 0 ]; then
        rm -rf -- "$target"
    fi
}

migration_choose_error_states() {
    local rows_file name fallback_status fallback_pid last_power answer selected found=0
    [ "$MIGRATION_BACKEND" = incus ] || return 0

    rows_file="$MIGRATION_DIR/incus-error-instances.tsv"
    if ! python3 - "$MIGRATION_DIR/legacy-state.json" > "$rows_file" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read Incus ERROR instances: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
    print("legacy state is not a list of objects", file=sys.stderr)
    raise SystemExit(1)
for row in rows:
    if (
        row.get("rebuild_fallback") is True or row.get("was_error_state") is True
    ) and row.get("run_state_confirmed") is not True:
        name = str(row.get("name") or "")
        status = str(row.get("fallback_status") or "ERROR")
        pid = str(row.get("fallback_init_pid") or "missing")
        power = str(row.get("last_state_power") or "unset")
        print(f"{name}\t{status}\t{pid}\t{power}")
PY
    then
        die "could not read Incus ERROR instance state choices"
    fi

    while IFS=$'\t' read -r name fallback_status fallback_pid last_power; do
        [ -n "$name" ] || continue
        found=1
        [ -n "$last_power" ] || last_power='unset'
        printf '\nIncus reports %s as %s with init PID %s; its guest filesystem will be rebuilt.\n' \
            "$name" "${fallback_status^^}" "$fallback_pid"
        printf 'Incus volatile.last_state.power is %s and may be stale.\n' "${last_power^^}"
        while true; do
            read -r -p "Should the replacement guest start after migration? Enter RUNNING or STOPPED: " answer </dev/tty \
                || die "could not read the replacement run state for $name; an interactive terminal is required"
            case "${answer^^}" in
                RUNNING|R) selected=running; break ;;
                STOPPED|S) selected=stopped; break ;;
                *) warn "enter RUNNING or STOPPED" ;;
            esac
        done
        python3 - "$MIGRATION_DIR/error-state-overrides.json" "$name" "$selected" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    choices = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read prior run-state choices: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(choices, dict):
    print("run-state choices are not an object", file=sys.stderr)
    raise SystemExit(1)
choices[sys.argv[2]] = sys.argv[3] == "running"
tmp = path.with_name(path.name + ".tmp")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(choices, stream, separators=(",", ":"))
    stream.write("\n")
os.replace(tmp, path)
os.chmod(path, 0o600)
PY
        printf 'Replacement for %s will be %s after migration.\n' "$name" "${selected^^}"
    done < "$rows_file"
    rm -f -- "$rows_file"

    if [ "$found" = 1 ]; then
        "$MIGRATION_HELPER" export --config "$1" --output "$MIGRATION_DIR" \
            --error-state-overrides "$MIGRATION_DIR/error-state-overrides.json" \
            --orphan-core-exclusions "$MIGRATION_DIR/orphan-core-exclusions.json" \
            || die "could not save the selected Incus replacement states"
        if ! python3 - "$MIGRATION_DIR/legacy-state.json" \
            "$MIGRATION_DIR/error-state-overrides.json" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
choices = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
    print("invalid legacy state", file=sys.stderr)
    raise SystemExit(2)
if not isinstance(choices, dict):
    print("invalid replacement run-state choices", file=sys.stderr)
    raise SystemExit(2)
fallbacks = {
    str(row.get("name") or "")
    for row in rows
    if row.get("rebuild_fallback") is True
}
pending = [
    str(row.get("name") or "")
    for row in rows
    if row.get("rebuild_fallback") is True
    and row.get("run_state_confirmed") is not True
]
if pending:
    print("new unusable Incus state needs a run-state choice: " + ", ".join(pending), file=sys.stderr)
    raise SystemExit(1)
stale_choices = sorted(set(choices) - fallbacks)
if stale_choices:
    print("Incus state changed while choosing replacement states: " + ", ".join(stale_choices), file=sys.stderr)
    raise SystemExit(1)
PY
        then
            die "Incus state changed while selecting replacement states; retry migration to review it"
        fi
    fi
}

migration_confirm_orphan_core_rows() {
    local candidates="$MIGRATION_DIR/orphan-core-candidates.json"
    local exclusions="$MIGRATION_DIR/orphan-core-exclusions.json"
    local answer
    [ -s "$candidates" ] || die "migration helper requested orphan-row confirmation without a candidate report"
    printf '\nGo has core VM record(s) with no matching backend record, live container, or port forwards.\n'
    printf 'They will be excluded from the Rust manifest; the original records remain in the root-only Go database snapshot.\n'
    if ! python3 - "$candidates" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read orphan core-row candidates: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
    print("orphan core-row candidate report is empty or invalid", file=sys.stderr)
    raise SystemExit(1)
for row in rows:
    print(
        "  {vm_id} status={status} image={image} cpu={cpu} memory_mb={memory_mb} "
        "disk_gb={disk_gb} bandwidth_mbps={bandwidth_mbps}".format(
            vm_id=row.get("vm_id", "?"),
            status=row.get("status", "?"),
            image=row.get("image", "?"),
            cpu=row.get("cpu", "?"),
            memory_mb=row.get("memory_mb", "?"),
            disk_gb=row.get("disk_gb", "?"),
            bandwidth_mbps=row.get("bandwidth_mbps", "?"),
        )
    )
PY
    then
        die "could not review orphan core-row candidates"
    fi
    read -r -p 'Type EXCLUDE ORPHAN GO RECORDS to confirm: ' answer </dev/tty \
        || die "could not read orphan-row confirmation; an interactive terminal is required"
    [ "$answer" = "EXCLUDE ORPHAN GO RECORDS" ] \
        || die "orphan-row exclusion cancelled; Go remains active"
    if ! python3 - "$candidates" "$exclusions" <<'PY'
import json
import os
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"cannot read orphan core-row candidates: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
    print("orphan core-row candidate report is empty or invalid", file=sys.stderr)
    raise SystemExit(1)
ids = [row.get("vm_id") for row in rows]
if any(not isinstance(value, str) for value in ids) or len(ids) != len(set(ids)):
    print("orphan core-row candidates contain missing or duplicate UUIDs", file=sys.stderr)
    raise SystemExit(1)
path = pathlib.Path(sys.argv[2])
tmp = path.with_name(path.name + ".tmp")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(sorted(ids), stream, separators=(",", ":"))
    stream.write("\n")
os.replace(tmp, path)
os.chmod(path, 0o600)
PY
    then
        die "could not save orphan-row exclusions"
    fi
}

migration_export_go_state() {
    "$MIGRATION_HELPER" export --config "$1" --output "$MIGRATION_DIR" \
        --error-state-overrides "$MIGRATION_DIR/error-state-overrides.json" \
        --orphan-core-exclusions "$MIGRATION_DIR/orphan-core-exclusions.json"
}

is_elf_for_arch() { # the file must be a 64-bit ELF for this machine
    local want
    want=$([ "$ARCH" = amd64 ] && echo 3e00 || echo b700)
    [ "$(head -c 6 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c460201 ] \
        && [ "$(dd if="$1" bs=1 skip=18 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$want" ]
}

migration_cpu_has_avx2() {
    awk '
        /^flags[[:space:]]*:/ {
            seen = 1
            found = 0
            for (i = 2; i <= NF; i++) if ($i == "avx2") found = 1
            if (!found) missing = 1
        }
        END { exit !(seen && !missing) }
    ' /proc/cpuinfo
}

rfw_asset_for_host() {
    if [ "$ARCH" = amd64 ] && ! migration_cpu_has_avx2; then
        printf 'rfw-amd64-legacy\n'
    else
        printf 'rfw-%s\n' "$ARCH"
    fi
}

migration_rfw_restore_original() {
    local tmp
    [ -n "$MIGRATION_RFW_BIN" ] \
        && [ -f "$MIGRATION_DIR/rfw-original" ] \
        || return 1
    tmp=$(mktemp "${MIGRATION_RFW_BIN}.runman-restore.XXXXXXXX") || return 1
    if ! cp -a -- "$MIGRATION_DIR/rfw-original" "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! mv -f -- "$tmp" "$MIGRATION_RFW_BIN"; then
        rm -f -- "$tmp"
        return 1
    fi
    systemctl restart rfw.service >/dev/null 2>&1 || return 1
    [ "$(sha256sum "$MIGRATION_RFW_BIN" | awk '{print $1}')" = "$MIGRATION_RFW_ORIGINAL_SHA256" ]
}

migration_rfw_ready_stable() {
    local attempt ready=0 baseline restarts
    for ((attempt = 1; attempt <= 20; attempt++)); do
        if systemctl is-active --quiet rfw.service \
            && curl -fsS --max-time 2 "$MIGRATION_RFW_API_URL" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    [ "$ready" = 1 ] || return 1
    baseline=$(systemctl show -p NRestarts --value rfw.service 2>/dev/null) || return 1
    [[ "$baseline" =~ ^[0-9]+$ ]] || return 1
    for ((attempt = 1; attempt <= 15; attempt++)); do
        systemctl is-active --quiet rfw.service \
            && curl -fsS --max-time 2 "$MIGRATION_RFW_API_URL" >/dev/null 2>&1 \
            || return 1
        restarts=$(systemctl show -p NRestarts --value rfw.service 2>/dev/null) || return 1
        [ "$restarts" = "$baseline" ] || return 1
        sleep 1
    done
}

migration_mark_rfw_journals() {
    command -v journalctl >/dev/null 2>&1 || return 0
    MIGRATION_RFW_SERVICE_CURSOR=$(journalctl -u rfw.service -n 0 --show-cursor --no-pager 2>/dev/null \
        | sed -n 's/^-- cursor: //p' | tail -n 1)
    MIGRATION_RFW_KERNEL_CURSOR=$(journalctl -k -n 0 --show-cursor --no-pager 2>/dev/null \
        | sed -n 's/^-- cursor: //p' | tail -n 1)
}

migration_capture_rfw_attempt() {
    local since="$1" mode="$2" service_cursor="$3" kernel_cursor="$4" service_log kernel_log
    command -v journalctl >/dev/null 2>&1 || return 0
    service_log="$MIGRATION_DIR/rfw-candidate-$mode-journal.log"
    kernel_log="$MIGRATION_DIR/rfw-candidate-$mode-kernel.log"
    {
        printf 'candidate_%s_active_state=%s\n' "$mode" \
            "$(systemctl show -p ActiveState --value rfw.service 2>/dev/null || true)"
        printf 'candidate_%s_exec_main_code=%s\n' "$mode" \
            "$(systemctl show -p ExecMainCode --value rfw.service 2>/dev/null || true)"
        printf 'candidate_%s_exec_main_status=%s\n' "$mode" \
            "$(systemctl show -p ExecMainStatus --value rfw.service 2>/dev/null || true)"
    } >> "$MIGRATION_DIR/rfw-repair.txt"
    if [ -n "$service_cursor" ]; then
        journalctl -u rfw.service --after-cursor="$service_cursor" -n 200 --no-pager -o short-iso-precise \
            > "$service_log" 2>&1 || true
    else
        journalctl -u rfw.service --since "$since" -n 200 --no-pager -o short-iso-precise \
            > "$service_log" 2>&1 || true
    fi
    if [ -n "$kernel_cursor" ]; then
        journalctl -k --after-cursor="$kernel_cursor" -n 200 --no-pager -o short-iso-precise \
            > "$kernel_log" 2>&1 || true
    else
        journalctl -k --since "$since" -n 200 --no-pager -o short-iso-precise \
            > "$kernel_log" 2>&1 || true
    fi
    chmod 600 "$service_log" "$kernel_log"
    printf 'candidate_%s_service_journal=%s\ncandidate_%s_kernel_journal=%s\n' \
        "$mode" "$service_log" "$mode" "$kernel_log" >> "$MIGRATION_DIR/rfw-repair.txt"
}

migration_rfw_candidate_sigill() {
    [ "$(systemctl show -p ExecMainStatus --value rfw.service 2>/dev/null || true)" = 4 ] \
        && return 0
    grep -Eiq 'status=4/ILL|status=ILL|rfw\[[0-9]+\].*trap invalid opcode|rfw.*SIGILL' \
        "$MIGRATION_DIR/rfw-candidate-native-journal.log" \
        "$MIGRATION_DIR/rfw-candidate-native-kernel.log" 2>/dev/null
}

migration_rfw_enable_skb_mode() {
    local dropins exec_count
    MIGRATION_RFW_UNIT_PATH=$(systemctl show -p FragmentPath --value rfw.service 2>/dev/null || true)
    case "$MIGRATION_RFW_UNIT_PATH" in
        /etc/systemd/system/*.service) ;;
        *)
            warn "RFW uses a non-local systemd unit; cannot safely retry with SKB mode"
            return 1
            ;;
    esac
    if [ ! -f "$MIGRATION_RFW_UNIT_PATH" ] || [ -L "$MIGRATION_RFW_UNIT_PATH" ]; then
        warn "RFW systemd unit is not a regular local file; cannot safely retry with SKB mode"
        return 1
    fi
    dropins=$(systemctl show -p DropInPaths --value rfw.service 2>/dev/null || true)
    if [ -n "$dropins" ]; then
        warn "RFW has systemd drop-ins; preserving them and skipping the automatic SKB-mode retry"
        return 1
    fi
    exec_count=$(grep -Ec '^ExecStart=' "$MIGRATION_RFW_UNIT_PATH" || true)
    if [ "$exec_count" != 1 ] || grep -Eq '^ExecStart=.*--xdp-mode([=[:space:]]|$)' "$MIGRATION_RFW_UNIT_PATH" \
        || grep -Eq '^ExecStart=.*\\[[:space:]]*$' "$MIGRATION_RFW_UNIT_PATH"; then
        warn "RFW systemd ExecStart is not a simple single command; cannot safely append SKB mode"
        return 1
    fi

    migration_capture_file "$MIGRATION_RFW_UNIT_PATH" || return 1
    MIGRATION_RFW_UNIT_TOUCHED=1
    sed -i '/^ExecStart=/ s/$/ --xdp-mode skb/' "$MIGRATION_RFW_UNIT_PATH" || return 1
    systemctl daemon-reload || return 1
    printf 'unit_path=%s\nxdp_mode=skb\n' "$MIGRATION_RFW_UNIT_PATH" >> "$MIGRATION_DIR/rfw-repair.txt"
}

migration_prepare_rfw_repair() {
    local active restarts journal_file failures exec_start path_count api_count port
    local sums_file asset
    { [ "$MIGRATE_GO" = 1 ] || [ "$RFW_REPAIR_ONLY" = 1 ]; } \
        && [ "$ARCH" = amd64 ] || return 0
    [ "$(systemctl show -p LoadState --value rfw.service 2>/dev/null || true)" = loaded ] || return 0
    active=$(systemctl show -p ActiveState --value rfw.service 2>/dev/null || true)
    case "$active" in
        active|activating) ;;
        *) return 0 ;;
    esac
    migration_cpu_has_avx2 && return 0

    restarts=$(systemctl show -p NRestarts --value rfw.service 2>/dev/null || true)
    [[ "$restarts" =~ ^[0-9]+$ ]] && [ "$restarts" -ge 3 ] || return 0
    if ! command -v journalctl >/dev/null 2>&1; then
        warn "RFW has restarted repeatedly on a CPU without AVX2, but journalctl is unavailable; leaving its binary untouched"
        return 0
    fi
    journal_file="$MIGRATION_DIR/rfw-sigill-journal.log"
    if ! journalctl -u rfw.service --since "24 hours ago" -n 200 --no-pager -o cat \
        > "$journal_file" 2>/dev/null; then
        warn "could not read recent RFW restart evidence; leaving its binary untouched"
        rm -f -- "$journal_file"
        return 0
    fi
    chmod 600 "$journal_file"
    failures=$(grep -Ec 'status=4/ILL([[:space:]]|$)|status=ILL([[:space:]]|$)' "$journal_file" || true)
    failures=${failures:-0}
    if [ "$failures" -lt 3 ]; then
        warn "RFW has restarted repeatedly on a CPU without AVX2, but fewer than three recent SIGILL exits were found; leaving its binary untouched"
        return 0
    fi

    exec_start=$(systemctl show -p ExecStart --value rfw.service 2>/dev/null || true)
    MIGRATION_RFW_BIN=$(printf '%s\n' "$exec_start" | sed -n 's/.*path=\([^ ;}]*\).*/\1/p')
    path_count=$(printf '%s\n' "$exec_start" | grep -o 'path=' | wc -l || true)
    api_count=$(printf '%s\n' "$exec_start" | grep -o -- '--api-addr' | wc -l || true)
    path_count=${path_count//[[:space:]]/}
    api_count=${api_count//[[:space:]]/}
    if [ "$path_count" != 1 ] || [ "$api_count" != 1 ]; then
        die "RFW is in a repeated SIGILL loop, but its systemd ExecStart cannot be parsed safely; Go remains active"
    fi
    if [[ ! "$MIGRATION_RFW_BIN" =~ ^/[A-Za-z0-9._/-]+/rfw$ ]] \
        || [ ! -f "$MIGRATION_RFW_BIN" ] || [ ! -x "$MIGRATION_RFW_BIN" ] || [ -L "$MIGRATION_RFW_BIN" ]; then
        die "RFW is in a repeated SIGILL loop, but its executable path is unsupported; Go remains active"
    fi
    MIGRATION_RFW_API_ADDR=$(printf '%s\n' "$exec_start" \
        | sed -n 's/.*argv\[\]=[^;]*--api-addr[[:space:]]\([^ ;}]*\).*/\1/p')
    [[ "$MIGRATION_RFW_API_ADDR" =~ ^(127\.0\.0\.1|\[::1\]|localhost):[0-9]{1,5}$ ]] \
        || die "RFW is in a repeated SIGILL loop, but its API address is not a supported loopback endpoint; Go remains active"
    port=${MIGRATION_RFW_API_ADDR##*:}
    (( 10#$port >= 1 && 10#$port <= 65535 )) \
        || die "RFW is in a repeated SIGILL loop, but its API port is invalid; Go remains active"
    MIGRATION_RFW_API_URL="http://$MIGRATION_RFW_API_ADDR/api/status"

    asset=$(rfw_asset_for_host)
    sums_file="$WORK/rfw-SHA256SUMS"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$sums_file" "$RFW_URL/SHA256SUMS" \
        || die "RFW has a confirmed AVX2-related crash loop, but its release checksum list is unavailable; Go remains active"
    MIGRATION_RFW_CANDIDATE="$WORK/$asset"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$MIGRATION_RFW_CANDIDATE" "$RFW_URL/$asset" \
        || die "RFW has a confirmed AVX2-related crash loop, but the compatible RFW release binary is unavailable; Go remains active"
    [ "$(grep -Ec "  \*?$asset\$" "$sums_file")" = 1 ] \
        || die "RFW release checksum list does not contain exactly one entry for $asset; Go remains active"
    (cd "$WORK" && grep -E "  \*?$asset\$" "$sums_file" | sha256sum -c --quiet -) \
        || die "RFW release checksum mismatch for $asset; Go remains active"
    is_elf_for_arch "$MIGRATION_RFW_CANDIDATE" \
        || die "the verified RFW release is not a binary for this host; Go remains active"
    chmod 755 "$MIGRATION_RFW_CANDIDATE"
    MIGRATION_RFW_VERSION=$("$MIGRATION_RFW_CANDIDATE" --version 2>&1) \
        || die "the verified RFW release cannot run on this host; Go remains active"
    MIGRATION_RFW_ORIGINAL_SHA256=$(sha256sum "$MIGRATION_RFW_BIN" | awk '{print $1}')
    MIGRATION_RFW_CANDIDATE_SHA256=$(sha256sum "$MIGRATION_RFW_CANDIDATE" | awk '{print $1}')
    [ "$MIGRATION_RFW_ORIGINAL_SHA256" != "$MIGRATION_RFW_CANDIDATE_SHA256" ] \
        || die "RFW has a confirmed AVX2-related crash loop, but the published binary is unchanged; migration stopped before changing Go"
    cp -a -- "$MIGRATION_RFW_BIN" "$MIGRATION_DIR/rfw-original" \
        || die "could not save the original RFW binary; Go remains active"
    {
        printf 'executable=%s\napi_addr=%s\n' "$MIGRATION_RFW_BIN" "$MIGRATION_RFW_API_ADDR"
        printf 'restart_count=%s\nrecent_sigill_exits=%s\n' "$restarts" "$failures"
        printf 'original_sha256=%s\ncandidate_sha256=%s\ncandidate_version=%s\n' \
            "$MIGRATION_RFW_ORIGINAL_SHA256" "$MIGRATION_RFW_CANDIDATE_SHA256" "$MIGRATION_RFW_VERSION"
    } > "$MIGRATION_DIR/rfw-repair.txt"
    chmod 600 "$MIGRATION_DIR/rfw-repair.txt"
    MIGRATION_RFW_REPAIR_REQUIRED=1
    log "detected repeated RFW SIGILL exits on a CPU without AVX2; verified a replacement and saved the original binary"
}

migration_apply_rfw_repair() {
    local tmp mode started
    [ "$MIGRATION_RFW_REPAIR_REQUIRED" = 1 ] || return 0
    MIGRATION_RFW_REPAIR_ATTEMPTED=1
    mode=$(stat -c '%a' -- "$MIGRATION_RFW_BIN") || return 1
    tmp=$(mktemp "${MIGRATION_RFW_BIN}.runman-new.XXXXXXXX") || return 1
    if ! install -m "$mode" "$MIGRATION_RFW_CANDIDATE" "$tmp" \
        || ! chown --reference="$MIGRATION_RFW_BIN" "$tmp" \
        || ! chmod --reference="$MIGRATION_RFW_BIN" "$tmp" \
        || ! mv -f -- "$tmp" "$MIGRATION_RFW_BIN"; then
        rm -f -- "$tmp"
        return 1
    fi
    [ "$(sha256sum "$MIGRATION_RFW_BIN" | awk '{print $1}')" = "$MIGRATION_RFW_CANDIDATE_SHA256" ] \
        || return 1
    migration_mark_rfw_journals
    started=$(date --iso-8601=seconds)
    systemctl restart rfw.service >/dev/null 2>&1 || true
    if ! migration_rfw_ready_stable; then
        migration_capture_rfw_attempt "$started" native \
            "$MIGRATION_RFW_SERVICE_CURSOR" "$MIGRATION_RFW_KERNEL_CURSOR"
        if migration_rfw_candidate_sigill; then
            warn "the replacement RFW still hit SIGILL; captured its service and kernel logs and will restore the original binary"
            return 1
        fi
        log "RFW API did not become healthy in its existing mode; retrying with the compatible SKB XDP mode"
        migration_rfw_enable_skb_mode || return 1
        migration_mark_rfw_journals
        started=$(date --iso-8601=seconds)
        systemctl restart rfw.service >/dev/null 2>&1 || true
        if ! migration_rfw_ready_stable; then
            migration_capture_rfw_attempt "$started" skb \
                "$MIGRATION_RFW_SERVICE_CURSOR" "$MIGRATION_RFW_KERNEL_CURSOR"
            return 1
        fi
        printf 'repair_applied=1\napi_stable_seconds=15\nxdp_mode=skb\n' >> "$MIGRATION_DIR/rfw-repair.txt"
        MIGRATION_RFW_REPAIRED=1
        log "RFW replacement passed a 15-second API stability check in SKB mode"
        return 0
    fi
    MIGRATION_RFW_REPAIRED=1
    printf 'repair_applied=1\napi_stable_seconds=15\nxdp_mode=existing\n' >> "$MIGRATION_DIR/rfw-repair.txt"
    log "RFW replacement passed a 15-second API stability check; its systemd unit and arguments were preserved"
}

repair_rfw_only() {
    [ "$RFW_REPAIR_ONLY" = 1 ] || return 0
    [ "$ARCH" = amd64 ] || die "standalone RFW repair currently supports x86_64 only"
    [ "$(systemctl show -p LoadState --value rfw.service 2>/dev/null || true)" = loaded ] \
        || die "rfw.service is not installed; no changes made"

    install -d -m 700 /var/backups
    MIGRATION_DIR=$(mktemp -d /var/backups/runman-rfw-repair.XXXXXXXX)
    chmod 700 "$MIGRATION_DIR"
    WORK=$(mktemp -d /tmp/runman-agent-rfw-repair.XXXXXXXX)
    trap cleanup_exit EXIT
    migration_prepare_rfw_repair
    [ "$MIGRATION_RFW_REPAIR_REQUIRED" = 1 ] \
        || die "no active non-AVX2 RFW crash loop was confirmed; no changes made"

    MIGRATION_ACTIVE=1
    migration_apply_rfw_repair \
        || die "RFW repair failed; the original binary/unit were restored when possible. Snapshot: $MIGRATION_DIR"
    MIGRATION_COMMITTED=1
    printf '\nRFW repair succeeded. Backup and candidate logs: %s\n' "$MIGRATION_DIR"
}

migration_rollback() {
    local failed=0 record id
    if [ "$MIGRATION_RFW_REPAIR_ATTEMPTED" = 1 ] && [ "$MIGRATION_RFW_REPAIRED" != 1 ]; then
        printf 'RFW replacement did not pass health checks; restoring the original binary and service.\n' >&2
        if [ "$MIGRATION_RFW_UNIT_TOUCHED" = 1 ]; then
            migration_restore_file "$MIGRATION_RFW_UNIT_PATH" || failed=1
            systemctl daemon-reload >/dev/null 2>&1 || failed=1
        fi
        migration_rfw_restore_original || failed=1
    fi
    if [ "$MIGRATION_GO_STOP_ATTEMPTED" = 1 ]; then
        printf '\nMigration did not commit; restoring the Go service and containers. Snapshot: %s\n' "$MIGRATION_DIR" >&2
        systemctl disable --now runman-agent.service >/dev/null 2>&1 || true
        if [ -d "$DATA_DIR/instances" ]; then
            for record in "$DATA_DIR"/instances/*/instance.json; do
                [ -f "$record" ] || continue
                id=$(basename "$(dirname "$record")")
                systemctl stop "runman-$id.service" >/dev/null 2>&1 || true
            done
        fi
        nft delete table inet runman >/dev/null 2>&1 || true
        nft delete table bridge runman >/dev/null 2>&1 || true
        ip link del rmbr0 >/dev/null 2>&1 || true
        rm -f "$BIN" /etc/systemd/system/runman-agent.service
        rm -rf -- "$CONFIG_DIR" "$DATA_DIR" /run/runman-agent
        rm -f /run/narwhal-agent/connlimit.sock /run/narwhal-agent/firewall.sock
        rmdir /run/narwhal-agent >/dev/null 2>&1 || true
    else
        printf '\nMigration stopped before stopping Go; leaving the Go service and legacy containers untouched. Snapshot: %s\n' "$MIGRATION_DIR" >&2
    fi
    if [ "$MIGRATION_MODULES_CONFIG_TOUCHED" = 1 ]; then
        migration_restore_file /etc/modules-load.d/runman.conf || failed=1
    fi
    if [ "$MIGRATION_SYSCTL_CONFIG_TOUCHED" = 1 ]; then
        migration_restore_file /etc/sysctl.d/90-runman.conf || failed=1
    fi
    if [ "$MIGRATION_LXCFS_CONFIG_TOUCHED" = 1 ]; then
        migration_restore_file /etc/systemd/system/lxcfs.service.d/runman.conf || failed=1
    fi
    systemctl daemon-reload >/dev/null 2>&1 || failed=1
    if [ "$MIGRATION_SYSCTL_CONFIG_TOUCHED" = 1 ]; then
        sysctl --system >/dev/null 2>&1 || true
    fi

    if [ "$MIGRATION_LXCFS_CONFIG_TOUCHED" = 1 ] || [ "$MIGRATION_LXCFS_STATE_TOUCHED" = 1 ]; then
        local lxcfs_active_now=0 lxcfs_enabled_now=0
        if systemctl is-active --quiet lxcfs.service; then lxcfs_active_now=1; fi
        if systemctl is-enabled --quiet lxcfs.service; then lxcfs_enabled_now=1; fi

        # Restore lxcfs configuration only when this installer changed it.
        # If the service was already in its original state, avoid restarting
        # it during an early rollback (which detaches its /proc views).
        if [ "$MIGRATION_LXCFS_WAS_ACTIVE" = 1 ]; then
            if [ "$lxcfs_active_now" = 0 ]; then
                systemctl start lxcfs.service >/dev/null 2>&1 || failed=1
            elif [ "$MIGRATION_LXCFS_CONFIG_TOUCHED" = 1 ]; then
                systemctl restart lxcfs.service >/dev/null 2>&1 || failed=1
            fi
        elif [ "$lxcfs_active_now" = 1 ]; then
            systemctl stop lxcfs.service >/dev/null 2>&1 || failed=1
        fi

        if [ "$MIGRATION_LXCFS_WAS_ENABLED" = 1 ]; then
            [ "$lxcfs_enabled_now" = 1 ] || systemctl enable lxcfs.service >/dev/null 2>&1 || failed=1
        elif [ "$lxcfs_enabled_now" = 1 ]; then
            systemctl disable lxcfs.service >/dev/null 2>&1 || failed=1
        fi
    fi
    if [ "$MIGRATION_GO_STOP_ATTEMPTED" = 1 ] \
        && [ -x "$MIGRATION_HELPER" ] && [ -f "$MIGRATION_DIR/legacy-state.json" ]; then
        "$MIGRATION_HELPER" lifecycle start --backend "$MIGRATION_BACKEND" \
            --state "$MIGRATION_DIR/legacy-state.json" || failed=1
    fi
    if [ "$MIGRATION_GUESTS_PREDELETE_ATTEMPTED" = 1 ]; then
        printf 'Low-space recovery had begun deleting confirmed Go-managed Incus guests before Rust health checks. The snapshot preserves their parameters and Go database, but their guest files cannot be restored. Review predeleted_for_space in %s/legacy-state.json.\n' \
            "$MIGRATION_DIR" >&2
    fi
    if [ "$MIGRATION_GO_STOP_ATTEMPTED" = 1 ]; then
        if [ "$MIGRATION_GO_WAS_ENABLED" = 1 ]; then
            systemctl enable narwhal-agent.service >/dev/null 2>&1 || failed=1
        else
            systemctl disable narwhal-agent.service >/dev/null 2>&1 || true
        fi
        if [ "$MIGRATION_GO_WAS_ACTIVE" = 1 ]; then
            systemctl start narwhal-agent.service >/dev/null 2>&1 || failed=1
        fi
    fi
    if [ "$failed" = 1 ]; then
        printf 'Automatic rollback could not confirm every restoration. Review %s and systemd/container logs.\n' "$MIGRATION_DIR" >&2
        if [ -x "$MIGRATION_DIR/diagnose-go-rust-migration.sh" ]; then
            printf 'Run the read-only diagnostic: bash %q %q\n' \
                "$MIGRATION_DIR/diagnose-go-rust-migration.sh" "$MIGRATION_DIR" >&2
        fi
    else
        if [ "$MIGRATION_GUESTS_PREDELETE_ATTEMPTED" = 1 ]; then
            printf 'Go service/configuration was restored. Incus guests deleted for disk recovery remain absent; their settings/database are backed up but their files cannot be restored.\n' >&2
        elif [ "$MIGRATION_GO_STOP_ATTEMPTED" = 1 ]; then
            printf 'Go service state and recoverable pre-existing containers were restored.\n' >&2
        else
            printf 'No Go service or container state was changed by the migration.\n' >&2
        fi
    fi
    if [ "$MIGRATION_RFW_REPAIRED" = 1 ]; then
        printf 'The verified RFW repair remains installed after Go rollback; see %s/rfw-repair.txt for its XDP mode and evidence.\n' \
            "$MIGRATION_DIR" >&2
    fi
}

cleanup_exit() {
    local rc=$?
    trap - EXIT
    if [ "$MIGRATION_ACTIVE" = 1 ] && [ "$MIGRATION_COMMITTED" != 1 ]; then
        set +e
        migration_rollback
        set -e
    fi
    [ -z "$WORK" ] || rm -rf -- "$WORK"
    exit "$rc"
}

cleanup_incus_cached_images() {
    local work candidates fingerprint count=0
    command -v incus >/dev/null 2>&1 || return 0
    command -v python3 >/dev/null 2>&1 || { warn "python3 is unavailable; skipping Incus image cleanup"; return 0; }

    work=$(mktemp -d)
    if ! incus list local: --all-projects -c F --format csv,noheader > "$work/used-images.csv" \
        || ! incus image list local: --format json > "$work/images.json"; then
        warn "could not inventory Incus image use; skipping Incus image cleanup"
        rm -rf -- "$work"
        return 0
    fi
    candidates="$work/candidates"
    if ! python3 - "$work/images.json" "$work/used-images.csv" > "$candidates" <<'PY'
import datetime
import json
import pathlib
import re
import sys

try:
    images = json.loads(pathlib.Path(sys.argv[1]).read_text())
    used = {line.strip() for line in pathlib.Path(sys.argv[2]).read_text().splitlines() if line.strip()}
    if not isinstance(images, list):
        raise ValueError("unexpected Incus image list")
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
    for image in images:
        if not isinstance(image, dict) or image.get("cached") is not True:
            continue
        if image.get("aliases"):
            continue
        fingerprint = image.get("fingerprint", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint) or fingerprint in used:
            continue
        timestamp = image.get("last_used_at") or image.get("created_at")
        if not timestamp:
            continue
        try:
            parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        if parsed < cutoff:
            print(fingerprint)
except Exception as exc:
    print(f"Incus image inventory could not be parsed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
    then
        warn "could not safely parse Incus image inventory; skipping Incus image cleanup"
        rm -rf -- "$work"
        return 0
    fi

    while IFS= read -r fingerprint; do
        [ -n "$fingerprint" ] || continue
        if incus image delete "local:$fingerprint" >/dev/null 2>&1; then
            log "removed unused Incus cached image ${fingerprint:0:12} (older than 7 days)"
            count=$((count + 1))
        else
            warn "Incus refused to remove cached image ${fingerprint:0:12}; it was left in place"
        fi
    done < "$candidates"
    [ "$count" -gt 0 ] || log "no unused Incus cached images older than 7 days"
    rm -rf -- "$work"
}

maintenance_cleanup() {
    local conf=/etc/systemd/journald.conf.d/90-runman-retention.conf
    local work backup_dir limits had_conf=0 failed=0
    work=$(mktemp -d)
    cat > "$work/desired.conf" <<'EOF'
# Managed by Runman Agent; system and Podman logs retain at most 7 days.
[Journal]
SystemMaxUse=512M
RuntimeMaxUse=128M
SystemKeepFree=1G
MaxRetentionSec=7day
MaxFileSec=1day
EOF

    install -d -m 755 /etc/systemd/journald.conf.d
    if [ -e "$conf" ]; then
        cp -a "$conf" "$work/original.conf"
        had_conf=1
    fi
    if ! cmp -s "$work/desired.conf" "$conf" 2>/dev/null; then
        if [ -e "$conf" ]; then
            backup_dir="/var/backups/runman-agent/maintenance-$(date -u +%Y%m%dT%H%M%SZ)"
            install -d -m 700 "$backup_dir"
            cp -a "$conf" "$backup_dir/90-runman-retention.conf.before"
            log "backed up existing journald drop-in to $backup_dir"
        fi
        install -m 644 "$work/desired.conf" "$conf"
        if ! systemd-analyze cat-config systemd/journald.conf > "$work/effective.conf" \
            || ! awk -F= '
                function trim(value) {
                    sub(/^[[:space:]]+/, "", value)
                    sub(/[[:space:]]+$/, "", value)
                    return value
                }
                index($0, "=") == 0 { next }
                {
                    key=trim(substr($0, 1, index($0, "=") - 1))
                    value=trim(substr($0, index($0, "=") + 1))
                    sub(/[[:space:]]+[;#].*$/, "", value)
                    if (key == "SystemMaxUse") system_max=value
                    if (key == "RuntimeMaxUse") runtime_max=value
                    if (key == "SystemKeepFree") system_keep_free=value
                    if (key == "MaxRetentionSec") max_retention=value
                    if (key == "MaxFileSec") max_file=value
                }
                END {
                    if (max_retention == "7day" && max_file == "1day") {
                        printf "SystemMaxUse=%s RuntimeMaxUse=%s SystemKeepFree=%s\n", system_max, runtime_max, system_keep_free
                        exit 0
                    }
                    printf "effective journald retention differs: MaxRetentionSec=%s MaxFileSec=%s\n", max_retention, max_file > "/dev/stderr"
                    exit 1
                }
            ' "$work/effective.conf" > "$work/effective-limits"; then
            if [ "$had_conf" = 1 ]; then cp -a "$work/original.conf" "$conf"; else rm -f "$conf"; fi
            warn "could not verify 7-day journald retention; restored its previous drop-in"
        elif ! systemctl restart systemd-journald.service; then
            if [ "$had_conf" = 1 ]; then cp -a "$work/original.conf" "$conf"; else rm -f "$conf"; fi
            systemctl restart systemd-journald.service >/dev/null 2>&1 || true
            warn "journald could not restart; restored its previous drop-in"
            failed=1
        else
            limits=$(cat "$work/effective-limits")
            log "applied 7-day journald retention; effective size limits: ${limits:-system defaults}"
        fi
    fi

    journalctl --rotate || { warn "could not rotate the active journal"; failed=1; }
    journalctl --vacuum-time=7d || { warn "could not vacuum journals older than 7 days"; failed=1; }

    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        if podman image prune -f; then
            log "removed dangling Podman images; tagged images and container data were preserved"
        else
            warn "Podman dangling-image cleanup failed"
            failed=1
        fi
    fi
    cleanup_incus_cached_images

    # Remove only rotated archives older than seven days, never active log files.
    if [ -d /var/log ]; then
        find /var/log -xdev -type f -mmin +10080 \
            \( -name '*.gz' -o -name '*.xz' -o -name '*.zst' -o -name '*.old' \
               -o -name '*.log.[0-9]*' -o -name '*.log-20[0-9][0-9][0-9][0-9][0-9][0-9]*' \) \
            -print -delete || { warn "could not prune all old rotated log archives"; failed=1; }
        if [ -d /var/log/installer ]; then
            find /var/log/installer -xdev -type f -mmin +10080 \
                \( -name syslog -o -name partman -o -name '*.log' -o -name 'Xorg*' \) \
                -print -delete || { warn "could not prune all old installer logs"; failed=1; }
        fi
    fi
    rm -rf -- "$work"
    return "$failed"
}

podman_rootless_state_present() {
    local username home users
    command -v getent >/dev/null 2>&1 || return 0
    users=$(getent passwd) || return 0
    if [ -f /etc/containers/storage.conf ] \
        && grep -Eq '^[[:space:]]*rootless_storage_path[[:space:]]*=' /etc/containers/storage.conf; then
        log "custom rootless Podman storage path is configured; keeping Podman and its data"
        return 0
    fi
    while IFS=: read -r username _ _ _ _ home _; do
        if [ -z "$home" ] || [ "$home" = /nonexistent ]; then
            continue
        fi
        if [ -d "$home/.local/share/containers/storage" ] \
            || [ -f "$home/.config/containers/storage.conf" ]; then
            log "Podman rootless storage/config exists for $username; keeping Podman and its data"
            return 0
        fi
    done <<< "$users"
    return 1
}

purge_runtime_packages() {
    local label="$1" package_names="$2" unit_names="$3" work package status unit
    local -a candidates installed units active_units enabled_units
    read -r -a candidates <<< "$package_names"
    read -r -a units <<< "$unit_names"
    installed=()
    active_units=()
    enabled_units=()
    for package in "${candidates[@]}"; do
        status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
        if [[ "$status" == ii* ]]; then installed+=("$package"); fi
    done
    [ "${#installed[@]}" -gt 0 ] || { log "$label runtime packages are already absent"; return 0; }

    work=$(mktemp -d)
    if ! LC_ALL=C apt-get -o DPkg::Lock::Timeout=600 -s purge "${installed[@]}" >"$work/plan" 2>&1; then
        warn "could not simulate $label package removal; leaving packages and services in place"
        rm -rf -- "$work"
        return 0
    fi
    if grep -E '^(Remv|Purg)[[:space:]]+(docker[^[:space:]]*|moby[^[:space:]]*|containerd[^[:space:]]*|runc|podman-docker)([[:space:]]|$)' "$work/plan" >/dev/null; then
        warn "$label removal would change Docker/containerd-related packages; keeping all packages and services"
        rm -rf -- "$work"
        return 0
    fi

    for unit in "${units[@]}"; do
        if systemctl is-active --quiet "$unit"; then active_units+=("$unit"); fi
        if systemctl is-enabled --quiet "$unit"; then enabled_units+=("$unit"); fi
    done
    for unit in "${units[@]}"; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    if ! DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q purge "${installed[@]}" >"$work/apply" 2>&1; then
        for unit in "${active_units[@]}"; do systemctl start "$unit" >/dev/null 2>&1 || true; done
        for unit in "${enabled_units[@]}"; do systemctl enable "$unit" >/dev/null 2>&1 || true; done
        warn "$label package removal failed; restored previously active/enabled services where possible"
        tail -n 12 "$work/apply" >&2 || true
        rm -rf -- "$work"
        return 0
    fi
    systemctl daemon-reload || warn "systemd daemon-reload reported an error after $label package removal"
    log "removed unused $label runtime packages: ${installed[*]} (Docker/containerd packages were not selected; autoremove was not run)"
    rm -rf -- "$work"
}

cleanup_unused_podman() {
    local work
    command -v podman >/dev/null 2>&1 || return 0
    if command -v snap >/dev/null 2>&1 && snap list podman >/dev/null 2>&1; then
        warn "Podman is Snap-managed; leaving it in place because this cleanup only purges apt-owned packages"
        return 0
    fi
    work=$(mktemp -d)
    if ! podman ps --all --quiet >"$work/containers" 2>&1; then
        warn "could not inventory Podman containers; keeping Podman"
        rm -rf -- "$work"
        return 0
    fi
    if [ -s "$work/containers" ]; then
        log "Podman still has containers; keeping its runtime and data"
        rm -rf -- "$work"
        return 0
    fi
    # `podman pod ps` already lists pods in every state; unlike `podman ps`,
    # this subcommand does not accept --all on supported Podman releases.
    if ! podman pod ps --quiet >"$work/pods" 2>&1; then
        warn "could not inventory Podman pods; keeping Podman"
        tail -n 8 "$work/pods" >&2 || true
        rm -rf -- "$work"
        return 0
    fi
    if [ -s "$work/pods" ]; then
        log "Podman still has pods; keeping its runtime and data"
        rm -rf -- "$work"
        return 0
    fi
    if ! podman volume ls --quiet >"$work/volumes" 2>&1; then
        warn "could not inventory Podman volumes; keeping Podman"
        rm -rf -- "$work"
        return 0
    fi
    if [ -s "$work/volumes" ]; then
        log "Podman still has named volumes; keeping its runtime and data"
        rm -rf -- "$work"
        return 0
    fi
    if podman_rootless_state_present; then
        rm -rf -- "$work"
        return 0
    fi
    if ! podman system prune --all --force >"$work/prune" 2>&1; then
        warn "Podman could not safely prune its unused image/cache data; keeping Podman packages"
        tail -n 8 "$work/prune" >&2 || true
        rm -rf -- "$work"
        return 0
    fi
    purge_runtime_packages "Podman" \
        "podman podman-compose aardvark-dns netavark" \
        "podman.socket podman-auto-update.timer podman-restart.service"
    rm -rf -- "$work"
}

cleanup_unused_incus() {
    local work pool count=0 fingerprint project volume_type
    command -v incus >/dev/null 2>&1 || return 0
    if command -v snap >/dev/null 2>&1 && snap list incus >/dev/null 2>&1; then
        warn "Incus is Snap-managed; leaving it in place because this cleanup only purges apt-owned packages"
        return 0
    fi
    command -v python3 >/dev/null 2>&1 || { warn "python3 unavailable; keeping Incus because its inventory cannot be checked"; return 0; }
    work=$(mktemp -d)
    if ! incus list local: --all-projects -c n --format csv,noheader >"$work/instances" 2>&1; then
        warn "could not inventory Incus instances across projects; keeping Incus"
        rm -rf -- "$work"
        return 0
    fi
    if [ -s "$work/instances" ]; then
        log "Incus still has instances in at least one project; keeping its runtime and data"
        rm -rf -- "$work"
        return 0
    fi
    if ! incus storage list local: -c n --format csv,noheader >"$work/pools" 2>&1; then
        warn "could not inventory Incus storage pools; keeping Incus"
        rm -rf -- "$work"
        return 0
    fi
    : > "$work/remaining-volumes"
    while IFS= read -r pool; do
        [ -n "$pool" ] || continue
        for volume_type in custom container virtual-machine; do
            count=$((count + 1))
            if ! incus storage volume list "local:$pool" "type=$volume_type" \
                --all-projects -c t,n --format csv,noheader >"$work/volumes-$count" 2>&1; then
                warn "could not inventory Incus $volume_type volumes in pool $pool; keeping Incus"
                tail -n 8 "$work/volumes-$count" >&2 || true
                rm -rf -- "$work"
                return 0
            fi
            if [ -s "$work/volumes-$count" ]; then
                cat "$work/volumes-$count" >> "$work/remaining-volumes"
            fi
        done
    done < "$work/pools"
    if [ -s "$work/remaining-volumes" ]; then
        log "Incus still has custom or orphaned instance storage volumes; keeping its runtime and data"
        rm -rf -- "$work"
        return 0
    fi
    if ! incus image list local: --all-projects -c F,e --format csv,noheader >"$work/images.csv" 2>&1; then
        warn "could not inventory Incus images; keeping Incus"
        rm -rf -- "$work"
        return 0
    fi
    if ! python3 - "$work/images.csv" > "$work/images.tsv" <<'PY'
import csv
import re
import sys

try:
    with open(sys.argv[1], newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if not row:
                continue
            if len(row) < 2:
                raise ValueError("Incus image project column is missing")
            fingerprint, project = row[0].strip(), row[1].strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
                raise ValueError("Incus returned a non-full image fingerprint")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", project):
                raise ValueError("Incus returned an invalid project name")
            print(f"{fingerprint}\t{project}")
except Exception as exc:
    print(f"image inventory could not be parsed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
    then
        warn "could not safely parse Incus images across projects; keeping Incus"
        rm -rf -- "$work"
        return 0
    fi
    while IFS=$'\t' read -r fingerprint project; do
        [ -n "$fingerprint" ] || continue
        if ! incus image delete "local:$fingerprint" --project "$project" >/dev/null 2>&1; then
            warn "could not remove every unused Incus image; keeping Incus packages"
            rm -rf -- "$work"
            return 0
        fi
    done < "$work/images.tsv"
    purge_runtime_packages "Incus" \
        "incus incus-base incus-client incus-ui-canonical incus-extra incus-tools" \
        "incus.service incus.socket incus-user.service incus-user.socket"
    rm -rf -- "$work"
}

cleanup_unused_container_runtimes() {
    # Rust v2 runs guests with its own namespace supervisor, not Incus or
    # Podman. Keep lxcfs: Rust guests use its per-instance /proc views.
    if [ -f /opt/narwhal-agent/config.json ] || [ -f /opt/narwhal-agent/agent.db ] \
        || [ -f /var/lib/narwhal-agent/agent.db ] \
        || systemctl is-active --quiet narwhal-agent.service; then
        log "Go v1 is still installed or active and may need its container backend; keeping Podman/Incus"
        return 0
    fi
    cleanup_unused_podman
    cleanup_unused_incus
    log "lxcfs was retained for Rust guests; Docker was not changed"
}

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --token TOKEN           Token issued by the platform. Without one the node runs
                          standalone: it never contacts the platform and is
                          managed entirely from its own panel
  --platform-url URL      Platform gRPC endpoint (default: https://hosting.fuckip.me:443)
  --web-listen ADDR       Management panel address (default 0.0.0.0:8792, which
                          covers IPv4 and IPv6;
                          use 127.0.0.1:8792 to reach it only through an SSH tunnel)
  --no-web                Disable the management panel
  --ipv6 MODE             auto (default), none, snat or subnet
  --ipv6-prefix CIDR      Prefix for --ipv6 subnet, e.g. 2001:db8:1:2::/64
  --ipv6-uplink IFACE     Interface where that prefix is on-link (NDP proxy);
                          omit when the prefix is routed to this host
  --bandwidth MBPS        Correct the measured uplink bandwidth reported to the
                          platform (default: report the speed test)
  --no-rfw                Do not install the rfw firewall
  --rfw-iface IFACE       Interface rfw protects (default: IPv4 default route)
  --from-dir DIR          Use binaries from DIR (runman-agent-linux-<arch>, SHA256SUMS,
                          optionally rfw-<arch> and rfw-amd64-legacy) instead of downloading
  --migrate-go            Lossy clean-rebuild migration from a supported Go Podman/Incus node;
                          keeps a rollback snapshot until Rust health, port, and network checks pass
  --repair-rfw            Repair a confirmed x86_64 RFW SIGILL loop without migrating Go containers
  --cleanup-only          Apply 7-day log retention and prune dangling/unused images, without installing
  --cleanup-runtimes      With --cleanup-only: remove empty Podman/Incus packages after inventory checks
  --uninstall             Remove the agent; refuses while instances exist
  --purge                 With --uninstall: also delete every instance and all data
  -h, --help              Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
        --platform-url) PLATFORM_URL="${2:?--platform-url needs a value}"; shift 2 ;;
        --web-listen) WEB_LISTEN="${2:?--web-listen needs a value}"; shift 2 ;;
        --no-web) WEB_LISTEN=""; shift ;;
        --ipv6) IPV6="${2:?--ipv6 needs a value}"; shift 2 ;;
        --ipv6-prefix) IPV6_PREFIX="${2:?--ipv6-prefix needs a value}"; shift 2 ;;
        --ipv6-uplink) IPV6_UPLINK="${2:?--ipv6-uplink needs a value}"; shift 2 ;;
        --bandwidth) BANDWIDTH="${2:?--bandwidth needs a value}"; shift 2 ;;
        --no-rfw) WITH_RFW=0; shift ;;
        --rfw-iface) RFW_IFACE="${2:?--rfw-iface needs a value}"; shift 2 ;;
        --from-dir) FROM_DIR="${2:?--from-dir needs a value}"; shift 2 ;;
        --migrate-go) MIGRATE_GO=1; WITH_RFW=0; shift ;;
        --repair-rfw) RFW_REPAIR_ONLY=1; shift ;;
        --cleanup-only) CLEANUP_ONLY=1; shift ;;
        --cleanup-runtimes) CLEANUP_RUNTIMES=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root"

# ── validation ──────────────────────────────────────────────────────────────

[[ "$PLATFORM_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || die "invalid --platform-url"
[ -z "$WEB_LISTEN" ] || [[ "$WEB_LISTEN" =~ ^[0-9.]+:[0-9]{1,5}$|^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]] \
    || die "invalid --web-listen (expected ip:port)"
[[ "$BANDWIDTH" =~ ^[0-9]{1,7}$ ]] || die "invalid --bandwidth"
[ -z "$TOKEN" ] || [[ "$TOKEN" =~ ^[[:graph:]]{16,512}$ ]] || die "--token must be 16-512 printable characters"
case "$IPV6" in
    auto|none|snat) ;;
    subnet)
        [[ "$IPV6_PREFIX" =~ ^[0-9a-fA-F:]+/[0-9]{1,3}$ ]] || die "--ipv6 subnet needs --ipv6-prefix CIDR"
        [ -z "$IPV6_UPLINK" ] || [[ "$IPV6_UPLINK" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "invalid --ipv6-uplink"
        ;;
    *) die "--ipv6 must be auto, none, snat or subnet" ;;
esac
[ -z "$RFW_IFACE" ] || [[ "$RFW_IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "invalid --rfw-iface"

if [ "$MIGRATE_GO" = 1 ]; then
    if [ -n "$TOKEN" ] || [ -n "$FROM_DIR" ] || [ "$UNINSTALL" != 0 ] \
        || [ "$PURGE" != 0 ] || [ "$WITH_RFW" != 0 ]; then
        die "--migrate-go cannot be combined with token, local assets, RFW, or uninstall options"
    fi
fi

if [ "$RFW_REPAIR_ONLY" = 1 ] && { [ "$MIGRATE_GO" = 1 ] || [ -n "$TOKEN" ] \
    || [ -n "$FROM_DIR" ] || [ "$WITH_RFW" != 1 ] || [ "$CLEANUP_ONLY" = 1 ] \
    || [ "$CLEANUP_RUNTIMES" = 1 ] || [ "$UNINSTALL" = 1 ] || [ "$PURGE" = 1 ]; }; then
    die "--repair-rfw must be used alone"
fi

if [ "$CLEANUP_ONLY" = 1 ] && { [ "$MIGRATE_GO" = 1 ] || [ "$UNINSTALL" = 1 ] \
    || [ "$PURGE" = 1 ] || [ -n "$TOKEN" ] || [ -n "$FROM_DIR" ]; }; then
    die "--cleanup-only cannot be combined with migration, uninstall, token, or local asset options"
fi
if [ "$CLEANUP_RUNTIMES" = 1 ] && [ "$CLEANUP_ONLY" != 1 ]; then
    die "--cleanup-runtimes requires --cleanup-only"
fi

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac

prepare_go_migration() {
    local go_config=/opt/narwhal-agent/config.json go_binary=/opt/narwhal-agent/narwhal-agent
    local asset go_unit_path host_port migration_free_after_delete orphan_count
    local diagnostic_asset=diagnose-go-rust-migration.sh
    [ "$MIGRATE_GO" = 1 ] || return 0
    [ -t 0 ] || die "Go -> Rust migration requires an interactive terminal for the destructive confirmation"
    if [ ! -f "$go_config" ] || [ ! -x "$go_binary" ]; then
        die "standard Go config/binary not found; no host changes made"
    fi
    # Go and Rust intentionally share these control API sockets, so their
    # presence is normal on a running Go node and does not identify Rust v2.
    if [ -e "$CONFIG_DIR" ] || [ -e "$DATA_DIR" ] || [ -e "$BIN" ] \
        || [ -e /etc/systemd/system/runman-agent.service ] || [ -e /run/runman-agent ] \
        || systemctl is-active --quiet runman-agent.service 2>/dev/null; then
        die "a Rust v2 installation already exists; migration will not overwrite it"
    fi
    ! ip link show rmbr0 >/dev/null 2>&1 || die "rmbr0 already exists; refusing to replace an existing network"
    ! nft list table inet runman >/dev/null 2>&1 || die "inet runman firewall table already exists"
    ! nft list table bridge runman >/dev/null 2>&1 || die "bridge runman firewall table already exists"
    command -v python3 >/dev/null 2>&1 || die "python3 is required for a consistent Go database snapshot"
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify Rust release assets"

    WORK=$(mktemp -d /tmp/runman-agent-rust-v2.XXXXXXXX)
    # Arm cleanup before any release download, migration prompt, or preflight
    # can fail. Rollback is gated by MIGRATION_ACTIVE inside cleanup_exit.
    trap cleanup_exit EXIT
    mkdir -p "$WORK/release"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/SHA256SUMS" "$RELEASE_URL/SHA256SUMS" \
        || die "cannot fetch the Rust release checksum list; Go remains active"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/release/migrate-go-state.py" "$RELEASE_URL/migrate-go-state.py" \
        || die "the Rust release has no Go migration helper; Go remains active"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/release/$diagnostic_asset" "$RELEASE_URL/$diagnostic_asset" \
        || die "the Rust release has no migration diagnostic helper; Go remains active"
    asset="runman-agent-linux-$ARCH"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/release/$asset" "$RELEASE_URL/$asset" \
        || die "cannot fetch the Rust binary; Go remains active"
    for asset in migrate-go-state.py "$diagnostic_asset" "runman-agent-linux-$ARCH"; do
        [ "$(grep -Ec "  \*?$asset\$" "$WORK/SHA256SUMS")" = 1 ] \
            || die "release checksum list does not contain exactly one entry for $asset"
        (cd "$WORK/release" && grep -E "  \*?$asset\$" "$WORK/SHA256SUMS" | sha256sum -c --quiet -) \
            || die "Rust release checksum mismatch for $asset"
    done
    chmod 755 "$WORK/release/migrate-go-state.py" "$WORK/release/$diagnostic_asset" "$WORK/release/runman-agent-linux-$ARCH"
    "$WORK/release/runman-agent-linux-$ARCH" --version >/dev/null \
        || die "Rust release binary does not run on this host; Go remains active"
    MIGRATION_HELPER="$WORK/release/migrate-go-state.py"

    install -d -m 700 /var/backups
    MIGRATION_DIR=$(mktemp -d /var/backups/runman-go-to-rust-v2.XXXXXXXX)
    chmod 700 "$MIGRATION_DIR"
    printf '{}\n' > "$MIGRATION_DIR/error-state-overrides.json"
    chmod 600 "$MIGRATION_DIR/error-state-overrides.json"
    printf '[]\n' > "$MIGRATION_DIR/orphan-core-exclusions.json"
    chmod 600 "$MIGRATION_DIR/orphan-core-exclusions.json"
    install -m 700 "$WORK/release/$diagnostic_asset" "$MIGRATION_DIR/$diagnostic_asset"
    cp -a "$go_config" "$MIGRATION_DIR/go-config.json"
    migration_backup_go_agent "$go_binary"
    migration_prepare_rfw_repair
    go_unit_path=$(systemctl show -p FragmentPath --value narwhal-agent.service 2>/dev/null || true)
    if [ -n "$go_unit_path" ] && [ -f "$go_unit_path" ]; then
        cp -a "$go_unit_path" "$MIGRATION_DIR/narwhal-agent.service"
    fi
    for host_port in /etc/modules-load.d/runman.conf /etc/sysctl.d/90-runman.conf \
        /etc/systemd/system/lxcfs.service.d/runman.conf; do
        migration_capture_file "$host_port"
    done
    MIGRATION_GO_WAS_ACTIVE=0
    MIGRATION_GO_WAS_ENABLED=0
    MIGRATION_LXCFS_WAS_ACTIVE=0
    MIGRATION_LXCFS_WAS_ENABLED=0
    if systemctl is-active --quiet narwhal-agent.service; then MIGRATION_GO_WAS_ACTIVE=1; fi
    if systemctl is-enabled --quiet narwhal-agent.service; then MIGRATION_GO_WAS_ENABLED=1; fi
    if systemctl is-active --quiet lxcfs.service; then MIGRATION_LXCFS_WAS_ACTIVE=1; fi
    if systemctl is-enabled --quiet lxcfs.service; then MIGRATION_LXCFS_WAS_ENABLED=1; fi

    if migration_export_go_state "$go_config"; then
        :
    else
        local migration_export_status=$?
        if [ "$migration_export_status" -eq 42 ]; then
            migration_confirm_orphan_core_rows
            migration_export_go_state "$go_config" \
                || die "Go migration preflight failed after orphan-row confirmation; Go remains active"
        else
            printf 'Go migration preflight failed; Go remains active. Snapshot: %s\n' "$MIGRATION_DIR" >&2
            printf 'Read-only diagnostic: bash %q %q\n' \
                "$MIGRATION_DIR/$diagnostic_asset" "$MIGRATION_DIR" >&2
            exit 1
        fi
    fi
    cp -a "$MIGRATION_DIR/orphan-core-candidates.json" "$MIGRATION_DIR/pre-confirm-orphan-core-candidates.json"
    MIGRATION_BACKEND=$(cat "$MIGRATION_DIR/source-backend")
    migration_choose_error_states "$go_config"
    WEB_LISTEN=$(cat "$MIGRATION_DIR/web-listen")
    migration_ipv4=$(sed -n 's/^ipv4_subnet = "\([^"]*\)"$/\1/p' "$MIGRATION_DIR/config.toml")
    migration_ipv6_mode=$(sed -n 's/^ipv6_mode = "\([^"]*\)"$/\1/p' "$MIGRATION_DIR/config.toml")
    cp -a "$MIGRATION_DIR/config.toml" "$MIGRATION_DIR/rust-config.toml"
    printf 'Go -> Rust v2 lossy migration\nCreated: %s\nBackend: %s\n' \
        "$(date -Is)" "$MIGRATION_BACKEND" > "$MIGRATION_DIR/README.txt"

    printf '\nThis migration rebuilds clean Alpine/Debian guests and permanently discards their old root filesystems after Rust health checks pass.\n'
    printf 'VM UUIDs, CPU/RAM/disk/bandwidth settings, running/stopped state, and supported TCP/UDP host-to-guest port forwards are retained.\n'
    printf 'Guest data, mounted volumes, installed software, traffic history, WireGuard bindings, custom images, and guest IP addresses are not migrated.\n'
    printf 'If a guest ignores both normal shutdown requests, Incus force-stops that instance as a last resort; unflushed guest writes may be lost.\n'
    printf 'The installer attempts service/config/container rollback on failure. If disk space is below 768 MiB, a second typed confirmation can delete all Go-managed Incus guests before Rust health checks; their parameters/database are backed up, but guest files cannot be restored. Power loss and host package changes cannot be guaranteed reversible.\n'
    if [ "$MIGRATION_RFW_REPAIR_REQUIRED" = 1 ]; then
        printf 'RFW repair detected: the host lacks AVX2 and RFW has repeated recent SIGILL exits. After confirmation, the verified %s binary will replace %s. The API must stay healthy for 15 seconds; if its current XDP mode fails without SIGILL, the installer backs up the unit and retries in SKB mode. A failed retry restores the original binary and unit before Go is stopped.\n' \
            "$MIGRATION_RFW_VERSION" "$MIGRATION_RFW_BIN"
    fi
    orphan_count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1], encoding="utf-8"))))' \
        "$MIGRATION_DIR/orphan-core-candidates.json")
    if [ "$orphan_count" -gt 0 ]; then
        printf 'Confirmed orphan core records excluded from Rust: %s (original rows retained in go-agent.db).\n' "$orphan_count"
    fi
    printf 'Rust will create a new rmbr0 bridge on %s (IPv6 mode: %s); old Podman/Incus bridges are not reused.\n' \
        "${migration_ipv4:-unknown}" "${migration_ipv6_mode:-unknown}"
    printf 'Backup and generated root passwords: %s\n' "$MIGRATION_DIR"
    read -r -p 'Type MIGRATE TO RUST to continue: ' _migration_confirm
    [ "$_migration_confirm" = "MIGRATE TO RUST" ] || die "migration cancelled; Go remains active"

    MIGRATION_ACTIVE=1
    migration_confirm_low_space_cleanup
    if [ "$MIGRATION_RFW_REPAIR_REQUIRED" = 1 ]; then
        migration_apply_rfw_repair \
            || die "RFW replacement failed its 15-second API health check; the original binary will be restored and Go will remain active"
    fi
    # On a low-space recovery path, first save the migration parameters, stop
    # Go and its guests, and delete only the ERROR guests covered by the second
    # confirmation. Their storage is needed to make room for APT and Rust.
    # Normal migrations retain the earlier package preflight ordering.
    if [ "$MIGRATION_GUESTS_PREDELETE_CONFIRMED" != 1 ]; then
        install_host_packages
    fi
    MIGRATION_GO_STOP_ATTEMPTED=1
    log "stopping the Go agent and its managed containers"
    systemctl stop narwhal-agent.service
    systemctl disable narwhal-agent.service >/dev/null
    # Freeze the authoritative DB/config before stopping guests. The first
    # export is a preflight; this final export closes the window in which the
    # Go panel could change instances or forwards while the user confirmed.
    cp -a "$go_config" "$MIGRATION_DIR/go-config.json"
    cp -a "$MIGRATION_DIR/legacy-state.json" "$MIGRATION_DIR/pre-confirm-legacy-state.json"
    "$MIGRATION_HELPER" export --config "$go_config" --output "$MIGRATION_DIR" \
        --error-state-overrides "$MIGRATION_DIR/error-state-overrides.json" \
        --orphan-core-exclusions "$MIGRATION_DIR/orphan-core-exclusions.json" \
        || die "final Go snapshot failed; the old guests remain intact and rollback will restart Go"
    if ! cmp -s "$MIGRATION_DIR/pre-confirm-orphan-core-candidates.json" \
        "$MIGRATION_DIR/orphan-core-candidates.json"; then
        die "orphan Go core rows changed after confirmation; retry migration to review the updated snapshot"
    fi
    if [ "$MIGRATION_BACKEND" = incus ]; then
        if ! python3 - "$MIGRATION_DIR/pre-confirm-legacy-state.json" "$MIGRATION_DIR/legacy-state.json" <<'PY'
import json
import pathlib
import sys

def instance_names(path):
    rows = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("legacy state is not a list of objects")
    names = [str(row.get("name") or "") for row in rows]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise ValueError("legacy state has a missing or duplicate instance name")
    return set(names)

try:
    changed = instance_names(sys.argv[2]) ^ instance_names(sys.argv[1])
except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
    print(f"cannot compare Incus instance set: {exc}", file=sys.stderr)
    raise SystemExit(2)
if changed:
    print(
        "Go-managed Incus instance set changed after confirmation; retry after reviewing: "
        + ", ".join(sorted(changed)),
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
        then
            die "Go-managed Incus instance set changed after confirmation; no legacy guest has been deleted"
        fi
    fi
    MIGRATION_BACKEND=$(cat "$MIGRATION_DIR/source-backend")
    WEB_LISTEN=$(cat "$MIGRATION_DIR/web-listen")
    migration_ipv4=$(sed -n 's/^ipv4_subnet = "\([^"]*\)"$/\1/p' "$MIGRATION_DIR/config.toml")
    migration_ipv6_mode=$(sed -n 's/^ipv6_mode = "\([^"]*\)"$/\1/p' "$MIGRATION_DIR/config.toml")
    cp -a "$MIGRATION_DIR/config.toml" "$MIGRATION_DIR/rust-config.toml"
    printf 'Go -> Rust v2 lossy migration\nCreated: %s\nBackend: %s\n' \
        "$(date -Is)" "$MIGRATION_BACKEND" > "$MIGRATION_DIR/README.txt"
    log "checking and stopping legacy $MIGRATION_BACKEND instances; low-space deletion applies only after an explicit snapshot-based confirmation"
    "$MIGRATION_HELPER" lifecycle stop --backend "$MIGRATION_BACKEND" \
        --state "$MIGRATION_DIR/legacy-state.json"
    if [ "$MIGRATION_GUESTS_PREDELETE_CONFIRMED" = 1 ]; then
        MIGRATION_GUESTS_PREDELETE_ATTEMPTED=1
        "$MIGRATION_HELPER" lifecycle purge-for-space --backend "$MIGRATION_BACKEND" \
            --state "$MIGRATION_DIR/legacy-state.json" \
            --confirmed-state "$MIGRATION_DIR/pre-confirm-legacy-state.json"
        cleanup_incus_cached_images
        install_host_packages
        migration_free_after_delete=$(migration_available_bytes)
        log "low-space cleanup and host package preparation left ${migration_free_after_delete} bytes available"
        [ "$migration_free_after_delete" -ge "$MIGRATION_MIN_FREE_BYTES" ] \
            || die "only ${migration_free_after_delete} bytes remain after deleting confirmed Incus guests and preparing host packages; more disk space is required before Rust image staging"
    fi
    log "legacy Go configuration, database snapshot, root passwords, and host settings saved at $MIGRATION_DIR"
}

# ── uninstall ───────────────────────────────────────────────────────────────

uninstall() {
    local count=0
    if [ -d "$DATA_DIR/instances" ]; then
        count=$(find "$DATA_DIR/instances" -mindepth 1 -maxdepth 1 -type d | wc -l)
    fi
    if [ "$count" -gt 0 ] && [ "$PURGE" != 1 ]; then
        die "$count instance(s) exist on this node; delete them on the platform first, or use --uninstall --purge to destroy them"
    fi
    log "stopping the agent"
    systemctl disable --now runman-agent.service 2>/dev/null || true
    if [ "$PURGE" = 1 ]; then
        log "stopping and deleting all instances"
        systemctl stop 'runman-*.service' 2>/dev/null || true
    fi
    log "removing host networking"
    nft delete table inet runman 2>/dev/null || true
    nft delete table bridge runman 2>/dev/null || true
    local link
    for link in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(rv[0-9]+i?|rw[0-9]+)$' || true); do
        ip link del "$link" 2>/dev/null || true
    done
    # Instance IPv6 addresses are the /128 routes on the bridge; drop the NDP
    # proxy entries the agent kept for them on the uplink.
    local addr uplink
    uplink=$(sed -n 's/^ipv6_ndp_uplink = "\(.*\)"$/\1/p' "$CONFIG" 2>/dev/null || true)
    if [ -n "$uplink" ]; then
        # `ip` prints single-address routes without the /128 suffix.
        for addr in $(ip -6 route show dev rmbr0 2>/dev/null | awk '$1 ~ /:/ && $1 !~ /\// && $1 !~ /^fe80/ {print $1}'); do
            ip -6 neigh del proxy "$addr" dev "$uplink" 2>/dev/null || true
        done
    fi
    ip link del rmbr0 2>/dev/null || true
    local tool dir
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        for dir in -i -o; do
            while "$tool" -w -D FORWARD "$dir" rmbr0 -m comment --comment runman -j ACCEPT 2>/dev/null; do :; done
        done
    done
    local fam rule
    for fam in -4 -6; do
        { ip "$fam" rule show | grep -E 'lookup 20[0-9]{3}' || true; } | while read -r rule; do
            # shellcheck disable=SC2086 # the rule text is split into ip arguments on purpose
            ip "$fam" rule del ${rule#*:} 2>/dev/null || true
        done
    done
    local chain
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null 2>&1 || continue
        for chain in RUNMAN_RS_CLIMIT RUNMAN_RS_RFW_ABUSE; do
            if "$tool" -w -t filter -S "$chain" 2>/dev/null | grep -Fq \
                -e runman-agent-rs-v2 -e runman-agent-rs-v2-abuse; then
                while "$tool" -w -t filter -C FORWARD -j "$chain" 2>/dev/null; do
                    "$tool" -w -t filter -D FORWARD -j "$chain" 2>/dev/null || break
                done
                "$tool" -w -t filter -F "$chain" 2>/dev/null || true
                "$tool" -w -t filter -X "$chain" 2>/dev/null || true
            fi
        done
    done
    if [ -f /etc/systemd/system/rfw.service ]; then
        log "removing rfw"
        systemctl disable --now rfw.service 2>/dev/null || true
        rm -f /etc/systemd/system/rfw.service "$RFW_BIN"
    fi
    rm -f /etc/systemd/system/runman-agent.service /etc/modules-load.d/runman.conf "$BIN" \
        /etc/sysctl.d/90-runman.conf /etc/systemd/system/lxcfs.service.d/runman.conf
    rm -rf "$CONFIG_DIR" /run/runman-agent
    [ ! -S /run/narwhal-agent/connlimit.sock ] || rm -f /run/narwhal-agent/connlimit.sock
    [ ! -S /run/narwhal-agent/firewall.sock ] || rm -f /run/narwhal-agent/firewall.sock
    rmdir /run/narwhal-agent 2>/dev/null || true
    if [ "$PURGE" = 1 ]; then
        local dir
        for dir in "$DATA_DIR"/instances/*/mnt/*; do
            if [ -d "$dir" ]; then umount -l "$dir" 2>/dev/null || true; fi
        done
        rm -rf "$DATA_DIR" "$RFW_DIR"
    fi
    systemctl daemon-reload
    log "uninstalled$([ "$PURGE" = 1 ] && echo ' (instances and data deleted)')"
}

if [ "$UNINSTALL" = 1 ]; then
    uninstall
    exit 0
fi

# The Rust major line has a different configuration, database, and container
# runtime. Never overwrite a live Go node or its release/updater path.
if { [ -f /opt/narwhal-agent/config.json ] || [ -f /opt/narwhal-agent/agent.db ] \
    || [ -f /var/lib/narwhal-agent/agent.db ] \
    || systemctl is-active --quiet narwhal-agent.service 2>/dev/null; } \
    && [ "$MIGRATE_GO" != 1 ] && [ "$CLEANUP_ONLY" != 1 ] \
    && [ "$RFW_REPAIR_ONLY" != 1 ]; then
    die "a Go Runman Agent installation was detected; v2 requires a planned migration and will not take over its Podman/Incus data"
fi

# ── host checks ─────────────────────────────────────────────────────────────

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
    debian:*|ubuntu:*|*:*debian*) ;;
    *) die "unsupported OS ${PRETTY_NAME:-unknown}; Debian 12+/Ubuntu 22.04+ are supported (Debian 13 recommended)" ;;
esac
if command -v systemd-detect-virt >/dev/null && systemd-detect-virt --container --quiet; then
    die "this host is itself a container ($(systemd-detect-virt --container)); a KVM VM or bare metal is required"
fi
[ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] || die "systemd is required"
[ -f /sys/fs/cgroup/cgroup.controllers ] || die "cgroup v2 (unified hierarchy) is required"
kernel=$(uname -r | cut -d- -f1)
[ "$(printf '%s\n%s\n' "$MIN_KERNEL" "$kernel" | sort -V | head -n1)" = "$MIN_KERNEL" ] \
    || die "kernel $kernel is too old; $MIN_KERNEL or newer is required (idmapped mounts)"

if [ "$CLEANUP_ONLY" = 1 ]; then
    cleanup_failed=0
    maintenance_cleanup || cleanup_failed=1
    if [ "$CLEANUP_RUNTIMES" = 1 ]; then
        cleanup_unused_container_runtimes || cleanup_failed=1
    fi
    [ "$cleanup_failed" = 0 ] || die "maintenance cleanup was incomplete; see warnings above"
    exit 0
fi

if [ "$RFW_REPAIR_ONLY" = 1 ]; then
    repair_rfw_only
    exit 0
fi

prepare_go_migration

# ── packages ────────────────────────────────────────────────────────────────

if [ "$HOST_PACKAGES_INSTALLED" = 1 ]; then
    log "required host packages were installed before stopping Go"
else
    install_host_packages
fi

for mod in wireguard ifb sch_cake tcp_bbr; do
    modprobe "$mod" 2>/dev/null || warn "kernel module $mod is unavailable; related features will fail"
done
if [ "$MIGRATION_ACTIVE" = 1 ]; then MIGRATION_MODULES_CONFIG_TOUCHED=1; fi
printf '%s\n' wireguard ifb sch_cake tcp_bbr > /etc/modules-load.d/runman.conf

log "tuning kernel limits"
# Each instance runs a full init. Their inotify instances, keys and neighbour
# entries add up on the host (inotify instances of all instances count against
# one host user: the default of 128 runs out after a handful of instances).
if [ "$MIGRATION_ACTIVE" = 1 ]; then MIGRATION_SYSCTL_CONFIG_TOUCHED=1; fi
cat > /etc/sysctl.d/90-runman.conf <<'SYSCTL'
# Written by the runman installer.
fs.inotify.max_user_instances = 65536
fs.inotify.max_user_watches = 4194304
fs.inotify.max_queued_events = 65536
kernel.keys.maxkeys = 2000
kernel.keys.maxbytes = 2000000
kernel.pid_max = 4194304
vm.max_map_count = 262144
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_thresh3 = 8192
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYSCTL
sysctl -q -p /etc/sysctl.d/90-runman.conf || warn "some kernel settings could not be applied"

# lxcfs gives instances their own /proc/meminfo, cpuinfo, uptime and load
# (CPU count from the CPU quota, load average per instance).
lxcfs_dropin=/etc/systemd/system/lxcfs.service.d/runman.conf
lxcfs_conf=$(printf '[Service]\nExecStart=\nExecStart=/usr/bin/lxcfs --enable-cfs -l /var/lib/lxcfs')
if [ "$(cat "$lxcfs_dropin" 2>/dev/null)" != "$lxcfs_conf" ]; then
    if [ "$MIGRATION_ACTIVE" = 1 ]; then MIGRATION_LXCFS_CONFIG_TOUCHED=1; fi
    install -d /etc/systemd/system/lxcfs.service.d
    printf '%s\n' "$lxcfs_conf" > "$lxcfs_dropin"
    systemctl daemon-reload
    # Restarting lxcfs detaches the views of running instances until they
    # restart, so only do it when its options actually change.
    systemctl restart lxcfs.service
fi
systemctl enable --now lxcfs.service >/dev/null 2>&1 || warn "lxcfs is not running; instances will see host-wide /proc values"

# ── binaries ────────────────────────────────────────────────────────────────

[ -n "$WORK" ] || WORK=$(mktemp -d /tmp/runman-agent-rust-v2.XXXXXXXX)
trap cleanup_exit EXIT

fetch() { # fetch <name> <dest> <base-url>; --from-dir wins when it has the file
    if [ -n "$FROM_DIR" ] && [ -f "$FROM_DIR/$1" ]; then
        cp "$FROM_DIR/$1" "$2"
    else
        curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$3/$1"
    fi
}

asset="runman-agent-linux-$ARCH"
log "fetching $asset"
fetch SHA256SUMS "$WORK/SHA256SUMS" "$RELEASE_URL" || die "cannot fetch SHA256SUMS"
fetch "$asset" "$WORK/$asset" "$RELEASE_URL" || die "cannot fetch $asset"
(cd "$WORK" && grep -E "  \*?$asset\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $asset"
is_elf_for_arch "$WORK/$asset" || die "$asset is not a binary for $ARCH"
chmod 755 "$WORK/$asset"
"$WORK/$asset" --version >/dev/null || die "$asset does not run on this host"
install -m 755 "$WORK/$asset" "$BIN.new"
mv -f "$BIN.new" "$BIN"
log "installed $("$BIN" --version)"

# ── configuration ───────────────────────────────────────────────────────────

FRESH=0
PASSWORD=""
if [ "$MIGRATE_GO" = 1 ]; then
    log "installing migrated Rust configuration"
    install -d -m 700 "$CONFIG_DIR"
    cp -a "$MIGRATION_DIR/rust-config.toml" "$CONFIG"
    chmod 600 "$CONFIG"
elif [ ! -f "$CONFIG" ]; then
    FRESH=1
    log "writing $CONFIG"
    if [ "$IPV6" = auto ]; then
        log "detecting IPv6 (this briefly tests one address of the prefix)"
        ipv6_conf=$("$BIN" detect-ipv6) || { warn "IPv6 detection failed; using none"; ipv6_conf='ipv6_mode = "none"'; }
    elif [ "$IPV6" = subnet ]; then
        ipv6_conf=$(printf 'ipv6_mode = "subnet"\nipv6_prefix = "%s"\nipv6_ndp_uplink = "%s"' "$IPV6_PREFIX" "$IPV6_UPLINK")
    else
        ipv6_conf="ipv6_mode = \"$IPV6\""
    fi
    install -d -m 700 "$CONFIG_DIR"
    umask 077
    cat > "$CONFIG" <<EOF
# Runman agent configuration. Most settings take effect after
# \`systemctl restart runman-agent\`; instances keep running across restarts.
platform_url = "$PLATFORM_URL"
data_dir = "$DATA_DIR"
backend = "container"
web_listen = "$WEB_LISTEN"
bandwidth_mbps = $BANDWIDTH
rfw_addr = "$RFW_API"

[network]
$ipv6_conf
EOF
    umask 022
    PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)
    printf '%s\n' "$PASSWORD" | "$BIN" --config "$CONFIG" set-password >/dev/null
else
    log "keeping existing $CONFIG"
fi
# Tokens are only ever issued by the platform; none means standalone mode.
if [ -n "$TOKEN" ]; then
    "$BIN" --config "$CONFIG" set-token "$TOKEN" >/dev/null
fi

# ── rfw ─────────────────────────────────────────────────────────────────────

rfw_ready() {
    local _
    for _ in $(seq 1 "$1"); do
        curl -fsS "http://$RFW_API/api/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

install_rfw() {
    local iface=$RFW_IFACE fresh_rfw=0 asset sums_file
    [ -n "$iface" ] || iface=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    [ -n "$iface" ] || { warn "no IPv4 default route; skipping rfw (use --rfw-iface)"; return 0; }
    asset=$(rfw_asset_for_host)
    log "installing $asset on $iface"
    sums_file="$WORK/rfw-SHA256SUMS"
    if ! fetch SHA256SUMS "$sums_file" "$RFW_URL"; then
        warn "cannot download RFW checksums; continuing without it"
        return 0
    fi
    if ! fetch "$asset" "$WORK/$asset" "$RFW_URL"; then
        warn "cannot download rfw; continuing without it"
        return 0
    fi
    [ "$(grep -Ec "  \*?$asset\$" "$sums_file")" = 1 ] \
        || { warn "RFW release checksum list does not contain exactly one entry for $asset; skipping"; return 0; }
    (cd "$WORK" && grep -E "  \*?$asset\$" "$sums_file" | sha256sum -c --quiet -) \
        || { warn "RFW checksum mismatch for $asset; skipping"; return 0; }
    is_elf_for_arch "$WORK/$asset" || { warn "RFW asset is not a binary for $ARCH; skipping"; return 0; }
    install -m 755 "$WORK/$asset" "$RFW_BIN.new"
    mv -f "$RFW_BIN.new" "$RFW_BIN"
    install -d -m 700 "$RFW_DIR"
    [ -f /etc/systemd/system/rfw.service ] || fresh_rfw=1
    write_rfw_unit "$iface" ""
    systemctl daemon-reload
    systemctl enable rfw.service >/dev/null 2>&1
    systemctl restart rfw.service
    if ! rfw_ready 10; then
        # Some virtual NICs reject native XDP; the generic SKB mode works everywhere.
        warn "rfw did not start in native XDP mode; retrying in SKB mode"
        write_rfw_unit "$iface" "--xdp-mode skb"
        systemctl daemon-reload
        systemctl restart rfw.service
        rfw_ready 15 || { warn "rfw is not responding; see journalctl -u rfw"; return 0; }
    fi
    if [ "$fresh_rfw" = 1 ] && [ "$(curl -fsS "http://$RFW_API/api/rules")" = "[]" ]; then
        log "adding default rfw rules"
        local proto port
        for proto in http socks5 fet; do
            rfw_rule "{\"priority\":100,\"direction\":\"in\",\"protocol\":\"$proto\",\"action\":\"block\",\"port_start\":0,\"enabled\":true,\"ip_type\":\"geoip\",\"countries\":[\"CN\"]}"
        done
        for port in 25 465 587; do
            rfw_rule "{\"priority\":100,\"direction\":\"out\",\"protocol\":\"tcp\",\"action\":\"block\",\"port_start\":$port,\"enabled\":true,\"ip_type\":\"any\"}"
        done
    fi
}

write_rfw_unit() { # write_rfw_unit <iface> <extra args>
    cat > /etc/systemd/system/rfw.service <<EOF
[Unit]
Description=rfw eBPF firewall
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$RFW_DIR
ExecStart=$RFW_BIN --iface $1 --api-addr $RFW_API $2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

rfw_rule() {
    curl -fsS -X POST -H 'Content-Type: application/json' -d "$1" "http://$RFW_API/api/rules" >/dev/null \
        || warn "failed to add rfw rule $1"
}

if [ "$WITH_RFW" = 1 ]; then
    install_rfw
fi

# ── service ─────────────────────────────────────────────────────────────────

log "starting runman-agent"
cat > /etc/systemd/system/runman-agent.service <<EOF
[Unit]
Description=Runman node agent
After=network-online.target nftables.service lxcfs.service
Wants=network-online.target lxcfs.service

[Service]
ExecStart=$BIN --config $CONFIG
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable runman-agent.service >/dev/null 2>&1
if [ "$MIGRATE_GO" = 1 ]; then
    log "rebuilding clean Rust guests from the verified Go migration manifest"
    "$BIN" --config "$CONFIG" import-go-manifest "$MIGRATION_DIR/manifest.json"
    systemctl start runman-agent.service
else
    systemctl restart runman-agent.service
fi

if [ -n "$WEB_LISTEN" ]; then
    port=${WEB_LISTEN##*:}
    for _ in $(seq 1 20); do
        curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
        sleep 1
    done
fi
systemctl is-active --quiet runman-agent.service || die "runman-agent failed to start; see journalctl -u runman-agent"

if [ "$MIGRATE_GO" = 1 ]; then
    log "verifying migrated instance identities, prior run states, and port forwards"
    health_ok=0
    network_targets="$MIGRATION_DIR/network-targets.tsv"
    for _ in $(seq 1 30); do
        inventory_http_status=$(curl --silent --show-error --max-time 3 \
            --unix-socket /run/narwhal-agent/connlimit.sock \
            http://localhost/v1/inventory -o "$MIGRATION_DIR/live-inventory.json" \
            -w '%{http_code}' 2>/dev/null || true)
        if [ "$inventory_http_status" = 200 ]; then
            if python3 - "$MIGRATION_DIR/manifest.json" "$MIGRATION_DIR/legacy-state.json" \
                "$MIGRATION_DIR/live-inventory.json" "$DATA_DIR/portforwards.json" "$network_targets" \
                "$migration_ipv6_mode" <<'PY'
import ipaddress, json, pathlib, sys
manifest, legacy, inventory = [json.loads(pathlib.Path(p).read_text()) for p in sys.argv[1:4]]
ipv6_mode = sys.argv[6]
if inventory.get('schema') != 1 or not isinstance(inventory.get('items'), list):
    print('invalid Rust inventory schema', file=sys.stderr)
    raise SystemExit(1)
expected = {item['vm_id']: item['was_running'] for item in manifest['instances']}
actual = {item.get('id'): item.get('running') is True for item in inventory['items'] if isinstance(item, dict)}
if set(actual) != set(expected) or actual != expected:
    print(f'instance identity/state mismatch: expected {len(expected)}, got {len(actual)}', file=sys.stderr)
    raise SystemExit(1)
forward_path = pathlib.Path(sys.argv[4])
stored = json.loads(forward_path.read_text()) if forward_path.exists() else []
normalize = lambda row: (row['vm_id'], row.get('protocol', row.get('proto')), row['host_port'], row['guest_port'])
if sorted(map(normalize, stored)) != sorted(map(normalize, manifest['port_forwards'])):
    print(f'port-forward mismatch: expected {len(manifest["port_forwards"])}, got {len(stored)}', file=sys.stderr)
    raise SystemExit(1)
targets = []
for item in inventory['items']:
    if not isinstance(item, dict):
        continue
    if expected.get(item.get('id')) is not True:
        continue
    pid = item.get('init_pid')
    if not isinstance(pid, int) or pid <= 0:
        print(f"running instance {item.get('id')} has no valid init PID", file=sys.stderr)
        raise SystemExit(1)
    try:
        ipv4 = next(str(ipaddress.ip_address(address)) for address in item.get('ips', [])
                    if ipaddress.ip_address(address).version == 4)
    except (StopIteration, ValueError, TypeError):
        print(f"running instance {item.get('id')} has no valid IPv4 address", file=sys.stderr)
        raise SystemExit(1)
    ipv6 = ""
    if ipv6_mode in {"snat", "subnet"}:
        try:
            ipv6 = next(str(ipaddress.ip_address(address)) for address in item.get('ips', [])
                        if ipaddress.ip_address(address).version == 6)
        except (StopIteration, ValueError, TypeError):
            print(f"running instance {item.get('id')} has no valid IPv6 address", file=sys.stderr)
            raise SystemExit(1)
    targets.append(f"{item['id']}\t{pid}\t{ipv4}\t{ipv6}")
pathlib.Path(sys.argv[5]).write_text(''.join(row + '\n' for row in targets))
PY
            then
                health_ok=1
                break
            fi
            break
        elif [ "$inventory_http_status" != 000 ]; then
            chmod 600 "$MIGRATION_DIR/live-inventory.json" 2>/dev/null || true
            inventory_error=$(python3 - "$MIGRATION_DIR/live-inventory.json" <<'PY'
import json, pathlib, sys
try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text())
    message = value.get('message', '') if isinstance(value, dict) else ''
except Exception:
    message = ''
print(' '.join(str(message).split())[:240])
PY
)
            warn "Rust local inventory returned HTTP $inventory_http_status${inventory_error:+: $inventory_error}"
            break
        fi
        sleep 1
    done
    [ "$health_ok" = 1 ] || die "Rust migration inventory or port-forward verification failed"
    if [ -s "$network_targets" ]; then
        dns_probe="$MIGRATION_DIR/dns-probe.py"
        cat > "$dns_probe" <<'PY'
import ipaddress
import secrets
import socket
import struct
import sys

name = "one.one.one.one"
transaction_id = int.from_bytes(secrets.token_bytes(2), "big")
question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0\0\1\0\1"
query = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question
server = ipaddress.ip_address(sys.argv[1].split("%", 1)[0])
family = socket.AF_INET if server.version == 4 else socket.AF_INET6
destination = (str(server), 53) if server.version == 4 else (str(server), 53, 0, 0)
with socket.socket(family, socket.SOCK_DGRAM) as client:
    client.settimeout(3)
    client.sendto(query, destination)
    response, _ = client.recvfrom(2048)
if len(response) < 12:
    raise SystemExit("short DNS response")
reply_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
if reply_id != transaction_id or flags & 0x000F or answers < 1:
    raise SystemExit("invalid DNS response")
PY
        chmod 600 "$dns_probe"
        while IFS=$'\t' read -r vm_id guest_pid guest_ipv4 guest_ipv6; do
            if [ -z "$vm_id" ] || ! [[ "$guest_pid" =~ ^[0-9]+$ ]]; then
                die "Rust migration network inventory is invalid; Go rollback will run"
            fi
            [ -r "/proc/$guest_pid/ns/net" ] \
                || die "migrated guest $vm_id has no live network namespace; Go rollback will run"
            resolv_conf="/proc/$guest_pid/root/etc/resolv.conf"
            [ -r "$resolv_conf" ] \
                || die "migrated guest $vm_id has no readable /etc/resolv.conf; Go rollback will run"
            log "checking route, configured DNS, and IPv4 HTTPS for migrated guest $vm_id"
            route_ok=0
            for _ in $(seq 1 20); do
                host_route=$(ip -4 route get "$guest_ipv4" 2>/dev/null || true)
                guest_route=$(nsenter --target "$guest_pid" --net -- ip -4 route get 1.1.1.1 2>/dev/null || true)
                if [[ " $host_route " == *" dev rmbr0 "* \
                    && " $guest_route " == *" via "* && " $guest_route " == *" dev eth0 "* ]]; then
                    if [ "$migration_ipv6_mode" = none ]; then
                        route_ok=1
                    elif [ -n "$guest_ipv6" ]; then
                        host_route6=$(ip -6 route get "$guest_ipv6" 2>/dev/null || true)
                        guest_route6=$(nsenter --target "$guest_pid" --net -- \
                            ip -6 route get 2606:4700:4700::1111 2>/dev/null || true)
                        if [[ " $host_route6 " == *" dev rmbr0 "* \
                            && " $guest_route6 " == *" via "* \
                            && " $guest_route6 " == *" dev eth0 "* ]]; then
                            route_ok=1
                        fi
                    fi
                    if [ "$route_ok" = 1 ]; then break; fi
                fi
                sleep 1
            done
            [ "$route_ok" = 1 ] \
                || die "migrated guest $vm_id does not route through rmbr0/eth0 (host: ${host_route:-missing}; guest: ${guest_route:-missing}; IPv6 host: ${host_route6:-skipped}; IPv6 guest: ${guest_route6:-skipped}); Go rollback will run"

            guest_dns_servers=$(awk '$1 == "nameserver" && NF >= 2 {print $2}' "$resolv_conf" | awk '!seen[$0]++')
            [ -n "$guest_dns_servers" ] \
                || die "migrated guest $vm_id has no nameserver in /etc/resolv.conf; Go rollback will run"
            dns_ok=0
            dns_server_ok=""
            while IFS= read -r dns_server; do
                [ -n "$dns_server" ] || continue
                if nsenter --target "$guest_pid" --net -- python3 "$dns_probe" "$dns_server" >/dev/null 2>&1; then
                    dns_ok=1
                    dns_server_ok=$dns_server
                    break
                fi
            done <<< "$guest_dns_servers"
            [ "$dns_ok" = 1 ] \
                || die "migrated guest $vm_id cannot resolve via any configured DNS server (${guest_dns_servers//$'\n'/, }); Go rollback will run"
            log "migrated guest $vm_id resolved through configured DNS server $dns_server_ok"

            egress_ok=0
            for _ in $(seq 1 10); do
                if nsenter --target "$guest_pid" --net -- env \
                -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy \
                curl -4 -fsS --connect-timeout 2 --max-time 4 \
                    --resolve one.one.one.one:443:1.1.1.1 \
                    https://one.one.one.one/ -o /dev/null 2>/dev/null; then
                    egress_ok=1
                    break
                fi
                sleep 1
            done
            [ "$egress_ok" = 1 ] \
                || die "migrated guest $vm_id cannot reach IPv4 HTTPS through rmbr0; Go rollback will run"

            if [ "$migration_ipv6_mode" != none ]; then
                ipv6_egress_ok=0
                for _ in $(seq 1 10); do
                    if nsenter --target "$guest_pid" --net -- env \
                    -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy \
                    curl -6 -fsS --connect-timeout 2 --max-time 4 \
                        --resolve 'one.one.one.one:443:[2606:4700:4700::1111]' \
                        https://one.one.one.one/ -o /dev/null 2>/dev/null; then
                        ipv6_egress_ok=1
                        break
                    fi
                    sleep 1
                done
                [ "$ipv6_egress_ok" = 1 ] \
                    || die "migrated guest $vm_id cannot reach IPv6 HTTPS in $migration_ipv6_mode mode; Go rollback will run"
            fi
        done < "$network_targets"
        log "verified routes, configured DNS, and IPv4 HTTPS egress for every running migrated guest"
    else
        log "no guests were running before migration; guest egress probe skipped"
    fi
    if [ -n "$WEB_LISTEN" ]; then
        host_port=${WEB_LISTEN##*:}
        web_host=${WEB_LISTEN%:*}
        case "$web_host" in
            ""|0.0.0.0) web_health_url="http://127.0.0.1:$host_port/" ;;
            "::"|"[::]"|"[::1]") web_health_url="http://[::1]:$host_port/" ;;
            \[*\]) web_health_url="http://$web_host:$host_port/" ;;
            *) web_health_url="http://$web_host:$host_port/" ;;
        esac
        for _ in $(seq 1 20); do
            curl -fsS -o /dev/null --max-time 2 "$web_health_url" 2>/dev/null && break
            sleep 1
        done
        curl -fsS -o /dev/null --max-time 3 "$web_health_url" \
            || die "Rust panel did not become healthy; Go rollback will run"
    fi

    MIGRATION_COMMITTED=1
    log "Rust health and port checks passed; removing old Go guest root filesystems"
    if "$MIGRATION_HELPER" lifecycle purge --backend "$MIGRATION_BACKEND" \
        --state "$MIGRATION_DIR/legacy-state.json"; then
        legacy_db=$(cat "$MIGRATION_DIR/source-db-path")
        [ ! -f /opt/narwhal-agent/config.json ] || mv /opt/narwhal-agent/config.json "$MIGRATION_DIR/legacy-config-original.json" \
            || warn "could not move the old config; a backup copy is retained"
        [ ! -f "$legacy_db" ] || mv "$legacy_db" "$MIGRATION_DIR/legacy-agent-original.db" \
            || warn "could not move the old database; a consistent snapshot is retained"
        [ ! -f /opt/narwhal-agent/narwhal-agent ] || mv /opt/narwhal-agent/narwhal-agent "$MIGRATION_DIR/legacy-agent-original" \
            || warn "could not move the old Go binary"
        log "legacy guest cleanup completed; original config/DB snapshots remain at $MIGRATION_DIR"
        MIGRATION_CLEANUP_RUNTIMES=1
    else
        warn "Rust migration succeeded, but some old guests could not be removed. The Go service stays disabled and cleanup is pending; inspect $MIGRATION_DIR"
    fi
fi

# Keep host and guest logs bounded after the new agent has passed health checks.
maintenance_cleanup || warn "installation succeeded, but some maintenance cleanup steps failed"
if [ "$MIGRATION_CLEANUP_RUNTIMES" = 1 ]; then
    cleanup_unused_container_runtimes
fi

public_ip=$(curl -4 -fsS --max-time 8 https://api-ipv4.ip.sb/ip 2>/dev/null || echo '<this-host>')
echo
log "done"
echo "  agent:   $("$BIN" --version), $(grep -E '^ipv6_mode' "$CONFIG" | head -n1 || echo 'ipv6_mode = none')"
if [ -n "$WEB_LISTEN" ]; then
    case "$WEB_LISTEN" in
        127.*|\[::1\]*) echo "  panel:   http://$WEB_LISTEN (local only; use: ssh -L ${WEB_LISTEN##*:}:$WEB_LISTEN root@$public_ip)" ;;
        *) echo "  panel:   http://$public_ip:${WEB_LISTEN##*:}" ;;
    esac
fi
if [ "$FRESH" = 1 ]; then
    echo "  login:   admin / $PASSWORD"
fi
if grep -qE '^token = ".+"' "$CONFIG"; then
    echo "  mode:    platform (connects to $(sed -n 's/^platform_url = "\(.*\)"$/\1/p' "$CONFIG"))"
else
    echo "  mode:    standalone (no platform token; manage instances in the panel)"
    echo "           connect later: runman-agent set-token '<token from the platform>' && systemctl restart runman-agent"
fi
echo "  OS images are downloaded in the background on first start (journalctl -fu runman-agent)."
if [ "$MIGRATE_GO" = 1 ]; then
    echo "  migration: Go guest files were rebuilt; generated root passwords are in $MIGRATION_DIR/root-passwords.txt (root-only)"
    echo "  rollback:  Go config/database snapshot and migration state are in $MIGRATION_DIR"
fi
