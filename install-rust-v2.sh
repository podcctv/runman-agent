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
WORK=""

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

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

migration_rollback() {
    local failed=0 record id
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
    migration_restore_file /etc/modules-load.d/runman.conf || failed=1
    migration_restore_file /etc/sysctl.d/90-runman.conf || failed=1
    migration_restore_file /etc/systemd/system/lxcfs.service.d/runman.conf || failed=1
    systemctl daemon-reload >/dev/null 2>&1 || failed=1
    sysctl --system >/dev/null 2>&1 || true
    # Restore lxcfs before restarting the old guests so they mount its views
    # with the original service configuration.
    if [ "$MIGRATION_LXCFS_WAS_ACTIVE" = 1 ]; then
        systemctl restart lxcfs.service >/dev/null 2>&1 || failed=1
    else
        systemctl stop lxcfs.service >/dev/null 2>&1 || true
    fi
    if [ "$MIGRATION_LXCFS_WAS_ENABLED" = 1 ]; then
        systemctl enable lxcfs.service >/dev/null 2>&1 || failed=1
    else
        systemctl disable lxcfs.service >/dev/null 2>&1 || true
    fi
    if [ -x "$MIGRATION_HELPER" ] && [ -f "$MIGRATION_DIR/legacy-state.json" ]; then
        "$MIGRATION_HELPER" lifecycle start --backend "$MIGRATION_BACKEND" \
            --state "$MIGRATION_DIR/legacy-state.json" || failed=1
    fi
    if [ "$MIGRATION_GO_WAS_ENABLED" = 1 ]; then
        systemctl enable narwhal-agent.service >/dev/null 2>&1 || failed=1
    else
        systemctl disable narwhal-agent.service >/dev/null 2>&1 || true
    fi
    if [ "$MIGRATION_GO_WAS_ACTIVE" = 1 ]; then
        systemctl start narwhal-agent.service >/dev/null 2>&1 || failed=1
    fi
    if [ "$failed" = 1 ]; then
        printf 'Automatic rollback could not confirm every restoration. Review %s and systemd/container logs.\n' "$MIGRATION_DIR" >&2
    else
        printf 'Go service state and pre-existing containers were restored.\n' >&2
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
    local work backup_dir had_conf=0 failed=0
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
                $1 == "SystemMaxUse" { system_max=$2 }
                $1 == "RuntimeMaxUse" { runtime_max=$2 }
                $1 == "SystemKeepFree" { system_keep_free=$2 }
                $1 == "MaxRetentionSec" { max_retention=$2 }
                $1 == "MaxFileSec" { max_file=$2 }
                END { exit !(system_max == "512M" && runtime_max == "128M" && system_keep_free == "1G" && max_retention == "7day" && max_file == "1day") }
            ' "$work/effective.conf"; then
            if [ "$had_conf" = 1 ]; then cp -a "$work/original.conf" "$conf"; else rm -f "$conf"; fi
            warn "journald rejected the 7-day retention configuration; restored its previous drop-in"
            failed=1
        elif ! systemctl restart systemd-journald.service; then
            if [ "$had_conf" = 1 ]; then cp -a "$work/original.conf" "$conf"; else rm -f "$conf"; fi
            systemctl restart systemd-journald.service >/dev/null 2>&1 || true
            warn "journald could not restart; restored its previous drop-in"
            failed=1
        else
            log "applied 7-day journald retention (512M persistent, 128M runtime cap)"
        fi
    fi

    if [ "$failed" = 0 ]; then
        journalctl --rotate || { warn "could not rotate the active journal"; failed=1; }
        journalctl --vacuum-time=7d || { warn "could not vacuum journals older than 7 days"; failed=1; }
    fi

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
        [ -n "$home" ] && [ "$home" != /nonexistent ] || continue
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
    if ! podman pod ps --all --quiet >"$work/pods" 2>&1; then
        warn "could not inventory Podman pods; keeping Podman"
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
            if ! incus storage volume list local: "$pool" "type=$volume_type" \
                --all-projects -c t,n --format csv,noheader >"$work/volumes-$count" 2>&1; then
                warn "could not inventory Incus $volume_type volumes in pool $pool; keeping Incus"
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
                          optionally rfw-<arch>) instead of downloading them
  --migrate-go            Lossy clean-rebuild migration from a supported Go Podman/Incus node;
                          keeps a rollback snapshot until Rust health and port checks pass
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
    local asset go_unit_path host_port
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

    WORK=$(mktemp -d)
    mkdir -p "$WORK/release"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/SHA256SUMS" "$RELEASE_URL/SHA256SUMS" \
        || die "cannot fetch the Rust release checksum list; Go remains active"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/release/migrate-go-state.py" "$RELEASE_URL/migrate-go-state.py" \
        || die "the Rust release has no Go migration helper; Go remains active"
    asset="runman-agent-linux-$ARCH"
    curl -fsSL --retry 3 --connect-timeout 20 -o "$WORK/release/$asset" "$RELEASE_URL/$asset" \
        || die "cannot fetch the Rust binary; Go remains active"
    for asset in migrate-go-state.py "runman-agent-linux-$ARCH"; do
        [ "$(grep -Ec "  \*?$asset\$" "$WORK/SHA256SUMS")" = 1 ] \
            || die "release checksum list does not contain exactly one entry for $asset"
        (cd "$WORK/release" && grep -E "  \*?$asset\$" "$WORK/SHA256SUMS" | sha256sum -c --quiet -) \
            || die "Rust release checksum mismatch for $asset"
    done
    chmod 755 "$WORK/release/migrate-go-state.py" "$WORK/release/runman-agent-linux-$ARCH"
    "$WORK/release/runman-agent-linux-$ARCH" --version >/dev/null \
        || die "Rust release binary does not run on this host; Go remains active"
    MIGRATION_HELPER="$WORK/release/migrate-go-state.py"

    install -d -m 700 /var/backups
    MIGRATION_DIR=$(mktemp -d /var/backups/runman-go-to-rust-v2.XXXXXXXX)
    chmod 700 "$MIGRATION_DIR"
    cp -a "$go_config" "$MIGRATION_DIR/go-config.json"
    cp -a "$go_binary" "$MIGRATION_DIR/go-agent"
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

    "$MIGRATION_HELPER" export --config "$go_config" --output "$MIGRATION_DIR" \
        || die "Go migration preflight failed; Go remains active"
    MIGRATION_BACKEND=$(cat "$MIGRATION_DIR/source-backend")
    WEB_LISTEN=$(cat "$MIGRATION_DIR/web-listen")
    cp -a "$MIGRATION_DIR/config.toml" "$MIGRATION_DIR/rust-config.toml"
    printf 'Go -> Rust v2 lossy migration\nCreated: %s\nBackend: %s\n' \
        "$(date -Is)" "$MIGRATION_BACKEND" > "$MIGRATION_DIR/README.txt"

    printf '\nThis migration rebuilds clean Alpine/Debian guests and permanently discards their old root filesystems after Rust health checks pass.\n'
    printf 'VM UUIDs, CPU/RAM/disk/bandwidth settings, running/stopped state, and supported TCP/UDP host-to-guest port forwards are retained.\n'
    printf 'Guest data, mounted volumes, installed software, traffic history, WireGuard bindings, custom images, and guest IP addresses are not migrated.\n'
    printf 'A failed install/import/health check triggers service/config/container rollback before old guests are deleted. Power loss and every host package change cannot be guaranteed reversible.\n'
    printf 'Backup and generated root passwords: %s\n' "$MIGRATION_DIR"
    read -r -p 'Type MIGRATE TO RUST to continue: ' _migration_confirm
    [ "$_migration_confirm" = "MIGRATE TO RUST" ] || die "migration cancelled; Go remains active"

    MIGRATION_ACTIVE=1
    trap cleanup_exit EXIT
    log "stopping the Go agent and its managed containers"
    systemctl stop narwhal-agent.service
    systemctl disable narwhal-agent.service >/dev/null
    # Freeze the authoritative DB/config before stopping guests. The first
    # export is a preflight; this final export closes the window in which the
    # Go panel could change instances or forwards while the user confirmed.
    cp -a "$go_config" "$MIGRATION_DIR/go-config.json"
    "$MIGRATION_HELPER" export --config "$go_config" --output "$MIGRATION_DIR" \
        || die "final Go snapshot failed; the old guests remain intact and rollback will restart Go"
    MIGRATION_BACKEND=$(cat "$MIGRATION_DIR/source-backend")
    WEB_LISTEN=$(cat "$MIGRATION_DIR/web-listen")
    cp -a "$MIGRATION_DIR/config.toml" "$MIGRATION_DIR/rust-config.toml"
    printf 'Go -> Rust v2 lossy migration\nCreated: %s\nBackend: %s\n' \
        "$(date -Is)" "$MIGRATION_BACKEND" > "$MIGRATION_DIR/README.txt"
    "$MIGRATION_HELPER" lifecycle stop --backend "$MIGRATION_BACKEND" \
        --state "$MIGRATION_DIR/legacy-state.json"
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
    && [ "$MIGRATE_GO" != 1 ] && [ "$CLEANUP_ONLY" != 1 ]; then
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
    maintenance_cleanup || die "maintenance cleanup was incomplete; see warnings above"
    if [ "$CLEANUP_RUNTIMES" = 1 ]; then cleanup_unused_container_runtimes; fi
    exit 0
fi

prepare_go_migration

# ── packages ────────────────────────────────────────────────────────────────

log "installing packages"
# Wait for other apt/dpkg runs (e.g. unattended-upgrades) instead of killing them.
apt_get() { LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q "$@"; }
apt_get update >/dev/null
apt_get install --no-install-recommends \
    ca-certificates curl iproute2 iptables nftables wireguard-tools e2fsprogs tar gzip zstd util-linux kmod lxcfs >/dev/null

for mod in wireguard ifb sch_cake tcp_bbr; do
    modprobe "$mod" 2>/dev/null || warn "kernel module $mod is unavailable; related features will fail"
done
printf '%s\n' wireguard ifb sch_cake tcp_bbr > /etc/modules-load.d/runman.conf

log "tuning kernel limits"
# Each instance runs a full init. Their inotify instances, keys and neighbour
# entries add up on the host (inotify instances of all instances count against
# one host user: the default of 128 runs out after a handful of instances).
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
    install -d /etc/systemd/system/lxcfs.service.d
    printf '%s\n' "$lxcfs_conf" > "$lxcfs_dropin"
    systemctl daemon-reload
    # Restarting lxcfs detaches the views of running instances until they
    # restart, so only do it when its options actually change.
    systemctl restart lxcfs.service
fi
systemctl enable --now lxcfs.service >/dev/null 2>&1 || warn "lxcfs is not running; instances will see host-wide /proc values"

# ── binaries ────────────────────────────────────────────────────────────────

[ -n "$WORK" ] || WORK=$(mktemp -d)
trap cleanup_exit EXIT

fetch() { # fetch <name> <dest> <base-url>; --from-dir wins when it has the file
    if [ -n "$FROM_DIR" ] && [ -f "$FROM_DIR/$1" ]; then
        cp "$FROM_DIR/$1" "$2"
    else
        curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$3/$1"
    fi
}

is_elf_for_arch() { # the file must be a 64-bit ELF for this machine
    local want
    want=$([ "$ARCH" = amd64 ] && echo 3e00 || echo b700)
    [ "$(head -c 6 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c460201 ] \
        && [ "$(dd if="$1" bs=1 skip=18 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$want" ]
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
    local iface=$RFW_IFACE fresh_rfw=0
    [ -n "$iface" ] || iface=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    [ -n "$iface" ] || { warn "no IPv4 default route; skipping rfw (use --rfw-iface)"; return 0; }
    log "installing rfw on $iface"
    if ! fetch "rfw-$ARCH" "$WORK/rfw" "$RFW_URL"; then
        warn "cannot download rfw; continuing without it"
        return 0
    fi
    is_elf_for_arch "$WORK/rfw" || { warn "rfw download is not a binary for $ARCH; skipping"; return 0; }
    install -m 755 "$WORK/rfw" "$RFW_BIN.new"
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
    for _ in $(seq 1 30); do
        inventory_http_status=$(curl --silent --show-error --max-time 3 \
            --unix-socket /run/narwhal-agent/connlimit.sock \
            http://localhost/v1/inventory -o "$MIGRATION_DIR/live-inventory.json" \
            -w '%{http_code}' 2>/dev/null || true)
        if [ "$inventory_http_status" = 200 ]; then
            if python3 - "$MIGRATION_DIR/manifest.json" "$MIGRATION_DIR/legacy-state.json" \
                "$MIGRATION_DIR/live-inventory.json" "$DATA_DIR/portforwards.json" <<'PY'
import json, pathlib, sys
manifest, legacy, inventory = [json.loads(pathlib.Path(p).read_text()) for p in sys.argv[1:4]]
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
