#!/usr/bin/env python3
"""Export and manage the deliberately limited Go -> Rust clean-rebuild migration."""

import argparse
import csv
import io
import ipaddress
import itertools
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import uuid
from pathlib import Path


DEFAULT_CONFIG = Path("/opt/narwhal-agent/config.json")
DEFAULT_DB = Path("/opt/narwhal-agent/agent.db")
MAX_DB_BYTES = 2 * 1024 * 1024 * 1024
INCUS_STOP_TIMEOUT = 120
DEFAULT_SNAT6_PREFIX = "fd91:cafe:cafe:10::/64"


def fail(message):
    raise SystemExit(message)


def checked_run(args, *, capture=True, timeout=45):
    try:
        result = subprocess.run(args, check=False, text=True, capture_output=capture, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"cannot run {args[0]}: {exc}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[-500:]
        fail(f"{args[0]} failed ({result.returncode}): {detail}")
    return result.stdout.strip() if capture else ""


def read_config(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read Go config: {exc}")
    if not isinstance(value, dict):
        fail("Go config must be a JSON object")
    backend = str(value.get("virt_type") or "").strip().lower()
    if backend not in {"podman", "incus"}:
        fail(f"unsupported Go backend {backend!r}; only Podman and Incus containers can be migrated")
    return value, backend


def table_rows(conn, table):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if table not in tables:
        fail(f"Go database table {table!r} is missing")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f'SELECT * FROM "{table}"')]
    except sqlite3.Error as exc:
        fail(f"cannot read Go database table {table!r}: {exc}")


def column(row, name, default=None):
    wanted = name.lower()
    return next((value for key, value in row.items() if key.lower() == wanted), default)


def bounded_int(value, label, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        fail(f"Go {label} value {value!r} is not an integer")
    if not minimum <= parsed <= maximum:
        fail(f"Go {label} value {parsed} is outside the supported range {minimum}..{maximum}")
    return parsed


def canonical_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        fail(f"invalid VM UUID in Go database: {value!r}")


def live_state(backend, name):
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
        fail(f"unsupported legacy container name {name!r}")
    if backend == "podman":
        result = checked_run(["podman", "inspect", "--format", "{{.State.Running}}", name])
        if result not in {"true", "false"}:
            fail(f"Podman returned an unrecognized state for {name}")
        return result == "true"
    result = checked_run(
        ["incus", "list", "--format", "csv,noheader", "--columns", "n,s,p", name]
    )
    try:
        rows = list(csv.reader(io.StringIO(result)))
    except csv.Error as exc:
        fail(f"Incus returned invalid state data for {name}: {exc}")
    if len(rows) != 1 or len(rows[0]) != 3 or rows[0][0] != name:
        fail(f"Incus did not return one unambiguous instance state for {name}")
    status = rows[0][1].strip().lower()
    if status not in {"running", "stopped"}:
        fail(
            f"Incus instance {name} is in {status.upper()} state; "
            "migration supports only Running or Stopped instances"
        )
    if status == "stopped":
        return False
    try:
        init_pid = int(rows[0][2])
    except ValueError:
        fail(f"Incus reports {name} as Running but returned an invalid init PID")
    if init_pid <= 1:
        fail(f"Incus reports {name} as Running with invalid init PID {init_pid}")
    return True


def backend_inventory(backend):
    if backend == "podman":
        output = checked_run(["podman", "ps", "--all", "--format", "{{.Names}}"])
    else:
        output = checked_run(["incus", "list", "--format", "csv", "-c", "n"])
    return {line.strip() for line in output.splitlines() if line.strip()}


def toml_string(value):
    return json.dumps(str(value), ensure_ascii=False)


def write_private(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def host_networks(version):
    family = f"-{version}"
    networks = set()
    try:
        routes = json.loads(checked_run(["ip", "-j", family, "route", "show", "table", "all"]))
        addresses = json.loads(checked_run(["ip", "-j", family, "address", "show"]))
    except (json.JSONDecodeError, TypeError) as exc:
        fail(f"could not inventory host IPv{version} routes: {exc}")
    if not isinstance(routes, list) or not isinstance(addresses, list):
        fail(f"host IPv{version} network inventory has an unexpected format")

    for route in routes:
        if not isinstance(route, dict):
            continue
        destination = route.get("dst")
        if not destination or destination == "default":
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version == version and network.prefixlen > 0:
            networks.add(network)

    for interface in addresses:
        if not isinstance(interface, dict):
            continue
        for address in interface.get("addr_info", []):
            if not isinstance(address, dict):
                continue
            local = address.get("local")
            prefixlen = address.get("prefixlen")
            if not local or not isinstance(prefixlen, int):
                continue
            try:
                network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
            except ValueError:
                continue
            if network.version == version:
                networks.add(network)
    return networks


def choose_ipv4_subnet(existing):
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    preferred = ipaddress.ip_network("10.91.0.0/20")
    ten_subnets = tuple(private_ranges[0].subnets(new_prefix=20))
    preferred_index = ten_subnets.index(preferred)
    candidates = itertools.chain(
        (preferred,),
        ten_subnets[preferred_index + 1 :],
        ten_subnets[:preferred_index],
        private_ranges[1].subnets(new_prefix=20),
        private_ranges[2].subnets(new_prefix=20),
    )
    for candidate in candidates:
        if not any(candidate.overlaps(network) for network in existing):
            return str(candidate)
    fail("no unused RFC1918 /20 is available for the migrated Rust guests")


def choose_ipv6_snat_prefix(existing):
    units = itertools.chain((0x10,), range(0x11, 0x10000), range(1, 0x10))
    for unit in units:
        candidate = ipaddress.ip_network(f"fd91:cafe:cafe:{unit:x}::/64")
        if not any(candidate.overlaps(network) for network in existing):
            return str(candidate)
    fail("no unused fd91:cafe:cafe::/48 ULA /64 is available for IPv6 SNAT")


def migration_network_selection(output, ipv6_mode):
    plan_path = output / "network-selection.json"
    ipv4_routes = host_networks(4)
    ipv6_routes = host_networks(6) if ipv6_mode == "snat" else set()
    if plan_path.exists():
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            ipv4 = ipaddress.ip_network(plan["ipv4_subnet"], strict=False)
            ipv6 = ipaddress.ip_network(plan["ipv6_snat_prefix"], strict=False)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            fail(f"saved migration network selection is invalid: {exc}")
        private_ranges = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
        if ipv4.prefixlen != 20 or ipv4.version != 4 or not any(ipv4.subnet_of(net) for net in private_ranges):
            fail("saved migration IPv4 subnet is not an RFC1918 /20")
        if (
            ipv6.prefixlen != 64
            or ipv6.version != 6
            or (ipv6.network_address.packed[0] & 0xFE) != 0xFC
        ):
            fail("saved migration IPv6 SNAT network is not a ULA /64")
        if any(ipv4.overlaps(network) for network in ipv4_routes):
            fail(f"saved migration IPv4 subnet {ipv4} now overlaps a host route")
        if ipv6_mode == "snat" and any(ipv6.overlaps(network) for network in ipv6_routes):
            fail(f"saved migration IPv6 prefix {ipv6} now overlaps a host route")
        return str(ipv4), str(ipv6)

    ipv4 = choose_ipv4_subnet(ipv4_routes)
    ipv6 = choose_ipv6_snat_prefix(ipv6_routes) if ipv6_mode == "snat" else DEFAULT_SNAT6_PREFIX
    plan = {"ipv4_subnet": ipv4, "ipv6_snat_prefix": ipv6}
    write_private(plan_path, json.dumps(plan, separators=(",", ":")) + "\n")
    return ipv4, ipv6


def export(args):
    cfg, backend = read_config(args.config)
    db_path = Path(str(cfg.get("db") or DEFAULT_DB))
    if not db_path.is_absolute():
        db_path = args.config.parent / db_path
    if not db_path.is_file() or db_path.stat().st_size > MAX_DB_BYTES:
        fail("Go SQLite database is missing or exceeds the 2 GiB migration limit")

    backup_db = args.output / "go-agent.db"
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=20)
        integrity = source.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            fail("Go database integrity_check failed")
        target = sqlite3.connect(backup_db)
        source.backup(target)
        backup_integrity = target.execute("PRAGMA integrity_check").fetchone()
        target.close()
        source.close()
        if not backup_integrity or backup_integrity[0] != "ok":
            fail("Go SQLite snapshot failed integrity_check")
        os.chmod(backup_db, 0o600)
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=20)
    except sqlite3.Error as exc:
        fail(f"cannot snapshot Go database: {exc}")

    base_rows = table_rows(conn, "vm_configs")
    provider_table = "podman_vm_configs" if backend == "podman" else "incus_vm_configs"
    provider_rows = table_rows(conn, provider_table)
    base_ids = [canonical_uuid(column(row, "vm_id")) for row in base_rows]
    provider_ids = [canonical_uuid(column(row, "vm_id")) for row in provider_rows]
    if len(set(base_ids)) != len(base_rows):
        fail("Go database has duplicate VM identities in vm_configs")
    if len(set(provider_ids)) != len(provider_rows):
        fail(f"Go database has duplicate VM identities in {provider_table}")
    base_by_id = dict(zip(base_ids, base_rows))
    provider_by_id = dict(zip(provider_ids, provider_rows))
    if set(provider_by_id) != set(base_by_id):
        fail("Go core instance rows do not exactly match the selected backend rows")

    managed_names = []
    for row in provider_rows:
        name = str(column(row, "container") or "").strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
            fail(f"Go database has an invalid {backend} container name {name!r}")
        managed_names.append(name)
    if len(set(managed_names)) != len(managed_names):
        fail(f"Go database maps multiple VM identities to the same {backend} container name")

    inventory = backend_inventory(backend)
    managed_set = set(managed_names)
    unmanaged = inventory - managed_set
    if unmanaged:
        fail(
            f"{backend} inventory contains {len(unmanaged)} container(s) without matching Go database records; "
            "refusing migration because their ownership cannot be proven"
        )
    missing = managed_set - inventory
    if missing:
        fail(
            f"Go database references {len(missing)} {backend} container(s) missing from the live inventory"
        )
    if not base_rows:
        print("Go database and backend inventory are empty; proceeding with host-only migration")

    instances = []
    legacy_state = []
    passwords = ["VM UUID\tnew root password (root-only; guest data is rebuilt)\n"]
    for vm_id, row in base_by_id.items():
        provider = provider_by_id[vm_id]
        name = str(column(provider, "container") or "").strip()
        if not name:
            fail(f"backend container name is missing for {vm_id}")
        running = live_state(backend, name)
        image = str(column(row, "image") or column(provider, "image") or "").strip().lower()
        if image == "alpine" or image.startswith("alpine/") or image.startswith("alpine-"):
            os_image = "alpine"
        elif image == "debian" or image.startswith("debian/") or image.startswith("debian-"):
            os_image = "debian"
        else:
            fail(f"image {image!r} for {vm_id} is not a supported stock Alpine/Debian family")
        password = secrets.token_urlsafe(20)
        instances.append({
            "vm_id": vm_id,
            "cpu": bounded_int(column(row, "cpu", 1), "CPU", 1, 256),
            "ram_mb": bounded_int(column(row, "memory_mb", 128), "memory_mb", 128, 1_048_576),
            "disk_gb": bounded_int(column(row, "disk_gb", 1), "disk_gb", 1, 65_536),
            "bandwidth_mbps": bounded_int(column(row, "bandwidth_mbps", 0), "bandwidth_mbps", 0, 10_000_000),
            "os_image": os_image,
            "root_password": password,
            "was_running": running,
        })
        legacy_state.append({"name": name, "was_running": running})
        passwords.append(f"{vm_id}\t{password}\n")

    forwards = []
    for row in table_rows(conn, "port_forwards"):
        vm_id = canonical_uuid(column(row, "vm_id"))
        if vm_id not in base_by_id:
            fail(f"port forward references unknown VM {vm_id}")
        protocol = str(column(row, "protocol") or "").lower()
        host_port = int(column(row, "host_port", 0) or 0)
        guest_port = int(column(row, "guest_port", 0) or 0)
        if protocol not in {"tcp", "udp"} or not (1 <= host_port <= 65535 and 1 <= guest_port <= 65535):
            fail(f"unsupported port-forward row for {vm_id}")
        forwards.append({
            "vm_id": vm_id,
            "protocol": protocol,
            "host_port": host_port,
            "guest_port": guest_port,
            "description": str(column(row, "description") or "")[:200],
        })
    conn.close()

    manifest = {"schema": 1, "source_backend": backend, "instances": instances, "port_forwards": forwards}
    write_private(args.output / "manifest.json", json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n")
    write_private(args.output / "legacy-state.json", json.dumps(legacy_state, separators=(",", ":")) + "\n")
    write_private(args.output / "root-passwords.txt", "".join(passwords))
    write_private(args.output / "source-backend", backend + "\n")
    write_private(args.output / "source-db-path", str(db_path) + "\n")

    web = str(cfg.get("web") or ":8792").strip()
    if web.startswith(":"):
        web = "0.0.0.0" + web
    if web in {"", "off", "disabled"}:
        web = ""
    if web and not re.fullmatch(r"(?:[0-9.]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", web):
        fail(f"unsupported Go web listen address {web!r}")
    write_private(args.output / "web-listen", web + "\n")
    port_limit = int(cfg.get("max_port_forward") or 20)
    if not 0 <= port_limit <= 65535:
        fail("Go max_port_forward must be between 0 and 65535")
    day = int(cfg.get("traffic_reset_day") or 1)
    if not 1 <= day <= 28:
        fail("Go traffic_reset_day must be between 1 and 28")
    password_hash = str(cfg.get("web_pass_hash") or "")
    if web and not re.match(r"^\$2[aby]\$[0-9]{2}\$", password_hash):
        fail("Go panel password is not a supported bcrypt hash; migration stopped before host changes")
    ipv6_mode = str(cfg.get("ipv6_mode") or "none").lower()
    if ipv6_mode not in {"none", "snat", "subnet"}:
        fail(f"unsupported Go IPv6 mode {ipv6_mode!r}")
    ipv6_prefix = str(cfg.get("ipv6_subnet") or "") if ipv6_mode == "subnet" else ""
    if ipv6_mode == "subnet" and not ipv6_prefix:
        fail("Go subnet IPv6 mode has no prefix")
    ndp_uplink = str(cfg.get("ndp_iface") or cfg.get("ipv6_iface") or "") if ipv6_mode == "subnet" else ""
    if ndp_uplink and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", ndp_uplink):
        fail("unsupported Go IPv6 uplink interface name")
    ipv4_subnet, ipv6_snat_prefix = migration_network_selection(args.output, ipv6_mode)
    rfw_addr = str(cfg.get("rfw_addr") or "127.0.0.1:7734")
    if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", rfw_addr):
        fail("unsupported Go RFW API address")

    rust_config = "\n".join([
        "# Generated by the Runman Go -> Rust lossy migration.",
        f"platform_url = {toml_string('https://hosting.fuckip.me:443')}",
        f"token = {toml_string(cfg.get('token') or '')}",
        f"host = {toml_string(cfg.get('host') or '')}",
        'virt_label = "container"',
        'data_dir = "/var/lib/runman-agent"',
        'backend = "container"',
        'image_base_url = "https://github.com/narwhal-cloud/runman-agent-rs/releases/download/images"',
        "tun = true",
        'traffic_reset_mode = "fixed"',
        f"traffic_reset_day = {day}",
        'traffic_timezone = "+00:00"',
        f"max_forwards = {port_limit}",
        "bandwidth_mbps = 0",
        f"web_listen = {toml_string(web)}",
        f"web_user = {toml_string(cfg.get('web_user') or 'admin')}",
        f"web_password_hash = {toml_string(password_hash)}",
        f"rfw_addr = {toml_string(rfw_addr)}",
        'update_url = "https://github.com/podcctv/runman-agent/releases/download/continuous-rs"',
        "auto_update = true",
        "",
        "[network]",
        'bridge = "rmbr0"',
        f"ipv4_subnet = {toml_string(ipv4_subnet)}",
        f"ipv6_mode = {toml_string(ipv6_mode)}",
        f"ipv6_prefix = {toml_string(ipv6_prefix)}",
        f"ipv6_ndp_uplink = {toml_string(ndp_uplink)}",
        f"ipv6_snat_prefix = {toml_string(ipv6_snat_prefix)}",
        'dns = ["1.1.1.1", "8.8.8.8"]',
        'veth_prefix = "rv"',
        'wg_prefix = "rw"',
        "wg_table_base = 20000",
        'nft_table = "runman"',
        "",
    ])
    write_private(args.output / "config.toml", rust_config)
    db_copy = args.output / "go-agent.db"
    try:
        shutil.copystat(db_path, db_copy)
        os.chmod(db_copy, 0o600)
    except OSError:
        pass
    print(f"exported {len(instances)} instance(s), {len(forwards)} port forward(s), backend={backend}")


def state_file(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read saved legacy container state: {exc}")
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        fail("saved legacy container state is invalid")
    return value


def lifecycle(args):
    rows = state_file(args.state)
    backend = args.backend
    if backend not in {"podman", "incus"}:
        fail("invalid legacy backend")
    if args.action == "stop":
        failed_name = ""
        try:
            for row in rows:
                if row.get("was_running") is not True:
                    continue
                name = str(row.get("name") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
                    fail(f"unsupported legacy container name {name!r}")
                failed_name = name
                # A previous stop may have completed even if its client timed
                # out. Make this phase idempotent before retrying a stop.
                if not live_state(backend, name):
                    continue
                if backend == "podman":
                    checked_run(["podman", "stop", "--time", "20", name])
                else:
                    # Give guests more time for a clean shutdown. Keep the
                    # client timeout longer than Incus's own shutdown timeout.
                    try:
                        checked_run(
                            ["incus", "stop", name, "--timeout", str(INCUS_STOP_TIMEOUT)],
                            timeout=INCUS_STOP_TIMEOUT + 30,
                        )
                    except SystemExit as stop_error:
                        # Incus can report a timed-out stop after the guest
                        # actually reached Stopped. Continue only when that
                        # state is independently confirmed.
                        try:
                            stopped = not live_state(backend, name)
                        except SystemExit as state_error:
                            fail(f"{name}: stop failed ({stop_error}); state check failed ({state_error})")
                        if not stopped:
                            raise stop_error
        except SystemExit as exc:
            restore_errors = []
            for row in rows:
                if row.get("was_running") is not True:
                    continue
                name = str(row.get("name") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
                    restore_errors.append(f"invalid saved name {name!r}")
                    continue
                try:
                    if live_state(backend, name):
                        continue
                    command = ["podman", "start", name] if backend == "podman" else ["incus", "start", name]
                    checked_run(command)
                except SystemExit as restore_exc:
                    restore_errors.append(f"{name}: {restore_exc}")
            if restore_errors:
                message = f"{exc}; stop rollback was incomplete: " + "; ".join(restore_errors)
                if backend == "incus" and failed_name:
                    message += (
                        f"; inspect with `incus info --show-log {failed_name}` "
                        "and do not force-stop or delete the instance"
                    )
                fail(message)
            if backend == "incus" and failed_name:
                fail(
                    f"{failed_name}: {exc}; inspect with `incus info --show-log {failed_name}` "
                    "and do not force-stop or delete the instance"
                )
            raise
        return
    if args.action == "start":
        errors = []
        for row in rows:
            if row.get("was_running") is not True:
                continue
            name = str(row.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
                errors.append(f"invalid saved name {name!r}")
                continue
            try:
                if live_state(backend, name):
                    continue
            except SystemExit as exc:
                errors.append(f"{name}: {exc}")
                continue
            command = ["podman", "start", name] if backend == "podman" else ["incus", "start", name]
            result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=45)
            if result.returncode != 0:
                errors.append(f"{name}: {(result.stderr or result.stdout or '').strip()[-300:]}")
        if errors:
            fail("could not restore all previously running Go containers: " + "; ".join(errors))
        return
    if args.action == "purge":
        errors = []
        for row in rows:
            name = str(row.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,200}", name):
                errors.append(f"invalid saved name {name!r}")
                continue
            command = ["podman", "rm", "--force", name] if backend == "podman" else ["incus", "delete", name, "--force"]
            result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=120)
            if result.returncode != 0:
                errors.append(f"{name}: {(result.stderr or result.stdout or '').strip()[-300:]}")
        if errors:
            fail("old guest cleanup incomplete: " + "; ".join(errors))
        print(f"removed {len(rows)} legacy guest container(s); images and host volumes were retained")
        return


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    export_parser = sub.add_parser("export")
    export_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    export_parser.add_argument("--output", type=Path, required=True)
    export_parser.set_defaults(func=export)
    life = sub.add_parser("lifecycle")
    life.add_argument("action", choices=["stop", "start", "purge"])
    life.add_argument("--backend", required=True, choices=["podman", "incus"])
    life.add_argument("--state", type=Path, required=True)
    life.set_defaults(func=lifecycle)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
