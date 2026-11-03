"""Guard the Go-to-Rust migration's empty-host preflight behavior."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "migrate_go_state", ROOT / "scripts" / "migrate-go-state.py"
)
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)
HOST_NETWORKS = MIGRATION.host_networks


class GoRustEmptyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="runman-go-rust-migration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db_path = self.root / "agent.db"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(
                """
                CREATE TABLE vm_configs (
                    vm_id TEXT, cpu INTEGER, memory_mb INTEGER, disk_gb INTEGER,
                    bandwidth_mbps INTEGER, image TEXT
                );
                CREATE TABLE podman_vm_configs (vm_id TEXT, container TEXT);
                CREATE TABLE port_forwards (
                    vm_id TEXT, protocol TEXT, host_port INTEGER,
                    guest_port INTEGER, description TEXT
                );
                """
            )
            conn.commit()
        finally:
            conn.close()
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps({"virt_type": "podman", "db": str(self.db_path), "web": "off"}),
            encoding="utf-8",
        )
        self.output = self.root / "migration"
        self.networks = {4: set(), 6: set()}
        network_patch = patch.object(
            MIGRATION, "host_networks", side_effect=lambda version: self.networks[version]
        )
        network_patch.start()
        self.addCleanup(network_patch.stop)

    def run_export(self):
        connections = []
        real_connect = sqlite3.connect

        def tracked_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch.object(sqlite3, "connect", side_effect=tracked_connect):
            try:
                MIGRATION.export(SimpleNamespace(config=self.config, output=self.output))
            finally:
                for connection in connections:
                    connection.close()

    def test_empty_database_and_empty_podman_inventory_export_host_only_manifest(self):
        with patch.object(MIGRATION, "backend_inventory", return_value=set()):
            self.run_export()

        manifest = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        legacy_state = json.loads((self.output / "legacy-state.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["instances"], [])
        self.assertEqual(manifest["port_forwards"], [])
        self.assertEqual(legacy_state, [])

    def test_empty_database_with_untracked_podman_container_is_rejected(self):
        with patch.object(MIGRATION, "backend_inventory", return_value={"untracked-vm"}):
            with self.assertRaisesRegex(SystemExit, "inventory contains 1 container"):
                self.run_export()

    def test_duplicate_canonical_vm_identities_are_rejected(self):
        vm_id = "550e8400-e29b-41d4-a716-446655440000"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO vm_configs VALUES (?, 1, 128, 1, 0, 'debian')",
                (vm_id,),
            )
            conn.execute(
                "INSERT INTO vm_configs VALUES (?, 1, 128, 1, 0, 'debian')",
                (vm_id.upper(),),
            )
            conn.commit()
        finally:
            conn.close()

        with patch.object(MIGRATION, "backend_inventory", return_value=set()):
            with self.assertRaisesRegex(SystemExit, "duplicate VM identities in vm_configs"):
                self.run_export()

    def test_migration_network_selection_avoids_legacy_bridge_routes_and_stays_stable(self):
        self.networks[4].add(ipaddress.ip_network("10.91.0.0/20"))
        self.networks[6].add(ipaddress.ip_network("fd91:cafe:cafe:10::/64"))

        first = MIGRATION.migration_network_selection(self.output, "snat")
        second = MIGRATION.migration_network_selection(self.output, "snat")

        self.assertEqual(first, ("10.91.16.0/20", "fd91:cafe:cafe:11::/64"))
        self.assertEqual(second, first)
        if os.name == "posix":
            self.assertEqual((self.output / "network-selection.json").stat().st_mode & 0o777, 0o600)

    def test_export_writes_conflict_free_networks_into_rust_config(self):
        self.networks[4].add(ipaddress.ip_network("10.91.0.0/20"))
        self.networks[6].add(ipaddress.ip_network("fd91:cafe:cafe:10::/64"))
        self.config.write_text(
            json.dumps({"virt_type": "podman", "db": str(self.db_path), "web": "off", "ipv6_mode": "snat"}),
            encoding="utf-8",
        )

        with patch.object(MIGRATION, "backend_inventory", return_value=set()):
            self.run_export()

        rust_config = (self.output / "config.toml").read_text(encoding="utf-8")
        self.assertIn('ipv4_subnet = "10.91.16.0/20"', rust_config)
        self.assertIn('ipv6_snat_prefix = "fd91:cafe:cafe:11::/64"', rust_config)

    def test_host_network_inventory_includes_routes_and_interface_addresses(self):
        output = {
            ("ip", "-j", "-4", "route", "show", "table", "all"): json.dumps(
                [{"dst": "10.91.0.0/20"}, {"dst": "default"}]
            ),
            ("ip", "-j", "-4", "address", "show"): json.dumps(
                [{"addr_info": [{"local": "192.168.8.2", "prefixlen": 24}]}]
            ),
        }
        with patch.object(MIGRATION, "checked_run", side_effect=lambda args: output[tuple(args)]):
            networks = HOST_NETWORKS(4)

        self.assertEqual(
            networks,
            {ipaddress.ip_network("10.91.0.0/20"), ipaddress.ip_network("192.168.8.0/24")},
        )

    def test_network_selection_aborts_if_saved_subnet_becomes_occupied(self):
        selected = MIGRATION.migration_network_selection(self.output, "none")
        self.networks[4].add(ipaddress.ip_network(selected[0]))

        with self.assertRaisesRegex(SystemExit, "now overlaps a host route"):
            MIGRATION.migration_network_selection(self.output, "none")


if __name__ == "__main__":
    unittest.main()
