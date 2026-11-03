"""Guard the Go-to-Rust migration's empty-host preflight behavior."""
import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
