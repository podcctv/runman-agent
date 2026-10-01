"""Exercise installer network functions with sandboxed Netavark files and tools."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")


def function_source(name):
    return name + "() {" + SOURCE.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


class PodmanDNSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="runman-dns-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "bin").mkdir()
        self.network = self.root / "narwhal-net.json"
        self.config = self.root / "config.json"
        self.calls = self.root / "calls"
        self.original = {
            "name": "narwhal-net", "dns_enabled": True,
            "subnets": [{"subnet": "10.91.0.0/20", "gateway": "10.91.0.1"}],
            "options": {"snat_ipv6": "false", "custom": "preserve-me"},
        }
        self.network.write_text(json.dumps(self.original, separators=(",", ":")))
        self.network.chmod(0o640)
        self.tool("podman", '''
printf 'podman %s\\n' "$*" >> "$TEST_ROOT/calls"
case "$1 $2" in
  'network exists') test "${TEST_EXISTS:-1}" = 1 ;;
  'network create') printf '{"name":"narwhal-net","dns_enabled":false,"options":{}}' > "$TEST_ROOT/narwhal-net.json" ;;
  *) exit 90 ;;
esac
''')
        self.functions = self.root / "functions.sh"
        functions = (
            function_source("disable_podman_network_dns")
            + function_source("ensure_podman_network_from_config"))
        self.functions.write_text(functions.replace(
            "/etc/containers/networks/${PODMAN_NETWORK}.json", "$TEST_ROOT/narwhal-net.json"),
            encoding="utf-8", newline="\n")

    def tool(self, name, body):
        path = self.root / "bin" / name
        path.write_text("#!/bin/bash\nset -e\n" + body + "\n", encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def run_shell(self, action, **env):
        result = subprocess.run([os.environ.get("RUNMAN_TEST_BASH", "bash"), "-c", '''
set -e
if command -v cygpath >/dev/null 2>&1; then
    TEST_ROOT=$(cygpath -u "$TEST_ROOT")
fi
export PATH="$TEST_ROOT/bin:$PATH"
PODMAN_NETWORK=narwhal-net
AGENT_CONFIG_FILE="$TEST_ROOT/config.json"
t() { printf '%s\\n' "$1"; }
log() { printf '%s\\n' "$1"; }
die() { printf '%s\\n' "$1" >&2; exit 1; }
source "$TEST_ROOT/functions.sh"
''' + action], env=dict(os.environ, TEST_ROOT=self.root.as_posix(), **env),
            text=True, encoding="utf-8", capture_output=True, timeout=15)
        return result

    def test_compact_json_preserves_other_options_and_permissions(self):
        result = self.run_shell("disable_podman_network_dns")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(self.original, dns_enabled=False)
        self.assertEqual(json.loads(self.network.read_text()), expected)
        if os.name != "nt":
            self.assertEqual(self.network.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.root.glob("narwhal-net.json.*")), [])

    def test_already_disabled_config_is_not_rewritten(self):
        self.network.write_text(json.dumps(dict(self.original, dns_enabled=False)))
        before = self.network.read_bytes()
        result = self.run_shell("disable_podman_network_dns")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.network.read_bytes(), before)

    def test_invalid_json_keeps_original_and_reports_failure(self):
        for content in ("{broken", "[]", "null"):
            with self.subTest(content=content):
                self.network.write_text(content)
                result = self.run_shell("disable_podman_network_dns")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Failed to disable Podman internal DNS", result.stderr)
                self.assertEqual(self.network.read_text(), content)
                self.assertEqual(list(self.root.glob("narwhal-net.json.*")), [])

    def test_missing_network_config_reports_failure(self):
        self.network.unlink()
        result = self.run_shell("disable_podman_network_dns")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Podman network config not found", result.stderr)

    def test_existing_network_is_migrated_without_recreation(self):
        self.config.write_text(json.dumps({"virt_type": "podman"}))
        result = self.run_shell("ensure_podman_network_from_config")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(self.network.read_text())["dns_enabled"])
        self.assertNotIn("network create", self.calls.read_text())

    def test_rebuild_disables_dns_for_every_ipv6_mode(self):
        for mode in ("none", "snat", "subnet"):
            with self.subTest(mode=mode):
                self.config.write_text(json.dumps({
                    "virt_type": "podman", "ipv6_mode": mode,
                    "ipv6_subnet": "2001:db8:100::/64",
                }))
                self.calls.write_text("")
                result = self.run_shell("ensure_podman_network_from_config", TEST_EXISTS="0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("network create --driver=bridge --disable-dns", self.calls.read_text())
                if mode == "subnet":
                    self.assertEqual(json.loads(self.network.read_text())["options"]["snat_ipv6"], "false")

    def test_fresh_network_disables_dns_for_every_ipv6_mode(self):
        block = "if podman network exists" + SOURCE.rsplit("\nif podman network exists", 1)[1].split(
            "\ninstall_podman_forwarding_compat", 1)[0]
        block = block.replace("/etc/containers/networks/${PODMAN_NETWORK}.json", "$TEST_ROOT/narwhal-net.json")
        for mode in ("none", "snat", "subnet"):
            with self.subTest(mode=mode):
                self.calls.write_text("")
                action = '''
IPV6_MODE="%s"
IPV6_ADDR=2001:db8:100::1
IPV6_PREFIX=64
IPV6_IFACE=eth0
IPV6_ROUTED=1
''' % mode + block
                result = self.run_shell(action, TEST_EXISTS="0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("--disable-dns", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
