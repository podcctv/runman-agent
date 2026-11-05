import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "patch-ring-legacy-cpu.py"
SPEC = importlib.util.spec_from_file_location("patch_ring_legacy_cpu", SCRIPT)
PATCHER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PATCHER)


class PatchRingLegacyCpuTests(unittest.TestCase):
    def make_ring_source(self, version="0.17.12"):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        (root / "Cargo.toml").write_text(
            f'[package]\nname = "ring"\nversion = "{version}"\n',
            encoding="utf-8",
        )
        source_dir = root / "crypto"
        source_dir.mkdir()
        source = source_dir / "cpu_intel.c"
        source.write_text(
            "  extended_features[0] = ebx;\n"
            "  OPENSSL_ia32cap_P[2] = extended_features[0];\n",
            encoding="utf-8",
        )
        return root, source

    def test_masks_avx2_before_exporting_cpu_features_and_is_idempotent(self):
        root, source_path = self.make_ring_source()

        self.assertTrue(PATCHER.patch_ring_source(root))
        patched = source_path.read_text(encoding="utf-8")
        self.assertIn("extended_features[0] &= ~(1u << 5);", patched)
        self.assertLess(
            patched.index("extended_features[0] &= ~(1u << 5);"),
            patched.index("OPENSSL_ia32cap_P[2] = extended_features[0];"),
        )
        self.assertFalse(PATCHER.patch_ring_source(root))

    def test_rejects_other_ring_versions(self):
        root, _ = self.make_ring_source(version="0.17.14")

        with self.assertRaisesRegex(ValueError, "only supports ring 0.17.12"):
            PATCHER.patch_ring_source(root)


if __name__ == "__main__":
    unittest.main()
