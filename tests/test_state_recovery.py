from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


state_mod = load_module("veramesh_state_recovery", ROOT / "payload" / "bin" / "veramesh_state.py")


class StaleTempRecoveryTests(unittest.TestCase):
    def _paths(self, td: str) -> tuple[Path, Path]:
        parent = Path(td) / "state"
        parent.mkdir(mode=0o700)
        final = parent / "scaffold-state.json"
        return final, final.with_name(final.name + ".new")

    def test_complete_exact_stale_temp_is_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            tmp.write_bytes(state_mod._canonical_bytes(state_mod.DEFAULT_STATE))
            os.chmod(tmp, 0o600)
            result = state_mod.initialize(final)
            self.assertEqual(state_mod.DEFAULT_STATE, result)
            self.assertTrue(final.is_file())
            self.assertFalse(tmp.exists())
            self.assertEqual(state_mod._canonical_bytes(state_mod.DEFAULT_STATE), final.read_bytes())

    def test_partial_stale_temp_is_safely_removed_and_fresh_state_created(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            tmp.write_bytes(b'{"schema":"VERA_MESH_SCAFFOLD_STATE_V1"')
            os.chmod(tmp, 0o600)
            result = state_mod.initialize(final)
            self.assertEqual(state_mod.DEFAULT_STATE, result)
            self.assertTrue(final.is_file())
            self.assertFalse(tmp.exists())
            self.assertEqual(state_mod._canonical_bytes(state_mod.DEFAULT_STATE), final.read_bytes())

    def test_empty_stale_temp_is_safely_removed_and_fresh_state_created(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            tmp.write_bytes(b"")
            os.chmod(tmp, 0o600)
            result = state_mod.initialize(final)
            self.assertEqual(state_mod.DEFAULT_STATE, result)
            self.assertFalse(tmp.exists())

    def test_symlink_temp_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            target = Path(td) / "target"
            target.write_bytes(b"do-not-touch")
            tmp.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "temporary state path"):
                state_mod.initialize(final)
            self.assertEqual(b"do-not-touch", target.read_bytes())
            self.assertTrue(tmp.is_symlink())
            self.assertFalse(final.exists())

    def test_directory_temp_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            tmp.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "temporary state path"):
                state_mod.initialize(final)
            self.assertTrue(tmp.is_dir())
            self.assertFalse(final.exists())

    def test_broad_mode_temp_is_rejected_and_not_deleted(self):
        with tempfile.TemporaryDirectory() as td:
            final, tmp = self._paths(td)
            tmp.write_bytes(state_mod._canonical_bytes(state_mod.DEFAULT_STATE))
            os.chmod(tmp, 0o644)
            before = tmp.read_bytes()
            with self.assertRaisesRegex(ValueError, "mode"):
                state_mod.initialize(final)
            self.assertTrue(tmp.is_file())
            self.assertEqual(before, tmp.read_bytes())
            self.assertFalse(final.exists())

    def test_exact_legacy_scaffold_is_archived_with_lifecycle_then_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            final, _ = self._paths(td)
            parent = final.parent
            final.write_bytes(state_mod._canonical_bytes(state_mod.LEGACY_SCAFFOLD_STATE_V1))
            lifecycle = parent / "lifecycle-state.json"
            lock = parent / "lifecycle.lock"
            lifecycle.write_bytes(b'{"legacy":"lifecycle"}\n')
            lock.write_bytes(b"")
            for path in (final, lifecycle, lock):
                os.chmod(path, 0o600)

            result = state_mod.initialize(final)
            self.assertEqual(state_mod.DEFAULT_STATE, result)
            archive = state_mod._legacy_archive_path(parent)
            self.assertTrue((archive / "scaffold-state.json").is_file())
            self.assertTrue((archive / "lifecycle-state.json").is_file())
            self.assertTrue((archive / "lifecycle.lock").is_file())
            self.assertTrue((archive / "MIGRATION_RECEIPT.json").is_file())
            receipt = json.loads((archive / "MIGRATION_RECEIPT.json").read_text())
            self.assertEqual("VERA_MESH_LEGACY_MIGRATION_RECEIPT_V1", receipt["schema"])
            self.assertEqual("VERA_MESH_SCAFFOLD_STATE_V1", receipt["source"])
            self.assertEqual(state_mod.DEFAULT_STATE, state_mod.read_state(final))
            self.assertFalse(lifecycle.exists())
            self.assertFalse(lock.exists())

    def test_unknown_predecessor_is_rejected_without_migration(self):
        with tempfile.TemporaryDirectory() as td:
            final, _ = self._paths(td)
            unknown = dict(state_mod.LEGACY_SCAFFOLD_STATE_V1)
            unknown["reason"] = "UNKNOWN_PREDECESSOR"
            final.write_bytes(state_mod._canonical_bytes(unknown))
            os.chmod(final, 0o600)
            before = final.read_bytes()
            with self.assertRaisesRegex(ValueError, "state shape mismatch"):
                state_mod.initialize(final)
            self.assertEqual(before, final.read_bytes())
            self.assertFalse(state_mod._legacy_archive_path(final.parent).exists())

    def test_legacy_migration_refuses_mixed_generation_edge_config(self):
        with tempfile.TemporaryDirectory() as td:
            final, _ = self._paths(td)
            final.write_bytes(state_mod._canonical_bytes(state_mod.LEGACY_SCAFFOLD_STATE_V1))
            os.chmod(final, 0o600)
            config = final.parent / "edge-config.json"
            config.write_text("{}\n")
            os.chmod(config, 0o600)
            with self.assertRaisesRegex(ValueError, "mixed-generation"):
                state_mod.initialize(final)
            self.assertTrue(final.exists())
            self.assertFalse(state_mod._legacy_archive_path(final.parent).exists())


if __name__ == "__main__":
    unittest.main()
