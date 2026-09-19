from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verify_spk = load_module("verify_spk_successor_profile", ROOT / "tools" / "verify_spk.py")


class VerifierSuccessorProfileTests(unittest.TestCase):
    def test_closed_profile_narrows_arch_and_requires_lifecycle_payload(self):
        self.assertEqual("armada38x", verify_spk.INFO_EXPECTED.get("arch"))
        self.assertIn("bin/veramesh_lifecycle.py", verify_spk.REQUIRED_PAYLOAD)

    def test_successor_profile_identity_is_new_and_digest_bound(self):
        self.assertEqual("SPK_DS216_LIVE_EDGE_V16_PROFILE_V1", verify_spk.METADATA_PROFILE_ID)
        digest = getattr(verify_spk, "SPK_PROFILE_SHA256", None)
        self.assertIsInstance(digest, str)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        lifecycle_id = getattr(verify_spk, "LIFECYCLE_PROFILE_ID", None)
        lifecycle_digest = getattr(verify_spk, "LIFECYCLE_PROFILE_SHA256", None)
        self.assertEqual("VERA_MESH_FIRST_SLICE_LIFECYCLE_PROFILE_V1", lifecycle_id)
        self.assertRegex(lifecycle_digest or "", r"^[0-9a-f]{64}$")

    def test_first_slice_profile_does_not_transfer_release_later_acceptance(self):
        descriptor = verify_spk.SPK_PROFILE_DESCRIPTOR
        self.assertEqual(
            [
                "MESH-FOUR-SPK-STATUS-UNKNOWN-COLLAPSE-007",
                "MESH-FOUR-SPK-PACKAGE-OWNED-INITIAL-STOPPED-GAP-008",
                "MESH-FOUR-SPK-LIFECYCLE-RESPONDER-BINDING-010",
            ],
            descriptor.get("first_slice_acceptance_findings"),
        )
        self.assertEqual(
            [
                "MESH-FOUR-SPK-INFO-ARCH-SCOPE-006",
                "MESH-FOUR-SPK-LIFECYCLE-CROSS-INSTALL-CONTAMINATION-009",
                "MESH-FOUR-SPK-LIFECYCLE-FAIL-SAFE-STOP-011",
                "MESH-SEVEN-SPK-LIFECYCLE-INCOMPLETE-TRANSITION-RECOVERY-012",
            ],
            descriptor.get("release_later_not_acceptance_transferred"),
        )


if __name__ == "__main__":
    unittest.main()
