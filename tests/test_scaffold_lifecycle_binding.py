from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_PATH = ROOT / "payload" / "bin" / "veramesh_lifecycle.py"
SCAFFOLD_PATH = ROOT / "payload" / "bin" / "veramesh_edge.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


lifecycle = load_module("veramesh_lifecycle", LIFECYCLE_PATH)


class ScaffoldLifecycleBindingPresenceTests(unittest.TestCase):
    def test_scaffold_successor_exists(self):
        self.assertTrue(SCAFFOLD_PATH.is_file(), "lifecycle-bound scaffold successor is missing")


if SCAFFOLD_PATH.is_file():
    # Minimal state module used only to load scaffold; status_payload is tested without
    # relying on the semantic state file implementation in this focused slice.
    class StateStub:
        @staticmethod
        def verify(_path):
            return {
                "semantic_state": "READY",
                "reason": "LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED",
            }

    sys.modules["veramesh_state"] = StateStub
    scaffold = load_module("veramesh_edge", SCAFFOLD_PATH)

    class ScaffoldLifecycleBindingTests(unittest.TestCase):
        INSTALL = "0123456789abcdef0123456789abcdef"
        PROCESS = "11111111111111111111111111111111"

        def setUp(self):
            self.td = tempfile.TemporaryDirectory()
            self.addCleanup(self.td.cleanup)
            self.root = Path(self.td.name)
            self.state = self.root / "lifecycle-state.json"
            self.base_transition_id = "33333333333333333333333333333333"
            base = {
                "schema": lifecycle.SCHEMA,
                "installation_incarnation_id": self.INSTALL,
                "installation_status": "CURRENT",
                "lifecycle_generation": 7,
                "lifecycle_state": "STARTING",
                "stopped_provenance": None,
                "process_instance_id": None,
                "process_start_generation": None,
                "transition_id": self.base_transition_id,
                "process_start_transition_id": None,
            }
            lifecycle.write_lifecycle_state_atomic(self.state, base)

        def test_daemon_startup_binding_carries_exact_lifecycle_profile_digest(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            self.assertTrue(hasattr(binding, "lifecycle_profile_sha256"))
            self.assertRegex(binding.lifecycle_profile_sha256, r"^[0-9a-f]{64}$")
            payload = scaffold.status_payload(binding)
            self.assertEqual(binding.lifecycle_profile_sha256, payload.get("lifecycle_profile_sha256"))

        def test_daemon_startup_binding_carries_start_transition_id(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            self.assertTrue(hasattr(binding, "start_transition_id"))
            self.assertRegex(binding.start_transition_id, r"^[0-9a-f]{32}$")

        def test_daemon_captures_starting_generation_once_at_startup(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            self.assertEqual(self.INSTALL, binding.installation_incarnation_id)
            self.assertEqual(7, binding.start_generation)
            self.assertEqual(self.PROCESS, binding.process_instance_id)
            self.assertEqual(lifecycle.PROFILE_ID, binding.lifecycle_profile_id)
            self.assertEqual(lifecycle.PACKAGE_VERSION, binding.package_version)

        def test_capture_rejects_non_starting_state(self):
            value = lifecycle.read_lifecycle_state(self.state)
            value["lifecycle_state"] = "STOPPED"
            value["stopped_provenance"] = "AUTHORIZED_STOP"
            lifecycle.write_lifecycle_state_atomic(self.state, value)
            with self.assertRaises(ValueError):
                lifecycle.capture_startup_binding(self.state, process_instance_factory=lambda: self.PROCESS)

        def test_status_payload_cross_binds_start_transition_id(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            payload = scaffold.status_payload(binding)
            self.assertIn("start_transition_id", payload)
            self.assertEqual(self.base_transition_id, payload["start_transition_id"])

        def test_status_payload_cross_binds_process_to_install_and_start_generation(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            payload = scaffold.status_payload(binding)
            self.assertEqual(self.INSTALL, payload["installation_incarnation_id"])
            self.assertEqual(7, payload["start_generation"])
            self.assertEqual(self.PROCESS, payload["process_instance_id"])
            self.assertEqual(lifecycle.PROFILE_ID, payload["lifecycle_profile_id"])
            self.assertEqual(lifecycle.PACKAGE_VERSION, payload["package_version"])
            self.assertEqual("READY", payload["mesh_semantic_state"])
            self.assertTrue(payload["edge_proxy_implemented"])
            self.assertFalse(payload["durable_relay_implemented"])

        def test_exact_bound_status_payload_round_trips_through_oracle_parser(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            raw = json.dumps(scaffold.status_payload(binding), sort_keys=True, separators=(",", ":")).encode()
            observation = lifecycle._parse_status_response(raw)
            self.assertEqual(lifecycle.ProbeResult.LIVE, observation.result)
            self.assertEqual(self.INSTALL, observation.installation_incarnation_id)
            self.assertEqual(7, observation.start_generation)
            self.assertEqual(self.PROCESS, observation.process_instance_id)

        def test_unbound_or_wrong_profile_status_payload_is_rejected_by_parser(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            payload = scaffold.status_payload(binding)
            for mutation in (
                lambda p: p.pop("process_instance_id"),
                lambda p: p.__setitem__("lifecycle_profile_id", "OLD_PROFILE"),
            ):
                hostile = dict(payload)
                mutation(hostile)
                raw = json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaises(ValueError):
                    lifecycle._parse_status_response(raw)

        def test_well_formed_but_stale_generation_remains_visible_for_caller_to_reject(self):
            binding = lifecycle.capture_startup_binding(
                self.state,
                process_instance_factory=lambda: self.PROCESS,
            )
            payload = scaffold.status_payload(binding)
            payload["start_generation"] = 8
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            observation = lifecycle._parse_status_response(raw)
            self.assertEqual(8, observation.start_generation)
            # Parser owns wire shape. start/status owns equality to current transition authority.
            self.assertNotEqual(binding.start_generation, observation.start_generation)


if __name__ == "__main__":
    unittest.main()
