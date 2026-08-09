from __future__ import annotations

import importlib.util
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "payload" / "bin" / "veramesh_start_readiness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("veramesh_start_readiness_tested", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeLifecycle:
    def __init__(self):
        self.state = {
            "installation_status": "CURRENT",
            "lifecycle_state": "STOPPED",
            "lifecycle_generation": 0,
            "installation_incarnation_id": "a" * 32,
            "transition_id": "b" * 32,
            "process_instance_id": None,
            "process_start_generation": None,
            "process_start_transition_id": None,
            "stopped_provenance": "POSTINSTALL_NOT_STARTED",
        }
        self.lock_entries = 0
        self.writes = []

    def lifecycle_writer_lock(self, path):
        outer = self
        class Ctx:
            def __enter__(self):
                outer.lock_entries += 1
            def __exit__(self, exc_type, exc, tb):
                outer.lock_entries -= 1
        return Ctx()

    def read_lifecycle_state(self, path):
        return dict(self.state)

    def _state_after(
        self, value, lifecycle_state, provenance=None,
        process_instance_id=None, process_start_generation=None,
        process_start_transition_id=None, transition_id=None
    ):
        out = dict(value)
        out["lifecycle_generation"] = value["lifecycle_generation"] + 1
        out["lifecycle_state"] = lifecycle_state
        out["stopped_provenance"] = provenance
        out["process_instance_id"] = process_instance_id
        out["process_start_generation"] = process_start_generation
        out["process_start_transition_id"] = process_start_transition_id
        if transition_id is not None:
            out["transition_id"] = transition_id
        return out

    def write_lifecycle_state_atomic(self, path, value):
        self.state = dict(value)
        self.writes.append(dict(value))
        return dict(value)

    def _best_effort_unknown(self, path, value):
        self.state = self._state_after(value, "UNKNOWN")
        self.writes.append(dict(self.state))

    def _live_matches_start(self, observation, starting):
        return (
            observation.get("result") == "LIVE"
            and observation.get("installation_incarnation_id") == starting["installation_incarnation_id"]
            and observation.get("start_generation") == starting["lifecycle_generation"]
            and observation.get("start_transition_id") == starting["transition_id"]
            and observation.get("process_instance_id") == "p" * 32
        )


class ManualClock:
    def __init__(self):
        self.value = 0.0
    def monotonic(self):
        return self.value
    def advance(self, amount):
        self.value += amount
    def sleep(self, amount):
        self.advance(amount)


class RealSocketApi:
    MAX_RESPONSE = 4096

    def __init__(self, socket_path: Path):
        self.SOCKET_PATH = socket_path

    @staticmethod
    def _parse_status_response(value: bytes):
        return json.loads(value.decode("utf-8"))


class StartReadinessContractTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module()
        self.api = FakeLifecycle()
        self.manager_calls = 0
        self.clock = ManualClock()

    def manager(self):
        self.assertGreater(self.api.lock_entries, 0, "writer lock must span manager start")
        self.manager_calls += 1
        return 0

    def policy(self, *, deadline=5.0, poll=0.25, probe_cap=1.0, accept_at_cutoff=False):
        return self.mod.ReadinessPolicy(
            deadline_seconds=deadline,
            poll_interval_seconds=poll,
            probe_timeout_cap_seconds=probe_cap,
            transient_errnos=frozenset(),
            accept_live_at_cutoff=accept_at_cutoff,
        )

    def live_now(self, *, installation_id=None):
        state = self.api.state
        return self.mod.ReadinessObservation.live({
            "result": "LIVE",
            "installation_incarnation_id": installation_id or state["installation_incarnation_id"],
            "start_generation": state["lifecycle_generation"],
            "start_transition_id": state["transition_id"],
            "process_instance_id": "p" * 32,
        })

    def run_start(self, probe, policy=None, manager=None):
        return self.mod.start_transition_bounded(
            "state", "lock", manager or self.manager, probe,
            policy or self.policy(),
            api=self.api,
            monotonic=self.clock.monotonic,
            sleeper=self.clock.sleep,
            transition_factory=lambda: "c" * 32,
        )

    def _serve_status(self, path, chunks, delays, *, hold_open=0.0):
        ready = threading.Event()
        def worker():
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            ready.set()
            conn, _ = server.accept()
            conn.recv(1024)
            try:
                for delay, chunk in zip(delays, chunks):
                    time.sleep(delay)
                    conn.sendall(chunk)
                if hold_open:
                    time.sleep(hold_open)
            except BrokenPipeError:
                pass
            finally:
                conn.close()
                server.close()
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(1.0))
        return thread

    def test_absent_then_exact_live_succeeds_with_one_manager_start(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            self.assertGreater(self.api.lock_entries, 0)
            self.clock.advance(0.05)
            return self.mod.ReadinessObservation.absent() if calls == 1 else self.live_now()
        rc = self.run_start(probe)
        self.assertEqual(0, rc)
        self.assertEqual(1, self.manager_calls)
        self.assertEqual(2, calls)
        self.assertEqual("RUNNING", self.api.state["lifecycle_state"])

    def test_typed_transient_then_live_succeeds(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            self.clock.advance(0.05)
            if calls == 1:
                return self.mod.ReadinessObservation.not_ready_transient("qualified_errno")
            return self.live_now()
        rc = self.run_start(probe)
        self.assertEqual(0, rc)
        self.assertEqual(1, self.manager_calls)
        self.assertEqual(2, calls)

    def test_integrity_error_is_immediate_unknown_and_never_heals(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            self.clock.advance(0.05)
            if calls == 1:
                return self.mod.ReadinessObservation.integrity_error("malformed")
            return self.live_now()
        rc = self.run_start(probe)
        self.assertEqual(4, rc)
        self.assertEqual(1, calls)
        self.assertEqual(1, self.manager_calls)
        self.assertEqual("UNKNOWN", self.api.state["lifecycle_state"])

    def test_wrong_live_after_retryable_absent_is_immediate_unknown(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            self.clock.advance(0.05)
            if calls == 1:
                return self.mod.ReadinessObservation.absent()
            if calls == 2:
                return self.live_now(installation_id="f" * 32)
            return self.live_now()
        rc = self.run_start(probe)
        self.assertEqual(4, rc)
        self.assertEqual(2, calls)
        self.assertEqual("UNKNOWN", self.api.state["lifecycle_state"])

    def test_deadline_expiry_is_unknown_and_manager_start_is_not_replayed(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            self.clock.advance(min(timeout, 0.20))
            return self.mod.ReadinessObservation.absent()
        rc = self.run_start(
            probe,
            self.policy(deadline=0.65, poll=0.20, probe_cap=0.25),
        )
        self.assertEqual(4, rc)
        self.assertEqual(1, self.manager_calls)
        self.assertEqual("UNKNOWN", self.api.state["lifecycle_state"])
        self.assertGreaterEqual(calls, 1)

    def test_probe_budget_never_exceeds_remaining_parent_deadline(self):
        seen = []
        def probe(timeout, policy):
            seen.append(timeout)
            self.clock.advance(min(timeout, 0.20))
            return self.mod.ReadinessObservation.absent()
        rc = self.run_start(
            probe,
            self.policy(deadline=0.55, poll=0.20, probe_cap=0.50),
        )
        self.assertEqual(4, rc)
        self.assertTrue(seen)
        self.assertTrue(all(0.0 < n <= 0.55 for n in seen))
        self.assertLess(seen[-1], seen[0])

    def test_transport_error_is_not_retryable_without_qualified_typed_mapping(self):
        calls = 0
        def probe(timeout, policy):
            nonlocal calls
            calls += 1
            return self.mod.ReadinessObservation.transport_error("generic_oserror")
        rc = self.run_start(probe)
        self.assertEqual(4, rc)
        self.assertEqual(1, calls)
        self.assertEqual("UNKNOWN", self.api.state["lifecycle_state"])

    def test_invalid_initial_authority_never_calls_manager(self):
        self.api.state["lifecycle_state"] = "UNKNOWN"
        rc = self.run_start(lambda timeout, policy: self.mod.ReadinessObservation.absent())
        self.assertEqual(4, rc)
        self.assertEqual(0, self.manager_calls)

    def test_manager_failure_does_not_probe(self):
        manager_calls = 0
        def bad_manager():
            nonlocal manager_calls
            manager_calls += 1
            return 1
        probe_calls = 0
        def probe(timeout, policy):
            nonlocal probe_calls
            probe_calls += 1
            return self.mod.ReadinessObservation.absent()
        rc = self.run_start(probe, manager=bad_manager)
        self.assertEqual(4, rc)
        self.assertEqual(1, manager_calls)
        self.assertEqual(0, probe_calls)
        self.assertEqual("UNKNOWN", self.api.state["lifecycle_state"])

    def test_unbound_runtime_profile_fails_before_manager_effect(self):
        calls = []
        self.mod.TARGET_POLICY = None
        rc = self.mod.runtime_start(api=self.api, manager_start=lambda: calls.append(1) or 0)
        self.assertEqual(4, rc)
        self.assertEqual([], calls)

    def test_algorithm_profile_declares_numeric_and_transient_inputs_unbound(self):
        profile = self.mod.ALGORITHM_PROFILE
        self.assertEqual(
            "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
            profile["deadline_seconds"],
        )
        self.assertEqual(
            "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
            profile["transient_errno_allowlist"],
        )
        self.assertRegex(self.mod.ALGORITHM_PROFILE_SHA256, r"^[0-9a-f]{64}$")

    def test_real_probe_rejects_delayed_trailing_bytes_after_valid_line(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.sock"
            self._serve_status(path, [b'{"result":"LIVE"}\n', b"X"], [0.01, 0.06])
            obs = self.mod.probe_control_socket_bounded(0.25, self.policy(), api=RealSocketApi(path))
            self.assertEqual(self.mod.ReadinessKind.INTEGRITY_ERROR, obs.kind)
            self.assertEqual("trailing_response_bytes", obs.cause)

    def test_real_probe_rejects_any_byte_after_terminating_lf(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.sock"
            self._serve_status(path, [b'{"result":"LIVE"}\n '], [0.01])
            obs = self.mod.probe_control_socket_bounded(0.25, self.policy(), api=RealSocketApi(path))
            self.assertEqual(self.mod.ReadinessKind.INTEGRITY_ERROR, obs.kind)
            self.assertEqual("trailing_response_bytes", obs.cause)

    def test_real_probe_requires_eof_after_exact_line_before_live(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.sock"
            self._serve_status(path, [b'{"result":"LIVE"}\n'], [0.01])
            obs = self.mod.probe_control_socket_bounded(0.25, self.policy(), api=RealSocketApi(path))
            self.assertEqual(self.mod.ReadinessKind.LIVE, obs.kind)
            self.assertEqual("LIVE", obs.payload["result"])

    def test_real_probe_valid_line_held_open_expires_before_live(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.sock"
            self._serve_status(path, [b'{"result":"LIVE"}\n'], [0.01], hold_open=0.35)
            started = time.monotonic()
            obs = self.mod.probe_control_socket_bounded(0.12, self.policy(), api=RealSocketApi(path))
            elapsed = time.monotonic() - started
            self.assertEqual(self.mod.ReadinessKind.TRANSPORT_ERROR, obs.kind)
            self.assertEqual("probe_deadline_expired", obs.cause)
            self.assertLess(elapsed, 0.30)

    def test_real_probe_fragmented_response_uses_one_aggregate_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.sock"
            self._serve_status(
                path,
                [b'{"res', b'ult"', b':"LI', b'VE"}', b"\n"],
                [0.04, 0.04, 0.04, 0.04, 0.04],
            )
            started = time.monotonic()
            obs = self.mod.probe_control_socket_bounded(0.12, self.policy(), api=RealSocketApi(path))
            elapsed = time.monotonic() - started
            self.assertEqual(self.mod.ReadinessKind.TRANSPORT_ERROR, obs.kind)
            self.assertEqual("probe_deadline_expired", obs.cause)
            self.assertLess(elapsed, 0.30)


if __name__ == "__main__":
    unittest.main()
