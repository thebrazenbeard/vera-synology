from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "payload" / "bin" / "veramesh_lifecycle.py"


class LifecycleOraclePresenceTests(unittest.TestCase):
    def test_package_owned_lifecycle_oracle_exists(self):
        self.assertTrue(MODULE.is_file(), "package-owned lifecycle oracle module is missing")


if MODULE.is_file():
    spec = importlib.util.spec_from_file_location("veramesh_lifecycle", MODULE)
    lifecycle = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(lifecycle)

    class LifecycleOracleBehaviorTests(unittest.TestCase):
        INSTALL_A = "0123456789abcdef0123456789abcdef"
        INSTALL_B = "abcdef0123456789abcdef0123456789"
        PROCESS_A = "11111111111111111111111111111111"
        PROCESS_B = "22222222222222222222222222222222"

        def setUp(self):
            self.td = tempfile.TemporaryDirectory()
            self.addCleanup(self.td.cleanup)
            self.root = Path(self.td.name)
            self.state = self.root / "state" / "lifecycle-state.json"
            self.lock = self.root / "state" / "lifecycle.lock"

        def absent(self):
            return lifecycle.ProbeObservation.absent()

        def error(self):
            return lifecycle.ProbeObservation.error()

        def live(self, installation_id, start_generation, process_id=PROCESS_A, start_transition_id=None):
            return lifecycle.ProbeObservation.live(
                installation_incarnation_id=installation_id,
                start_generation=start_generation,
                process_instance_id=process_id,
                start_transition_id=start_transition_id,
            )

        def bootstrap(self, installation_id=INSTALL_A):
            return lifecycle.bootstrap_install(
                self.state,
                self.lock,
                probe=self.absent,
                incarnation_factory=lambda: installation_id,
            )

        def start_ok(self, process_id=PROCESS_A):
            before = lifecycle.read_lifecycle_state(self.state)
            expected_start_generation = before["lifecycle_generation"] + 1

            def probe():
                starting = lifecycle.read_lifecycle_state(self.state)
                return self.live(
                    before["installation_incarnation_id"],
                    expected_start_generation,
                    process_id,
                    starting["transition_id"],
                )

            return lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: 0,
                probe,
            )

        def test_fresh_install_state_carries_transition_correlation(self):
            value = self.bootstrap()
            self.assertIn("transition_id", value)
            self.assertRegex(value["transition_id"], r"^[0-9a-f]{32}$")
            self.assertIn("process_start_transition_id", value)
            self.assertIsNone(value["process_start_transition_id"])

        def test_fresh_install_bootstraps_current_stopped(self):
            value = self.bootstrap()
            self.assertEqual(self.INSTALL_A, value["installation_incarnation_id"])
            self.assertEqual("CURRENT", value["installation_status"])
            self.assertEqual("STOPPED", value["lifecycle_state"])
            self.assertEqual("POSTINSTALL_NOT_STARTED", value["stopped_provenance"])
            self.assertEqual(0, value["lifecycle_generation"])
            self.assertIsNone(value["process_instance_id"])
            self.assertIsNone(value["process_start_generation"])
            self.assertEqual(3, lifecycle.status_code(self.state, self.absent))

        def test_upgrade_or_unknown_postinst_never_bootstraps(self):
            first = self.bootstrap()
            before = self.state.read_bytes()
            for pkg_status in ("UPGRADE", "", "START", "STOP"):
                with self.subTest(pkg_status=pkg_status):
                    result = lifecycle.postinstall_context(
                        pkg_status,
                        self.state,
                        self.lock,
                        probe=self.absent,
                        incarnation_factory=lambda: self.INSTALL_B,
                    )
                    self.assertIsNone(result)
                    self.assertEqual(before, self.state.read_bytes())
                    self.assertEqual(first, lifecycle.read_lifecycle_state(self.state))

        def test_fresh_install_supersedes_valid_prior_install_authority(self):
            first = self.bootstrap(self.INSTALL_A)
            second = lifecycle.bootstrap_install(
                self.state,
                self.lock,
                probe=self.absent,
                incarnation_factory=lambda: self.INSTALL_B,
            )
            self.assertNotEqual(first["installation_incarnation_id"], second["installation_incarnation_id"])
            self.assertEqual(self.INSTALL_B, second["installation_incarnation_id"])
            self.assertEqual("CURRENT", second["installation_status"])
            self.assertEqual("STOPPED", second["lifecycle_state"])
            self.assertEqual(0, second["lifecycle_generation"])

        def test_fresh_install_supersedes_valid_stale_transition_from_prior_install(self):
            first = self.bootstrap(self.INSTALL_A)
            stale = dict(first)
            stale["lifecycle_generation"] = 7
            stale["lifecycle_state"] = "STARTING"
            stale["stopped_provenance"] = None
            lifecycle.write_lifecycle_state_atomic(self.state, stale)
            second = lifecycle.bootstrap_install(
                self.state,
                self.lock,
                probe=self.absent,
                incarnation_factory=lambda: self.INSTALL_B,
            )
            self.assertEqual(self.INSTALL_B, second["installation_incarnation_id"])
            self.assertEqual("STOPPED", second["lifecycle_state"])
            self.assertEqual(0, second["lifecycle_generation"])

        def test_fresh_install_preserves_corrupt_prior_state_and_refuses_bootstrap(self):
            self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            bad = b'{"schema":"corrupt-prior-install"}\n'
            self.state.write_bytes(bad)
            os.chmod(self.state, 0o600)
            with self.assertRaises(ValueError):
                lifecycle.bootstrap_install(
                    self.state,
                    self.lock,
                    probe=self.absent,
                    incarnation_factory=lambda: self.INSTALL_B,
                )
            self.assertEqual(bad, self.state.read_bytes())

        def test_uninstall_retirement_is_idempotent_and_not_running_authority(self):
            current = self.bootstrap()
            retired = lifecycle.retire_uninstall(self.state, self.lock)
            self.assertEqual(current["installation_incarnation_id"], retired["installation_incarnation_id"])
            self.assertEqual("RETIRED", retired["installation_status"])
            self.assertEqual("UNKNOWN", retired["lifecycle_state"])
            self.assertEqual(4, lifecycle.status_code(self.state, self.absent))
            again = lifecycle.retire_uninstall(self.state, self.lock)
            self.assertEqual(retired, again)

        def test_start_publishes_fresh_transition_id_and_running_retains_start_transition(self):
            current = self.bootstrap()
            bootstrap_transition = current["transition_id"]
            observed = []
            expected_start_generation = current["lifecycle_generation"] + 1

            def manager():
                during = lifecycle.read_lifecycle_state(self.state)
                observed.append((during["lifecycle_state"], during["transition_id"]))
                return 0

            def valid_probe():
                starting = lifecycle.read_lifecycle_state(self.state)
                return self.live(
                    self.INSTALL_A,
                    expected_start_generation,
                    self.PROCESS_A,
                    starting["transition_id"],
                )

            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                manager,
                valid_probe,
            )
            self.assertEqual(0, rc)
            self.assertEqual("STARTING", observed[0][0])
            self.assertNotEqual(bootstrap_transition, observed[0][1])
            final = lifecycle.read_lifecycle_state(self.state)
            self.assertEqual(observed[0][1], final["transition_id"])
            self.assertEqual(observed[0][1], final["process_start_transition_id"])

        def test_start_publishes_starting_before_manager_and_running_with_exact_responder_binding(self):
            current = self.bootstrap()
            observed = []
            expected_start_generation = current["lifecycle_generation"] + 1

            def manager():
                during = lifecycle.read_lifecycle_state(self.state)
                observed.append((during["lifecycle_state"], during["lifecycle_generation"]))
                return 0

            def valid_probe():
                starting = lifecycle.read_lifecycle_state(self.state)
                return self.live(
                    self.INSTALL_A,
                    expected_start_generation,
                    self.PROCESS_A,
                    starting["transition_id"],
                )

            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                manager,
                valid_probe,
            )
            self.assertEqual([("STARTING", expected_start_generation)], observed)
            self.assertEqual(0, rc)
            final = lifecycle.read_lifecycle_state(self.state)
            self.assertEqual("RUNNING", final["lifecycle_state"])
            self.assertEqual(expected_start_generation + 1, final["lifecycle_generation"])
            self.assertEqual(expected_start_generation, final["process_start_generation"])
            self.assertEqual(self.PROCESS_A, final["process_instance_id"])

        def test_start_rejects_wrong_transition_responder_even_when_generation_matches(self):
            current = self.bootstrap()
            expected_start_generation = current["lifecycle_generation"] + 1

            def wrong_probe():
                starting = lifecycle.read_lifecycle_state(self.state)
                wrong = "44444444444444444444444444444444"
                self.assertNotEqual(starting["transition_id"], wrong)
                return self.live(self.INSTALL_A, expected_start_generation, self.PROCESS_A, wrong)

            rc = lifecycle.start_transition(self.state, self.lock, lambda: 0, wrong_probe)
            self.assertEqual(4, rc)
            self.assertEqual("UNKNOWN", lifecycle.read_lifecycle_state(self.state)["lifecycle_state"])

        def test_status_rejects_wrong_start_transition_responder(self):
            self.bootstrap()
            self.assertEqual(0, self.start_ok(self.PROCESS_A))
            running = lifecycle.read_lifecycle_state(self.state)
            wrong = "55555555555555555555555555555555"
            self.assertNotEqual(running["process_start_transition_id"], wrong)
            rc = lifecycle.status_code(
                self.state,
                lambda: self.live(
                    running["installation_incarnation_id"],
                    running["process_start_generation"],
                    running["process_instance_id"],
                    wrong,
                ),
            )
            self.assertEqual(4, rc)

        def test_start_rejects_stale_prior_generation_responder(self):
            current = self.bootstrap()
            expected_start_generation = current["lifecycle_generation"] + 1
            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: 0,
                lambda: self.live(self.INSTALL_A, expected_start_generation - 1, self.PROCESS_A),
            )
            self.assertEqual(4, rc)
            self.assertEqual("UNKNOWN", lifecycle.read_lifecycle_state(self.state)["lifecycle_state"])

        def test_start_rejects_prior_install_responder(self):
            current = self.bootstrap()
            expected_start_generation = current["lifecycle_generation"] + 1
            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: 0,
                lambda: self.live(self.INSTALL_B, expected_start_generation, self.PROCESS_A),
            )
            self.assertEqual(4, rc)
            self.assertEqual("UNKNOWN", lifecycle.read_lifecycle_state(self.state)["lifecycle_state"])

        def test_start_rejects_unbound_generic_live_result(self):
            self.bootstrap()
            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: 0,
                lambda: lifecycle.ProbeResult.LIVE,
            )
            self.assertEqual(4, rc)
            self.assertEqual("UNKNOWN", lifecycle.read_lifecycle_state(self.state)["lifecycle_state"])

        def test_status_running_requires_exact_process_binding(self):
            self.bootstrap()
            self.assertEqual(0, self.start_ok(self.PROCESS_A))
            running = lifecycle.read_lifecycle_state(self.state)
            self.assertEqual(
                0,
                lifecycle.status_code(
                    self.state,
                    lambda: self.live(
                        running["installation_incarnation_id"],
                        running["process_start_generation"],
                        running["process_instance_id"],
                        running["process_start_transition_id"],
                    ),
                ),
            )
            self.assertEqual(
                4,
                lifecycle.status_code(
                    self.state,
                    lambda: self.live(
                        running["installation_incarnation_id"],
                        running["process_start_generation"],
                        self.PROCESS_B,
                        running["process_start_transition_id"],
                    ),
                ),
            )

        def test_status_generation_change_during_stopped_observation_is_unknown(self):
            current = self.bootstrap()

            def racing_probe():
                next_state = dict(current)
                next_state["lifecycle_generation"] = 1
                next_state["lifecycle_state"] = "STARTING"
                next_state["stopped_provenance"] = None
                lifecycle.write_lifecycle_state_atomic(self.state, next_state)
                return self.absent()

            self.assertEqual(4, lifecycle.status_code(self.state, racing_probe))

        def test_normal_stop_does_not_replay_manager_when_already_stopping(self):
            self.bootstrap()
            self.assertEqual(0, self.start_ok(self.PROCESS_A))
            running = lifecycle.read_lifecycle_state(self.state)
            stopping = lifecycle._state_after(
                running,
                "STOPPING",
                transition_id="66666666666666666666666666666666",
            )
            lifecycle.write_lifecycle_state_atomic(self.state, stopping)
            before = self.state.read_bytes()
            called = []
            rc = lifecycle.stop_transition(
                self.state,
                self.lock,
                lambda: called.append("stop") or 0,
                self.absent,
            )
            self.assertEqual(4, rc)
            self.assertEqual([], called)
            self.assertEqual(before, self.state.read_bytes())

        def test_stop_publishes_fresh_transition_id_and_stopped_retains_stop_transition(self):
            self.bootstrap()
            self.assertEqual(0, self.start_ok(self.PROCESS_A))
            running = lifecycle.read_lifecycle_state(self.state)
            start_transition = running["transition_id"]
            observed = []

            def manager():
                during = lifecycle.read_lifecycle_state(self.state)
                observed.append((during["lifecycle_state"], during["transition_id"]))
                return 0

            rc = lifecycle.stop_transition(self.state, self.lock, manager, self.absent)
            self.assertEqual(0, rc)
            self.assertEqual("STOPPING", observed[0][0])
            self.assertNotEqual(start_transition, observed[0][1])
            final = lifecycle.read_lifecycle_state(self.state)
            self.assertEqual("STOPPED", final["lifecycle_state"])
            self.assertEqual(observed[0][1], final["transition_id"])

        def test_stop_publishes_stopping_before_manager_and_stopped_after_absence(self):
            self.bootstrap()
            self.assertEqual(0, self.start_ok())
            observed = []

            def manager():
                during = lifecycle.read_lifecycle_state(self.state)
                observed.append(during["lifecycle_state"])
                return 0

            rc = lifecycle.stop_transition(self.state, self.lock, manager, self.absent)
            self.assertEqual(["STOPPING"], observed)
            self.assertEqual(0, rc)
            final = lifecycle.read_lifecycle_state(self.state)
            self.assertEqual("STOPPED", final["lifecycle_state"])
            self.assertEqual("AUTHORIZED_STOP", final["stopped_provenance"])
            self.assertIsNone(final["process_instance_id"])
            self.assertEqual(3, lifecycle.status_code(self.state, self.absent))

        def test_corrupt_state_does_not_block_fail_safe_manager_stop(self):
            self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            bad = b'{"schema":"corrupt"}\n'
            self.state.write_bytes(bad)
            os.chmod(self.state, 0o600)
            called = []
            rc = lifecycle.stop_transition(self.state, self.lock, lambda: called.append("stop") or 0, self.absent)
            self.assertEqual(["stop"], called)
            self.assertEqual(4, rc)
            self.assertEqual(bad, self.state.read_bytes())

        def test_missing_state_does_not_block_fail_safe_manager_stop(self):
            called = []
            rc = lifecycle.stop_transition(self.state, self.lock, lambda: called.append("stop") or 0, self.absent)
            self.assertEqual(["stop"], called)
            self.assertEqual(4, rc)
            self.assertFalse(self.state.exists())

        def test_symlink_state_is_not_followed_and_does_not_block_fail_safe_manager_stop(self):
            self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = self.root / "target.json"
            target.write_text('{"schema":"do-not-touch"}\n')
            os.chmod(target, 0o600)
            self.state.symlink_to(target)
            called = []
            rc = lifecycle.stop_transition(self.state, self.lock, lambda: called.append("stop") or 0, self.absent)
            self.assertEqual(["stop"], called)
            self.assertEqual(4, rc)
            self.assertEqual(b'{"schema":"do-not-touch"}\n', target.read_bytes())
            self.assertTrue(self.state.is_symlink())

        def test_unsafe_lock_path_blocks_manager_effect(self):
            self.lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = self.root / "lock-target"
            target.write_text("do-not-lock")
            os.chmod(target, 0o600)
            self.lock.symlink_to(target)
            called = []
            rc = lifecycle.stop_transition(self.state, self.lock, lambda: called.append("stop") or 0, self.absent)
            self.assertEqual([], called)
            self.assertEqual(4, rc)

        def test_start_remains_blocked_on_corrupt_state(self):
            self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.state.write_text('{"schema":"corrupt"}\n')
            os.chmod(self.state, 0o600)
            called = []
            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: called.append("start") or 0,
                lambda: self.error(),
            )
            self.assertEqual([], called)
            self.assertEqual(4, rc)

        def test_generation_cannot_wrap(self):
            value = self.bootstrap()
            value["lifecycle_generation"] = lifecycle.MAX_GENERATION
            lifecycle.write_lifecycle_state_atomic(self.state, value)
            called = []
            rc = lifecycle.start_transition(
                self.state,
                self.lock,
                lambda: called.append("start") or 0,
                lambda: self.error(),
            )
            self.assertEqual([], called)
            self.assertEqual(4, rc)


if __name__ == "__main__":
    unittest.main()
