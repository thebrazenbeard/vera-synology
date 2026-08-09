from pathlib import Path
import hashlib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SpkSuccessorContractTests(unittest.TestCase):
    def test_info_narrows_package_platform_to_armada38x(self):
        info = (ROOT / "spk" / "INFO").read_text(encoding="utf-8")
        self.assertIn('arch="armada38x"\n', info)
        self.assertNotIn('arch="noarch"', info)

    def test_start_uses_bounded_readiness_adapter_with_target_validation_policy(self):
        script = (ROOT / "spk" / "scripts" / "start-stop-status").read_text(encoding="utf-8")
        self.assertIn('veramesh_start_readiness as r', script)
        self.assertIn('r.TARGET_POLICY = r.ReadinessPolicy(', script)
        self.assertIn('deadline_ns=30_000_000_000', script)
        self.assertIn('poll_interval_ns=250_000_000', script)
        self.assertIn('probe_timeout_cap_ns=1_000_000_000', script)
        self.assertIn('transient_stage_errnos=frozenset()', script)
        self.assertIn('raise SystemExit(r.runtime_start())', script)
        self.assertIn('real DS216 Package Center', script)
        self.assertIn('exec "$PY" "$LIFECYCLE" stop', script)
        self.assertIn('exec "$PY" "$LIFECYCLE" status', script)

    def test_postinst_initializes_semantic_state_then_binds_install_context_to_lifecycle(self):
        script = (ROOT / "spk" / "scripts" / "postinst").read_text(encoding="utf-8")
        self.assertIn('veramesh_state.py" initialize', script)
        self.assertIn('veramesh_lifecycle.py" postinstall', script)
        semantic = script.index('veramesh_state.py" initialize')
        lifecycle = script.index('veramesh_lifecycle.py" postinstall')
        self.assertLess(semantic, lifecycle)
        self.assertIn('${SYNOPKG_PKG_STATUS:-}', script)

    def test_postuninst_retires_lifecycle_only_for_uninstall_and_never_deletes_durable_state(self):
        script = (ROOT / "spk" / "scripts" / "postuninst").read_text(encoding="utf-8")
        self.assertIn('SYNOPKG_PKG_STATUS', script)
        self.assertIn('UNINSTALL', script)
        self.assertIn('veramesh_lifecycle.py" retire-uninstall', script)
        for token in ('rm ', 'rm\t', 'unlink', 'rmdir'):
            self.assertNotIn(token, script)

    def test_vera_icon_bytes_replace_placeholder_across_package_and_ui(self):
        expected = {
            "spk/PACKAGE_ICON.PNG": "695395ad653aa51bc8de9aac93a9089e48b2e77c23f27dc7bb24e8d1a0e0d261",
            "spk/PACKAGE_ICON_256.PNG": "6c5e5892a7515d57003dad9623fe6e9e330b3dffcc4887031d58722689c479f0",
            "payload/ui/images/app_16.png": "4095dc0ae6681cb269d3b2b90158ca26724e68a70b1b574e79fa486a91a89908",
            "payload/ui/images/app_24.png": "c092c428887e9373d88b9717023859e0ad427a9071d5ae3fab2bb102f96a66f2",
            "payload/ui/images/app_32.png": "1bbb097c2b8be84fe891a95e6d55c7d14b0658b47063efe288ed8b5530af751b",
            "payload/ui/images/app_48.png": "1b7ee62ab4a863b57dd0088af5ada0c7e69a75fbb7603121cec51c217f2ffa9a",
            "payload/ui/images/app_64.png": "695395ad653aa51bc8de9aac93a9089e48b2e77c23f27dc7bb24e8d1a0e0d261",
            "payload/ui/images/app_72.png": "c2dff96744b3049641b74a05d7c3a84d68949cd3f23f618b8a74a4f13f8f95d0",
            "payload/ui/images/app_256.png": "6c5e5892a7515d57003dad9623fe6e9e330b3dffcc4887031d58722689c479f0",
        }
        for rel, digest in expected.items():
            with self.subTest(path=rel):
                self.assertEqual(digest, hashlib.sha256((ROOT / rel).read_bytes()).hexdigest())

    def test_open_ui_explains_safe_idle_and_never_calls_start_failure_expected(self):
        html = (ROOT / "payload" / "ui" / "index.html").read_text(encoding="utf-8")
        self.assertIn("safe idle / unpaired", html)
        self.assertIn("BLOCKED_MESH_NOT_IMPLEMENTED", html)
        self.assertIn("Any package start failure is a repair failure", html)


if __name__ == "__main__":
    unittest.main()
