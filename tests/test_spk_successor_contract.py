from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SpkSuccessorContractTests(unittest.TestCase):
    def test_info_narrows_package_platform_to_armada38x(self):
        info = (ROOT / "spk" / "INFO").read_text(encoding="utf-8")
        self.assertIn('arch="armada38x"\n', info)
        self.assertNotIn('arch="noarch"', info)

    def test_start_uses_bounded_readiness_adapter_while_stop_status_keep_package_oracle(self):
        script = (ROOT / "spk" / "scripts" / "start-stop-status").read_text(encoding="utf-8")
        self.assertIn('LIFECYCLE="$SYNOPKG_PKGDEST/bin/veramesh_lifecycle.py"', script)
        self.assertIn('START_READINESS="$SYNOPKG_PKGDEST/bin/veramesh_start_readiness.py"', script)
        self.assertIn('exec "$PY" "$START_READINESS" start', script)
        self.assertNotIn('exec "$PY" "$LIFECYCLE" start', script)
        self.assertIn('exec "$PY" "$LIFECYCLE" stop', script)
        self.assertIn('exec "$PY" "$LIFECYCLE" status', script)
        self.assertNotIn('synosystemctl status', script)
        self.assertNotIn('"$CTL" start', script)
        self.assertNotIn('"$CTL" stop', script)

    def test_postinst_initializes_semantic_state_then_binds_install_context_to_lifecycle(self):
        script = (ROOT / "spk" / "scripts" / "postinst").read_text(encoding="utf-8")
        self.assertIn('veramesh_state.py" initialize', script)
        self.assertIn('veramesh_lifecycle.py" postinstall', script)
        semantic = script.index('veramesh_state.py" initialize')
        lifecycle = script.index('veramesh_lifecycle.py" postinstall')
        self.assertLess(semantic, lifecycle)
        self.assertIn('${SYNOPKG_PKG_STATUS:-}', script)
        self.assertNotIn(chr(92) + '${SYNOPKG_PKG_STATUS:-}', script, 'escaped package status is invalid')
        self.assertIn('edge-config.json', script)
        self.assertIn('100.88.50.35', script)
        self.assertNotIn('lappy.tail86ea75.ts.net', script)
        self.assertIn('chmod 600', script)
        self.assertNotIn('chown ', script)
        self.assertIn("printf '%s\\n'", script)
        self.assertNotIn('<<', script, 'DSM postinst must not use heredoc syntax')

    def test_preuninst_retires_lifecycle_before_payload_removal(self):
        script = (ROOT / "spk" / "scripts" / "preuninst").read_text(encoding="utf-8")
        self.assertIn('SYNOPKG_PKG_STATUS', script)
        self.assertIn('UNINSTALL', script)
        self.assertIn('veramesh_lifecycle.py" retire-uninstall', script)

    def test_postuninst_never_executes_removed_payload_or_deletes_durable_state(self):
        script = (ROOT / "spk" / "scripts" / "postuninst").read_text(encoding="utf-8")
        self.assertNotIn('veramesh_lifecycle.py', script)
        self.assertNotIn('SYNOPKG_PKGDEST', script)
        for token in ('rm ', 'rm\t', 'unlink', 'rmdir'):
            self.assertNotIn(token, script)


if __name__ == "__main__":
    unittest.main()
