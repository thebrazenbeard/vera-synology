import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SRC = Path(__file__).resolve().parents[1] / "tools/diagnose_verarelay_owner.py"
spec = importlib.util.spec_from_file_location("verarelay_diag", SRC)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class RelayCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.pkg = base / "VeraRelay"
        self.proc = base / "proc"
        (self.pkg / "var/state").mkdir(parents=True)
        (self.proc / "net").mkdir(parents=True)
        for pid in (100, 101):
            (self.proc / str(pid)).mkdir(parents=True)
        runtime = str(self.pkg / "target/app/runtime.js")
        server = str(self.pkg / "target/app/server.js")
        (self.proc / "100/cmdline").write_bytes(("/node\0" + runtime + "\0").encode())
        (self.proc / "101/cmdline").write_bytes(("/node\0" + server + "\0").encode())
        (self.proc / "100/status").write_text("Uid:\t226494 226494\nPPid:\t1\n")
        (self.proc / "101/status").write_text("Uid:\t226494 226494\nPPid:\t100\n")
        (self.pkg / "var/state/runtime.pid").write_text("100\n")
        (self.pkg / "var/state/runtime.json").write_text(json.dumps(
            {"runtimePid": 100, "serverPid": 101, "status": "running"}
        ))
        (self.proc / "net/tcp").write_text(
            "sl local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n"
            "0: 0100007F:4423 00000000:0000 0A 0:0 00:0000 00 226494 0 867 1\n"
        )
        self.health = {
            "status": "ok", "bindAddress": "127.0.0.1",
            "port": 17443, "nodeRole": "relay", "version": "0.3.0-0005",
            "audit": {"ok": True}
        }

    def inspect(self, **kwargs):
        return diag.inspect(
            self.pkg, self.proc, 226494,
            health_probe=lambda: kwargs.get("health", self.health),
            socket_probe=lambda *_: kwargs.get("socket_owned", True)
        )

    def test_loopback_socket_inode_parser(self):
        self.assertEqual(diag.listening_inodes(self.proc), ["867"])

    def test_valid_runtime_process_chain(self):
        result = self.inspect()
        self.assertEqual(result["outcome"], "PROCESS_CHAIN_MATCHES_PIDFILE")
        self.assertFalse(result["mutations_performed"])

    def test_missing_pidfile_requires_review_not_automatic_mutation(self):
        (self.pkg / "var/state/runtime.pid").unlink()
        result = self.inspect()
        self.assertEqual(result["outcome"], "STALE_OR_MISSING_PIDFILE_CANDIDATE")
        self.assertTrue(result["pidfile_requires_manual_review"])
        self.assertFalse((self.pkg / "var/state/runtime.pid").exists())

    def test_stale_pidfile_is_not_treated_as_owned(self):
        pidfile = self.pkg / "var/state/runtime.pid"
        pidfile.write_text("999\n")
        result = self.inspect()
        self.assertEqual(result["outcome"], "STALE_OR_MISSING_PIDFILE_CANDIDATE")
        self.assertEqual(pidfile.read_text(), "999\n")

    def test_foreign_uid_rejected(self):
        (self.proc / "101/status").write_text("Uid:\t0 0\nPPid:\t100\n")
        self.assertEqual(self.inspect()["outcome"], "UNVERIFIED_OR_FOREIGN_LISTENER")

    def test_parent_mismatch_rejected(self):
        (self.proc / "101/status").write_text("Uid:\t226494 226494\nPPid:\t999\n")
        self.assertEqual(self.inspect()["outcome"], "UNVERIFIED_OR_FOREIGN_LISTENER")

    def test_other_process_socket_rejected(self):
        self.assertEqual(self.inspect(socket_owned=False)["outcome"],
                         "UNVERIFIED_OR_FOREIGN_LISTENER")

    def test_audit_failure_rejected(self):
        h = dict(self.health, audit={"ok": False})
        self.assertEqual(self.inspect(health=h)["outcome"],
                         "UNVERIFIED_OR_FOREIGN_LISTENER")

    def test_malformed_health_does_not_throw_or_assert_owner(self):
        for value in (None, [], {"audit": None}, "ok"):
            with self.subTest(value=value):
                self.assertEqual(self.inspect(health=value)["outcome"],
                                 "UNVERIFIED_OR_FOREIGN_LISTENER")

    def test_stale_runtime_state_does_not_prove_ownership(self):
        f = self.pkg / "var/state/runtime.json"
        f.write_text(json.dumps({"runtimePid": 100, "serverPid": 101,
                                 "status": "exited"}))
        self.assertEqual(self.inspect()["outcome"],
                         "UNVERIFIED_OR_FOREIGN_LISTENER")
    def test_not_listening_never_infers_ownership(self):
        (self.proc / "net/tcp").write_text("header\n")
        self.assertEqual(self.inspect()["outcome"],
                         "NO_LOCAL_LISTENER_OR_PROC_VISIBILITY")

    def test_invalid_pidfile_rejected(self):
        (self.pkg / "var/state/runtime.pid").write_text("1;echo danger\n")
        self.assertEqual(self.inspect()["outcome"],
                         "STALE_OR_MISSING_PIDFILE_CANDIDATE")

    def test_runtime_script_arg_spoof_rejected(self):
        runtime = str(self.pkg / "target/app/runtime.js")
        (self.proc / "100/cmdline").write_bytes(
            ("/node\0-e\0" + runtime + "\0").encode()
        )
        self.assertEqual(self.inspect()["outcome"],
                         "UNVERIFIED_OR_FOREIGN_LISTENER")


if __name__ == "__main__":
    unittest.main()
