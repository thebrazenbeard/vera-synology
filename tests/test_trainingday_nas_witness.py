"""Synthetic-only checks of the NAS witness's HOLD/CAS/replay boundary."""

import hashlib
import hmac
import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from trainingday_issuer.nas_witness import (BrokerAuthError, LedgerConflict,
                                            StateError, WitnessEngine, make_server,
                                            provision)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"
        provision(self.root)
        self.engine = WitnessEngine(self.root, now=lambda: 1762045200)
        self.broker_key = (self.root / "broker.key").read_bytes()

    def request(self, *, nonce="a" * 32, previous_head="0" * 64,
                expires_unix=1762045260, event_kind="PREFLIGHT", **kw):
        body = {"schema": "VERA_TRAININGDAY_NAS_WITNESS_REQUEST_V1",
                "nonce": nonce, "previous_head": previous_head,
                "request_sha256": "b" * 64, "expires_unix": expires_unix,
                "event_kind": event_kind}
        body.update(kw)
        raw = canonical(body)
        mac = hmac.new(self.broker_key, b"VERA_TRAININGDAY_NAS_BROKER_V1\x00" + raw,
                       hashlib.sha256).hexdigest()
        return raw, mac

    def test_successful_authenticated_append_is_never_a_grant(self):
        raw, mac = self.request()
        result = self.engine.append(raw, mac)
        self.assertEqual(result["seq"], 1)
        self.assertEqual(result["status"], "HOLD")
        for field in ("rights_admitted", "gpu_lease_granted",
                      "physical_training_authorized"):
            self.assertIs(result[field], False)

    def test_wrong_hmac_and_body_mutation_rejected_without_append(self):
        raw, mac = self.request()
        with self.assertRaises(BrokerAuthError):
            self.engine.append(raw, "0" * 64)
        with self.assertRaises(BrokerAuthError):
            self.engine.append(raw.replace(b"PREFLIGHT", b"ABORT"), mac)
        self.assertEqual(self.engine.health()["seq"], 0)

    def test_duplicate_nonce_and_stale_head_rejected(self):
        raw, mac = self.request()
        first = self.engine.append(raw, mac)
        with self.assertRaises(LedgerConflict):
            self.engine.append(raw, mac)
        stale, stale_mac = self.request(nonce="c" * 32)
        with self.assertRaises(LedgerConflict):
            self.engine.append(stale, stale_mac)
        self.assertEqual(self.engine.health()["head"], first["head"])

    def test_expiry_future_and_bad_shape_rejected(self):
        for overrides in ({"expires_unix": 1762045199},
                          {"expires_unix": 1762045400},
                          {"event_kind": "AUTHORIZE"},
                          {"unexpected": "true"},
                          {"nonce": "x" * 32}):
            raw, mac = self.request(**overrides)
            with self.subTest(overrides=overrides), self.assertRaises(StateError):
                self.engine.append(raw, mac)
        self.assertEqual(self.engine.health()["seq"], 0)

    def test_expiry_rechecked_after_write_lock_acquired(self):
        clock = iter((1762045200, 1762045261))
        self.engine._now = lambda: next(clock)
        raw, mac = self.request(expires_unix=1762045260)
        with self.assertRaises(StateError):
            self.engine.append(raw, mac)
        self.assertEqual(self.engine.health()["seq"], 0)

    def test_valid_later_commit_clock_persists_after_restart(self):
        clock = iter((1762045200, 1762045201))
        self.engine._now = lambda: next(clock)
        raw, mac = self.request(expires_unix=1762045260)
        result = self.engine.append(raw, mac)
        self.assertEqual(result["created_unix"], 1762045201)
        self.assertEqual(self.engine.health()["seq"], 1)
        restored = WitnessEngine(self.root, now=lambda: 1762045202)
        self.assertEqual(restored.health()["head"], result["head"])

    def test_concurrent_cas_exactly_one_wins(self):
        barrier = threading.Barrier(2)
        outcomes = []

        def worker(nonce):
            raw, mac = self.request(nonce=nonce)
            barrier.wait()
            try:
                self.engine.append(raw, mac)
                outcomes.append("APPENDED")
            except LedgerConflict:
                outcomes.append("CONFLICT")

        threads = [threading.Thread(target=worker, args=(ch * 32,)) for ch in "cd"]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=5)
            self.assertFalse(th.is_alive())
        self.assertCountEqual(outcomes, ["APPENDED", "CONFLICT"])

    def test_restart_persists_and_detects_corrupted_ledger(self):
        raw, mac = self.request()
        first = self.engine.append(raw, mac)
        restored = WitnessEngine(self.root, now=lambda: 1762045201)
        self.assertEqual(restored.health()["head"], first["head"])
        with restored._connect() as db:
            db.execute("UPDATE events SET head=? WHERE seq=1", ("f" * 64,))
        with self.assertRaises(StateError):
            WitnessEngine(self.root, now=lambda: 1762045202)

    def test_refuses_unprovisioned_or_world_readable_secret(self):
        with self.assertRaises(StateError):
            WitnessEngine(self.root / "missing")
        (self.root / "broker.key").chmod(0o644)
        with self.assertRaises(StateError):
            WitnessEngine(self.root)

    def test_real_loopback_http_hold_and_replay(self):
        server = make_server(self.engine, 0)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: thread.join(timeout=2))
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        self.addCleanup(conn.close)
        conn.request("GET", "/health")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        self.assertFalse(json.loads(res.read())["physical_training_authorized"])
        raw, mac = self.request()
        headers = {"Content-Type": "application/json", "X-Vera-Broker-HMAC": mac}
        conn.request("POST", "/v1/witness", body=raw, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        self.assertEqual(json.loads(res.read())["status"], "HOLD")
        conn.request("POST", "/v1/witness", body=raw, headers=headers)
        res = conn.getresponse()
        self.assertEqual(res.status, 409)
        res.read()
        conn.request("POST", "/v1/witness", body=raw,
                     headers={"Content-Type": "application/json",
                              "X-Vera-Broker-HMAC": "0" * 64})
        res = conn.getresponse()
        self.assertEqual(res.status, 403)
        res.read()

    def test_loopback_http_slow_client_and_capacity_bounded(self):
        server = make_server(self.engine, 0)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: thread.join(timeout=2))
        port = server.server_address[1]
        with patch("trainingday_issuer.nas_witness.CLIENT_TIMEOUT_SECONDS", 0.15):
            with socket.create_connection(("127.0.0.1", port), timeout=1) as slow:
                slow.sendall(b"POST /v1/witness HTTP/1.1\r\nHost: localhost\r\n"
                             b"Content-Length: 80\r\nContent-Type: application/json\r\n"
                             b"X-Vera-Broker-HMAC: " + b"a" * 64 + b"\r\n\r\n{}")
                # The incomplete body must time out instead of pinning a worker.
                time.sleep(0.4)
        held = [server._slots.acquire(blocking=False) for _ in range(16)]
        self.assertTrue(all(held))
        self.assertFalse(server._slots.acquire(blocking=False))
        for _ in held:
            server._slots.release()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        self.addCleanup(conn.close)
        conn.request("GET", "/health")
        result = conn.getresponse()
        self.assertEqual(result.status, 200)
        self.assertFalse(json.loads(result.read())["gpu_lease_granted"])

    def test_http_rejects_early_eof_even_with_valid_body_hmac(self):
        server = make_server(self.engine, 0)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: thread.join(timeout=2))
        raw, mac = self.request()
        with socket.create_connection(("127.0.0.1", server.server_address[1]),
                                      timeout=2) as client:
            header = ("POST /v1/witness HTTP/1.0\r\nHost: localhost\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: {}\r\nX-Vera-Broker-HMAC: {}\r\n\r\n".format(
                          len(raw) + 1, mac)).encode("ascii")
            client.sendall(header + raw)
            client.shutdown(socket.SHUT_WR)
            response = client.recv(4096)
        self.assertIn(b" 422 ", response)
        self.assertEqual(self.engine.health()["seq"], 0)


if __name__ == "__main__":
    unittest.main()
