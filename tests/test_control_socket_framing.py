from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


state_mod = load_module("veramesh_state", ROOT / "payload" / "bin" / "veramesh_state.py")
sys.modules["veramesh_state"] = state_mod
lifecycle_mod = load_module("veramesh_lifecycle", ROOT / "payload" / "bin" / "veramesh_lifecycle.py")
sys.modules["veramesh_lifecycle"] = lifecycle_mod
edge_mod = load_module("veramesh_edge_framing", ROOT / "payload" / "bin" / "veramesh_edge.py")


class ControlSocketFramingTests(unittest.TestCase):
    def test_fragmented_status_request_is_reassembled_to_newline(self):
        reader, writer = socket.socketpair()
        reader.settimeout(1)

        def send_fragments():
            writer.sendall(b'{"op":')
            time.sleep(0.05)
            writer.sendall(b'"status"}\n')
            writer.close()

        thread = threading.Thread(target=send_fragments)
        thread.start()
        try:
            data, error = edge_mod._read_request_bytes(reader)
        finally:
            reader.close()
            thread.join(timeout=1)
        self.assertIsNone(error)
        self.assertEqual(b'{"op":"status"}', data)

    def test_disconnected_client_does_not_raise_when_response_is_sent(self):
        server_end, client_end = socket.socketpair()
        client_end.close()
        try:
            sent = edge_mod._send_json_response(server_end, {"schema": "TEST"})
        finally:
            server_end.close()
        self.assertFalse(sent)

    def test_reset_during_request_read_is_classified_not_raised(self):
        class ResettingConn:
            def recv(self, _size):
                raise ConnectionResetError("peer reset")
        data, error = edge_mod._read_request_bytes(ResettingConn())
        self.assertIsNone(data)
        self.assertEqual("CLIENT_DISCONNECTED", error)

    def test_multiple_requests_in_one_frame_are_rejected(self):
        reader, writer = socket.socketpair()
        reader.settimeout(1)
        try:
            writer.sendall(b'{"op":"status"}\n{"op":"status"}\n')
            data, error = edge_mod._read_request_bytes(reader)
        finally:
            reader.close()
            writer.close()
        self.assertIsNone(data)
        self.assertEqual("MULTIPLE_OR_TRAILING_REQUEST_DATA", error)


if __name__ == "__main__":
    unittest.main()
