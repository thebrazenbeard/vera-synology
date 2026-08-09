#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import socket
import stat
import sys
from pathlib import Path

from veramesh_lifecycle import STATE_PATH as LIFECYCLE_STATE
from veramesh_lifecycle import StartupBinding, capture_startup_binding
from veramesh_state import verify

STATE = Path("/var/packages/VeraMesh/var/vera/scaffold-state.json")
RUN_DIR = Path("/var/packages/VeraMesh/tmp/run")
SOCKET_PATH = RUN_DIR / "control.sock"
MAX_REQUEST = 4096
CONNECTION_TIMEOUT_SECONDS = 1.0


def status_payload(binding: StartupBinding) -> dict:
    state = verify(STATE)
    return {
        "schema": "VERA_MESH_SCAFFOLD_STATUS_V1",
        "package_runtime": "RUNNING",
        "mesh_semantic_state": state["semantic_state"],
        "reason": state["reason"],
        "pairing_implemented": False,
        "tcp_mesh_listener": False,
        "mesh_delivery_implemented": False,
        "lifecycle_profile_id": binding.lifecycle_profile_id,
        "lifecycle_profile_sha256": binding.lifecycle_profile_sha256,
        "package_version": binding.package_version,
        "installation_incarnation_id": binding.installation_incarnation_id,
        "start_generation": binding.start_generation,
        "start_transition_id": binding.start_transition_id,
        "process_instance_id": binding.process_instance_id,
    }


def _prepare_socket_path() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    rst = RUN_DIR.lstat()
    if not stat.S_ISDIR(rst.st_mode):
        raise RuntimeError("run directory is not a real directory")
    os.chmod(RUN_DIR, 0o700)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        st = SOCKET_PATH.lstat()
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError("control socket path substituted by non-socket")
        SOCKET_PATH.unlink()


def _read_request_bytes(conn: socket.socket) -> tuple[bytes | None, str | None]:
    buf = bytearray()
    while True:
        try:
            chunk = conn.recv(min(1024, MAX_REQUEST + 1 - len(buf)))
        except TimeoutError:
            return None, "REQUEST_TIMEOUT"
        except ConnectionResetError:
            return None, "CLIENT_DISCONNECTED"
        if not chunk:
            return (bytes(buf), None) if buf else (None, "EMPTY_REQUEST")
        buf.extend(chunk)
        if len(buf) > MAX_REQUEST:
            return None, "REQUEST_TOO_LARGE"
        newline = buf.find(b"\n")
        if newline >= 0:
            if bytes(buf[newline + 1:]).strip():
                return None, "MULTIPLE_OR_TRAILING_REQUEST_DATA"
            return bytes(buf[:newline]), None


def _send_json_response(conn: socket.socket, response: dict) -> bool:
    payload = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        conn.sendall(payload)
    except (BrokenPipeError, ConnectionResetError):
        return False
    return True


def serve() -> int:
    verify(STATE)
    binding = capture_startup_binding(LIFECYCLE_STATE)
    _prepare_socket_path()
    stop = False

    def _term(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCKET_PATH))
        os.chmod(SOCKET_PATH, 0o600)
        server.listen(4)
        server.settimeout(1.0)
        while not stop:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(CONNECTION_TIMEOUT_SECONDS)
                data, framing_error = _read_request_bytes(conn)
                if framing_error is not None:
                    response = {"error": framing_error}
                else:
                    try:
                        request = json.loads(data.decode("utf-8"))
                    except Exception:
                        request = None
                    if request != {"op": "status"}:
                        response = {"error": "UNSUPPORTED_OPERATION"}
                    else:
                        response = status_payload(binding)
                _send_json_response(conn, response)
    finally:
        server.close()
        try:
            if SOCKET_PATH.exists() and stat.S_ISSOCK(SOCKET_PATH.lstat().st_mode):
                SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["serve"]:
        return serve()
    print("usage: veramesh_scaffold.py serve", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
