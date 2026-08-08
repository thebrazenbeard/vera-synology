#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import socket
import stat
import sys
from pathlib import Path

from veramesh_state import verify

STATE = Path("/var/packages/VeraMesh/var/vera/scaffold-state.json")
RUN_DIR = Path("/var/packages/VeraMesh/tmp/run")
SOCKET_PATH = RUN_DIR / "control.sock"
MAX_REQUEST = 4096


def status_payload() -> dict:
    state = verify(STATE)
    return {
        "schema": "VERA_MESH_SCAFFOLD_STATUS_V1",
        "package_runtime": "RUNNING",
        "mesh_semantic_state": state["semantic_state"],
        "reason": state["reason"],
        "pairing_implemented": False,
        "tcp_mesh_listener": False,
        "mesh_delivery_implemented": False,
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


def serve() -> int:
    verify(STATE)
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
                data = conn.recv(MAX_REQUEST + 1)
                if len(data) > MAX_REQUEST:
                    response = {"error": "REQUEST_TOO_LARGE"}
                else:
                    try:
                        request = json.loads(data.decode("utf-8"))
                    except Exception:
                        request = None
                    if request != {"op": "status"}:
                        response = {"error": "UNSUPPORTED_OPERATION"}
                    else:
                        response = status_payload()
                conn.sendall((json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
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
    if argv[1:] == ["status"]:
        print(json.dumps(status_payload(), sort_keys=True, separators=(",", ":")))
        return 0
    print("usage: veramesh_scaffold.py {serve|status}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
