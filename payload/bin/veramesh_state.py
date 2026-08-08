#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

SCHEMA = "VERA_MESH_SCAFFOLD_STATE_V1"
ALLOWED_STATES = {"UNPAIRED_READY", "READY", "DEGRADED", "BLOCKED"}
DEFAULT_STATE = {
    "schema": SCHEMA,
    "semantic_state": "BLOCKED",
    "reason": "BLOCKED_MESH_NOT_IMPLEMENTED",
    "mesh_implemented": False,
    "pairing_implemented": False,
    "tcp_mesh_listener": False,
    "trust_identity_generated": False,
    "mesh_delivery_implemented": False,
}


def _canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _validate_shape(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("state must be object")
    if value.get("schema") != SCHEMA:
        raise ValueError("wrong state schema")
    if value.get("semantic_state") not in ALLOWED_STATES:
        raise ValueError("invalid semantic state")
    if value.get("mesh_implemented") is not False:
        raise ValueError("scaffold may not claim Mesh implementation")
    if value.get("semantic_state") != "BLOCKED" or value.get("reason") != "BLOCKED_MESH_NOT_IMPLEMENTED":
        raise ValueError("scaffold must remain fail-closed")
    for key in ("pairing_implemented", "tcp_mesh_listener", "trust_identity_generated", "mesh_delivery_implemented"):
        if value.get(key) is not False:
            raise ValueError(f"scaffold invariant failed: {key}")
    return value


def read_state(path: Path) -> dict:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("state path is not a regular file")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError("state file permissions too broad")
    with path.open("r", encoding="utf-8") as fh:
        return _validate_shape(json.load(fh))


def initialize(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        pst = path.parent.lstat()
        if not stat.S_ISDIR(pst.st_mode):
            raise ValueError("state parent is not a real directory")
        if stat.S_IMODE(pst.st_mode) & 0o077:
            os.chmod(path.parent, 0o700)
    except FileNotFoundError:
        raise ValueError("state parent missing after creation")
    if path.exists() or path.is_symlink():
        return read_state(path)
    tmp = path.with_name(path.name + ".new")
    data = _canonical_bytes(DEFAULT_STATE)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    return read_state(path)


def verify(path: Path) -> dict:
    return read_state(path)


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"initialize", "verify"}:
        print("usage: veramesh_state.py {initialize|verify} STATE_PATH", file=sys.stderr)
        return 64
    path = Path(argv[2])
    try:
        state = initialize(path) if argv[1] == "initialize" else verify(path)
    except Exception as exc:
        print(f"BLOCKED_STATE_INTEGRITY: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(state, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
