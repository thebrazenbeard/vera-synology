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


def _read_regular_bytes_nofollow(path: Path) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("state path is not a regular file")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError("state file permissions too broad")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read()
    finally:
        os.close(fd)
    return data, st


def read_state(path: Path) -> dict:
    data, _ = _read_regular_bytes_nofollow(path)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("state file is not strict UTF-8 JSON") from exc
    return _validate_shape(value)


def _fsync_directory(path: Path) -> None:
    dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _safe_remove_same_inode(path: Path, st: os.stat_result) -> None:
    current = path.lstat()
    if current.st_dev != st.st_dev or current.st_ino != st.st_ino:
        raise ValueError("temporary state path changed during recovery")
    if not stat.S_ISREG(current.st_mode):
        raise ValueError("temporary state path changed type during recovery")
    path.unlink()


def _recover_stale_temp(tmp: Path, final: Path, parent_stat: os.stat_result) -> bool:
    try:
        lst = tmp.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(lst.st_mode):
        raise ValueError("temporary state path is not a regular file")
    if stat.S_IMODE(lst.st_mode) != 0o600:
        raise ValueError("temporary state file mode is not 0600")
    if lst.st_uid != parent_stat.st_uid or lst.st_gid != parent_stat.st_gid:
        raise ValueError("temporary state ownership differs from state parent")

    fd = os.open(tmp, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fst = os.fstat(fd)
        if fst.st_dev != lst.st_dev or fst.st_ino != lst.st_ino or not stat.S_ISREG(fst.st_mode):
            raise ValueError("temporary state changed during recovery")
        data = b""
        canonical = _canonical_bytes(DEFAULT_STATE)
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            if len(data) > len(canonical) + 4096:
                break
        if data == canonical:
            os.fsync(fd)
            current = tmp.lstat()
            if current.st_dev != fst.st_dev or current.st_ino != fst.st_ino:
                raise ValueError("temporary state changed before promotion")
            os.replace(tmp, final)
            _fsync_directory(final.parent)
            return True
    finally:
        os.close(fd)

    _safe_remove_same_inode(tmp, lst)
    _fsync_directory(tmp.parent)
    return False


def initialize(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        pst = path.parent.lstat()
        if not stat.S_ISDIR(pst.st_mode):
            raise ValueError("state parent is not a real directory")
        if stat.S_IMODE(pst.st_mode) & 0o077:
            os.chmod(path.parent, 0o700)
            pst = path.parent.lstat()
    except FileNotFoundError:
        raise ValueError("state parent missing after creation")
    if path.exists() or path.is_symlink():
        return read_state(path)

    tmp = path.with_name(path.name + ".new")
    data = _canonical_bytes(DEFAULT_STATE)
    for attempt in range(2):
        if _recover_stale_temp(tmp, path, pst):
            return read_state(path)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            if attempt == 0:
                continue
            raise ValueError("temporary state creation raced repeatedly")
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.close(fd)
            fd = -1
            current = tmp.lstat()
            if current.st_dev != created.st_dev or current.st_ino != created.st_ino:
                raise ValueError("temporary state changed before atomic promotion")
            os.replace(tmp, path)
            _fsync_directory(path.parent)
            return read_state(path)
        except Exception:
            if fd >= 0:
                os.close(fd)
            try:
                _safe_remove_same_inode(tmp, created)
            except FileNotFoundError:
                pass
            raise
    raise ValueError("temporary state recovery exhausted")


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
