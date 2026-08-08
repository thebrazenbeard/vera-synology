#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import tarfile
from pathlib import Path

REQUIRED_OUTER = {
    "INFO",
    "package.tgz",
    "conf/PKG_DEPS",
    "conf/privilege",
    "conf/resource",
    "conf/systemd/pkguser-veramesh.service",
    "scripts/preinst",
    "scripts/postinst",
    "scripts/preuninst",
    "scripts/postuninst",
    "scripts/preupgrade",
    "scripts/postupgrade",
    "scripts/start-stop-status",
    "PACKAGE_ICON.PNG",
    "PACKAGE_ICON_256.PNG",
}
REQUIRED_PAYLOAD = {
    "bin/veramesh_state.py",
    "bin/veramesh_scaffold.py",
    "ui/config",
    "ui/index.html",
}


def _expected_mode(name: str, archive_kind: str) -> int:
    if archive_kind == "outer":
        return 0o755 if name.startswith("scripts/") else 0o644
    if archive_kind == "payload":
        return 0o755 if name.startswith("bin/") else 0o644
    raise ValueError(f"unknown archive kind: {archive_kind}")


def _members(tf: tarfile.TarFile, archive_kind: str) -> list[tarfile.TarInfo]:
    members = tf.getmembers()
    names = [m.name for m in members]
    if len(names) != len(set(names)):
        raise ValueError("duplicate archive member names")
    if names != sorted(names):
        raise ValueError("archive members are not sorted deterministically")
    for m in members:
        p = Path(m.name)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError("unsafe archive member path")
        if not m.isfile():
            raise ValueError("only regular files are permitted in scaffold archives")
        expected_mode = _expected_mode(m.name, archive_kind)
        if m.mode != expected_mode:
            raise ValueError(f"archive member mode mismatch: {m.name} expected {expected_mode:04o} got {m.mode:04o}")
        if m.uid != 0 or m.gid != 0 or m.mtime != 0 or m.uname != "" or m.gname != "":
            raise ValueError(f"archive member metadata mismatch: {m.name}")
    return members


def verify_bytes(spk: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(spk), mode="r:") as outer:
        outer_members = _members(outer, "outer")
        outer_names = {m.name for m in outer_members}
        missing = REQUIRED_OUTER - outer_names
        if missing:
            raise ValueError(f"missing outer members: {sorted(missing)}")
        info = outer.extractfile("INFO").read().decode("utf-8")
        required_info = ("package=\"VeraMesh\"", "version=\"0.0.1-0002\"", "os_min_ver=\"7.2-72806\"", "arch=\"noarch\"", "dsmuidir=\"ui\"", "dsmappname=\"com.vera.MeshScaffold\"")
        if not all(token in info for token in required_info):
            raise ValueError("INFO contract mismatch")
        privilege = json.loads(outer.extractfile("conf/privilege").read())
        if privilege.get("defaults", {}).get("run-as") != "package":
            raise ValueError("package must run lower privilege")
        resource = json.loads(outer.extractfile("conf/resource").read())
        if set(resource) != {"systemd-user-unit"}:
            raise ValueError("unexpected resource surface")
        package_tgz = outer.extractfile("package.tgz").read()
    with tarfile.open(fileobj=io.BytesIO(package_tgz), mode="r:gz") as inner:
        inner_members = _members(inner, "payload")
        inner_names = {m.name for m in inner_members}
        if any("__pycache__" in Path(name).parts or name.endswith(".pyc") for name in inner_names):
            raise ValueError("python bytecode/cache members are forbidden in package payload")
        missing = REQUIRED_PAYLOAD - inner_names
        if missing:
            raise ValueError(f"missing payload members: {sorted(missing)}")
    return {"outer_members": len(outer_members), "payload_members": len(inner_members)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spk", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_bytes(args.spk.read_bytes()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
