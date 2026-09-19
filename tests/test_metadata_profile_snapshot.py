from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build_spk = load_module("build_spk_metadata_snapshot", ROOT / "tools" / "build_spk.py")
verify_spk = load_module("verify_spk_metadata_snapshot", ROOT / "tools" / "verify_spk.py")


def replace_outer_member(name: str, replacement: bytes) -> bytes:
    original = build_spk.build_spk_bytes()
    files: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as tf:
        for member in tf.getmembers():
            data = replacement if member.name == name else tf.extractfile(member).read()
            copy = tarfile.TarInfo(member.name)
            copy.size = len(data)
            copy.mode = member.mode
            copy.mtime = member.mtime
            copy.uid = member.uid
            copy.gid = member.gid
            copy.uname = member.uname
            copy.gname = member.gname
            files.append((copy, data))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member, data in files:
            tf.addfile(member, io.BytesIO(data))
    return raw.getvalue()


def replace_payload_member(name: str, replacement: bytes) -> bytes:
    original = build_spk.build_spk_bytes()
    outer_files: dict[str, bytes] = {}
    outer_meta: dict[str, tarfile.TarInfo] = {}
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as outer:
        for member in outer.getmembers():
            outer_files[member.name] = outer.extractfile(member).read()
            outer_meta[member.name] = member
    inner_files: list[tuple[str, bytes, int]] = []
    with tarfile.open(fileobj=io.BytesIO(outer_files["package.tgz"]), mode="r:gz") as inner:
        for member in inner.getmembers():
            data = replacement if member.name == name else inner.extractfile(member).read()
            inner_files.append((member.name, data, member.mode))
    outer_files["package.tgz"] = build_spk._tar_bytes(inner_files, gzipped=True)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member_name in sorted(outer_files):
            old = outer_meta[member_name]
            data = outer_files[member_name]
            ti = tarfile.TarInfo(member_name)
            ti.size = len(data)
            ti.mode = old.mode
            ti.mtime = old.mtime
            ti.uid = old.uid
            ti.gid = old.gid
            ti.uname = old.uname
            ti.gname = old.gname
            tf.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


class ImmutableSnapshotTests(unittest.TestCase):
    def test_build_uses_retained_git_bytes_after_worktree_mutation(self):
        snapshot = build_spk.validated_source_snapshot()
        path = ROOT / "payload" / "ui" / "index.html"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\nMUTATED_AFTER_VALIDATION\n")
            package = build_spk.build_package_tgz(snapshot)
            with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as tf:
                self.assertEqual(original, tf.extractfile("ui/index.html").read())
        finally:
            path.write_bytes(original)

    def test_source_manifest_is_derived_from_same_retained_snapshot(self):
        snapshot = build_spk.validated_source_snapshot()
        entries = build_spk.source_manifest_entries(snapshot)
        index = {entry["path"]: entry for entry in entries}
        entry = snapshot["payload/ui/index.html"]
        self.assertEqual(len(entry.data), index[entry.path]["bytes"])


class ClosedMetadataProfileTests(unittest.TestCase):
    def test_privilege_extra_capability_surface_is_rejected(self):
        hostile = b'{"defaults":{"run-as":"package"},"username":"VeraMesh","groupname":"VeraMesh","capabilities":["ALL"]}\n'
        with self.assertRaisesRegex(ValueError, "privilege"):
            verify_spk.verify_bytes(replace_outer_member("conf/privilege", hostile))

    def test_resource_nonempty_worker_is_rejected(self):
        hostile = b'{"systemd-user-unit":{"unexpected":"value"}}\n'
        with self.assertRaisesRegex(ValueError, "resource"):
            verify_spk.verify_bytes(replace_outer_member("conf/resource", hostile))

    def test_resource_duplicate_key_is_rejected(self):
        hostile = b'{"systemd-user-unit":{},"systemd-user-unit":{}}\n'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify_spk.verify_bytes(replace_outer_member("conf/resource", hostile))

    def test_wrong_pkg_deps_contract_is_rejected(self):
        hostile = b'[wrongpkg]\nos_min_ver=7.2-72806\npkg_min_ver=999\n'
        with self.assertRaisesRegex(ValueError, "PKG_DEPS"):
            verify_spk.verify_bytes(replace_outer_member("conf/PKG_DEPS", hostile))

    def test_systemd_alternate_execstart_is_rejected(self):
        hostile = (
            b'[Unit]\nDescription=VeraMesh DS216 live edge proxy\n\n'
            b'[Service]\nType=simple\nExecStart=/bin/sh -c hostile\nRestart=always\nUMask=0000\n\n'
            b'[Install]\nWantedBy=default.target\n'
        )
        with self.assertRaisesRegex(ValueError, "systemd"):
            verify_spk.verify_bytes(replace_outer_member("conf/systemd/pkguser-veramesh.service", hostile))

    def test_manifest_crossbind_rejects_modified_payload_member(self):
        manifest = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
        hostile = replace_payload_member("ui/index.html", b"different-but-valid-static-ui")
        with self.assertRaisesRegex(ValueError, "byte identity mismatch"):
            verify_spk.verify_bytes(hostile, manifest)


if __name__ == "__main__":
    unittest.main()
