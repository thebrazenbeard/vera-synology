from __future__ import annotations

import gzip
import importlib.util
import io
import json
import subprocess
import tempfile
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


build_spk = load_module("build_spk_hardening", ROOT / "tools" / "build_spk.py")
verify_spk = load_module("verify_spk_hardening", ROOT / "tools" / "verify_spk.py")


class SourceSymlinkTests(unittest.TestCase):
    def test_payload_file_symlink_to_outside_root_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as td:
            outside = Path(td) / "outside.txt"
            outside.write_bytes(b"OUTSIDE_ROOT_SENTINEL")
            link = ROOT / "payload" / "linked-outside.txt"
            link.symlink_to(outside)
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    build_spk.build_package_tgz()
            finally:
                link.unlink(missing_ok=True)

    def test_in_root_file_symlink_is_rejected(self):
        link = ROOT / "spk" / "linked-info"
        link.symlink_to(ROOT / "spk" / "INFO")
        try:
            with self.assertRaisesRegex(ValueError, "symlink"):
                build_spk.build_spk_bytes()
        finally:
            link.unlink(missing_ok=True)

    def test_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as td:
            outside_dir = Path(td) / "outside-dir"
            outside_dir.mkdir()
            (outside_dir / "surprise.txt").write_bytes(b"SURPRISE")
            link_dir = ROOT / "payload" / "linked-dir"
            link_dir.symlink_to(outside_dir, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    build_spk.build_package_tgz()
            finally:
                link_dir.unlink(missing_ok=True)

    def test_source_manifest_rejects_symlink_and_binds_regular_type(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as td:
            outside = Path(td) / "outside.txt"
            outside.write_bytes(b"OUTSIDE_ROOT_SENTINEL")
            link = ROOT / "payload" / "manifest-linked.txt"
            link.symlink_to(outside)
            try:
                proc = subprocess.run(
                    ["python", str(ROOT / "tools" / "make_source_manifest.py")],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(0, proc.returncode, proc.stdout + proc.stderr)
                self.assertIn("symlink", (proc.stdout + proc.stderr).lower())
            finally:
                link.unlink(missing_ok=True)
        subprocess.run(["python", str(ROOT / "tools" / "make_source_manifest.py")], cwd=ROOT, check=True)
        entries = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text())
        self.assertTrue(entries)
        self.assertTrue(all(entry["type"] == "regular" for entry in entries))


class ArchiveMetadataTests(unittest.TestCase):
    @staticmethod
    def _repack_outer(mutate) -> bytes:
        original = build_spk.build_spk_bytes()
        files = []
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as tf:
            for member in tf.getmembers():
                data = tf.extractfile(member).read()
                copy = tarfile.TarInfo(member.name)
                copy.size = len(data)
                copy.mode = member.mode
                copy.mtime = member.mtime
                copy.uid = member.uid
                copy.gid = member.gid
                copy.uname = member.uname
                copy.gname = member.gname
                mutate(copy)
                files.append((copy, data))
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for member, data in files:
                tf.addfile(member, io.BytesIO(data))
        return raw.getvalue()

    @staticmethod
    def _repack_inner(mutate) -> bytes:
        original = build_spk.build_spk_bytes()
        outer_files = {}
        outer_meta = {}
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as outer:
            for member in outer.getmembers():
                outer_files[member.name] = outer.extractfile(member).read()
                outer_meta[member.name] = member
        inner_files = []
        with tarfile.open(fileobj=io.BytesIO(outer_files["package.tgz"]), mode="r:gz") as inner:
            for member in inner.getmembers():
                data = inner.extractfile(member).read()
                copy = tarfile.TarInfo(member.name)
                copy.size = len(data)
                copy.mode = member.mode
                copy.mtime = member.mtime
                copy.uid = member.uid
                copy.gid = member.gid
                copy.uname = member.uname
                copy.gname = member.gname
                mutate(copy)
                inner_files.append((copy, data))
        package_raw = io.BytesIO()
        with gzip.GzipFile(fileobj=package_raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for member, data in inner_files:
                    tf.addfile(member, io.BytesIO(data))
        outer_files["package.tgz"] = package_raw.getvalue()
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name in sorted(outer_files):
                old = outer_meta[name]
                ti = tarfile.TarInfo(name)
                data = outer_files[name]
                ti.size = len(data)
                ti.mode = old.mode
                ti.mtime = old.mtime
                ti.uid = old.uid
                ti.gid = old.gid
                ti.uname = old.uname
                ti.gname = old.gname
                tf.addfile(ti, io.BytesIO(data))
        return raw.getvalue()

    def test_nonexecutable_lifecycle_script_mode_is_rejected(self):
        bad = self._repack_outer(lambda m: setattr(m, "mode", 0o644) if m.name == "scripts/postinst" else None)
        with self.assertRaisesRegex(ValueError, "mode"):
            verify_spk.verify_bytes(bad)

    def test_nonexecutable_payload_program_mode_is_rejected(self):
        bad = self._repack_inner(lambda m: setattr(m, "mode", 0o644) if m.name == "bin/veramesh_state.py" else None)
        with self.assertRaisesRegex(ValueError, "mode"):
            verify_spk.verify_bytes(bad)

    def test_nondeterministic_ownership_or_mtime_is_rejected(self):
        def mutate(member):
            if member.name == "INFO":
                member.uid = 1000
                member.mtime = 1
        bad = self._repack_outer(mutate)
        with self.assertRaisesRegex(ValueError, "metadata"):
            verify_spk.verify_bytes(bad)


if __name__ == "__main__":
    unittest.main()
