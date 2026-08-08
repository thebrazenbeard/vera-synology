#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = ROOT / "SOURCE_PATHS.json"
FIXED_MTIME = 0
EXCLUDED_TRACKED = {"SOURCE_MANIFEST.json"}
EXCLUDED_TOP = {".git", "dist"}


def _mode_for_rel(rel: str) -> int:
    if rel.startswith("spk/scripts/") or rel.startswith("payload/bin/") or rel.startswith("tools/"):
        return 0o755
    return 0o644


def _git_mode_for_rel(rel: str) -> str:
    return "100755" if _mode_for_rel(rel) == 0o755 else "100644"


def _expected_source_paths() -> list[str]:
    value = json.loads(SOURCE_PATHS.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value):
        raise ValueError("SOURCE_PATHS must be a nonempty string array")
    if value != sorted(value) or len(value) != len(set(value)):
        raise ValueError("SOURCE_PATHS must be unique and lexicographically sorted")
    if "SOURCE_PATHS.json" not in value:
        raise ValueError("SOURCE_PATHS must bind itself")
    for rel in value:
        p = Path(rel)
        if p.is_absolute() or ".." in p.parts or rel in EXCLUDED_TRACKED:
            raise ValueError(f"unsafe source path: {rel}")
    return value


def _git_head_entries() -> dict[str, tuple[str, str, str]]:
    try:
        proc = subprocess.run(
            ["git", "ls-tree", "-r", "-z", "HEAD"], cwd=ROOT, check=True, capture_output=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("exact Git HEAD source custody unavailable") from exc
    result: dict[str, tuple[str, str, str]] = {}
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        meta, raw_path = record.split(b"\t", 1)
        mode, obj_type, sha = meta.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if path in result:
            raise ValueError(f"duplicate Git tree path: {path}")
        result[path] = (mode, obj_type, sha)
    return result


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def validated_source_paths() -> list[str]:
    expected = _expected_source_paths()
    expected_set = set(expected)
    head = _git_head_entries()
    allowed_tracked = expected_set | EXCLUDED_TRACKED
    if set(head) != allowed_tracked:
        missing = sorted(allowed_tracked - set(head))
        extra = sorted(set(head) - allowed_tracked)
        raise ValueError(f"Git HEAD source path-set mismatch missing={missing} unexpected={extra}")

    observed: set[str] = set()
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in EXCLUDED_TOP:
            continue
        if path.name == "SOURCE_MANIFEST.json" or "__pycache__" in rel.parts or path.suffix == ".pyc":
            continue
        rel_text = rel.as_posix()
        if path.is_symlink():
            raise ValueError(f"source symlink is forbidden: {rel_text}")
        st = path.lstat()
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"source entry is not a regular file: {rel_text}")
        observed.add(rel_text)
    if observed != expected_set:
        missing = sorted(expected_set - observed)
        extra = sorted(observed - expected_set)
        raise ValueError(f"worktree source path-set mismatch missing={missing} unexpected={extra}")

    for rel in expected:
        mode, obj_type, head_sha = head[rel]
        if obj_type != "blob" or mode != _git_mode_for_rel(rel):
            raise ValueError(f"Git source type/mode mismatch: {rel}")
        path = ROOT / rel
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or path.is_symlink():
            raise ValueError(f"source path is not a direct regular file: {rel}")
        data = path.read_bytes()
        if _git_blob_sha(data) != head_sha:
            raise ValueError(f"worktree bytes differ from exact Git HEAD: {rel}")
    return expected


def _tar_bytes(files: list[tuple[str, bytes, int]], gzipped: bool) -> bytes:
    raw = io.BytesIO()
    target = raw
    gz = None
    if gzipped:
        gz = gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=FIXED_MTIME, compresslevel=9)
        target = gz
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        seen: set[str] = set()
        for name, data, mode in sorted(files, key=lambda item: item[0]):
            if name in seen:
                raise ValueError(f"duplicate tar member: {name}")
            seen.add(name)
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = mode
            ti.mtime = FIXED_MTIME
            ti.uid = 0
            ti.gid = 0
            ti.uname = ""
            ti.gname = ""
            tf.addfile(ti, io.BytesIO(data))
    if gz is not None:
        gz.close()
    return raw.getvalue()


def build_package_tgz() -> bytes:
    paths = validated_source_paths()
    files: list[tuple[str, bytes, int]] = []
    for rel in paths:
        if not rel.startswith("payload/"):
            continue
        path = ROOT / rel
        member = rel.removeprefix("payload/")
        files.append((member, path.read_bytes(), _mode_for_rel(rel)))
    return _tar_bytes(files, gzipped=True)


def build_spk_bytes() -> bytes:
    paths = validated_source_paths()
    files: list[tuple[str, bytes, int]] = []
    for rel in paths:
        if not rel.startswith("spk/"):
            continue
        path = ROOT / rel
        member = rel.removeprefix("spk/")
        files.append((member, path.read_bytes(), _mode_for_rel(rel)))
    files.append(("package.tgz", build_package_tgz(), 0o644))
    return _tar_bytes(files, gzipped=False)


def main() -> int:
    out = ROOT / "dist" / "VeraMesh-0.0.1-0002-reconstructed-scaffold.spk"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build_spk_bytes())
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
