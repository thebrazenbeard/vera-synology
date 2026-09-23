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
EXCLUDED_TRACKED = {
    "SOURCE_MANIFEST.json",
    "CLA.md",
    "COMMERCIAL_LICENSE.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
}
EXCLUDED_TOP = {".git", "dist"}


class SourceEntry:
    __slots__ = ("path", "data", "archive_mode", "git_mode", "git_blob_sha")

    def __init__(self, path: str, data: bytes, archive_mode: int, git_mode: str, git_blob_sha: str) -> None:
        self.path = path
        self.data = data
        self.archive_mode = archive_mode
        self.git_mode = git_mode
        self.git_blob_sha = git_blob_sha


def _mode_for_rel(rel: str) -> int:
    if rel.startswith("spk/scripts/") or rel.startswith("payload/bin/") or rel.startswith("tools/"):
        return 0o755
    return 0o644


def _git_mode_for_rel(rel: str) -> str:
    return "100755" if _mode_for_rel(rel) == 0o755 else "100644"


def _git(args: list[str]) -> bytes:
    try:
        proc = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("exact Git HEAD source custody unavailable") from exc
    return proc.stdout


def _git_head_entries() -> dict[str, tuple[str, str, str]]:
    result: dict[str, tuple[str, str, str]] = {}
    for record in _git(["ls-tree", "-r", "-z", "HEAD"]).split(b"\0"):
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


def _git_blob_bytes(sha: str) -> bytes:
    data = _git(["cat-file", "blob", sha])
    if _git_blob_sha(data) != sha:
        raise ValueError(f"Git object identity mismatch: {sha}")
    return data


def _parse_source_paths(data: bytes) -> list[str]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SOURCE_PATHS must be strict UTF-8 JSON") from exc
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


def _read_worktree_regular(rel: str) -> bytes:
    path = ROOT / rel
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError(f"source path cannot be opened without following links: {rel}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"source entry is not a regular file: {rel}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def validated_source_snapshot() -> dict[str, SourceEntry]:
    head = _git_head_entries()
    source_paths_entry = head.get("SOURCE_PATHS.json")
    if source_paths_entry is None or source_paths_entry[:2] != ("100644", "blob"):
        raise ValueError("SOURCE_PATHS.json missing or wrong Git type/mode")
    expected = _parse_source_paths(_git_blob_bytes(source_paths_entry[2]))
    expected_set = set(expected)
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
        if rel_text in EXCLUDED_TRACKED:
            continue
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

    snapshot: dict[str, SourceEntry] = {}
    for rel in expected:
        mode, obj_type, head_sha = head[rel]
        expected_mode = _git_mode_for_rel(rel)
        if obj_type != "blob" or mode != expected_mode:
            raise ValueError(f"Git source type/mode mismatch: {rel}")
        worktree_data = _read_worktree_regular(rel)
        if _git_blob_sha(worktree_data) != head_sha:
            raise ValueError(f"worktree bytes differ from exact Git HEAD: {rel}")
        git_data = _git_blob_bytes(head_sha)
        snapshot[rel] = SourceEntry(
            path=rel,
            data=git_data,
            archive_mode=_mode_for_rel(rel),
            git_mode=mode,
            git_blob_sha=head_sha,
        )
    return snapshot


def validated_source_paths() -> list[str]:
    return list(validated_source_snapshot())


def source_manifest_entries(snapshot: dict[str, SourceEntry]) -> list[dict]:
    entries: list[dict] = []
    for rel, entry in snapshot.items():
        if not rel.startswith(("payload/", "spk/")):
            continue
        entries.append(
            {
                "path": rel,
                "type": "regular",
                "source_mode": f"{entry.archive_mode:04o}",
                "bytes": len(entry.data),
                "sha256": hashlib.sha256(entry.data).hexdigest(),
            }
        )
    return entries


def source_manifest_bytes(snapshot: dict[str, SourceEntry]) -> bytes:
    return (json.dumps(source_manifest_entries(snapshot), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


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


def build_package_tgz(snapshot: dict[str, SourceEntry] | None = None) -> bytes:
    if snapshot is None:
        snapshot = validated_source_snapshot()
    files: list[tuple[str, bytes, int]] = []
    for rel, entry in snapshot.items():
        if rel.startswith("payload/"):
            files.append((rel.removeprefix("payload/"), entry.data, entry.archive_mode))
    return _tar_bytes(files, gzipped=True)


def build_spk_bytes(snapshot: dict[str, SourceEntry] | None = None) -> bytes:
    if snapshot is None:
        snapshot = validated_source_snapshot()
    files: list[tuple[str, bytes, int]] = []
    for rel, entry in snapshot.items():
        if rel.startswith("spk/"):
            files.append((rel.removeprefix("spk/"), entry.data, entry.archive_mode))
    files.append(("package.tgz", build_package_tgz(snapshot), 0o644))
    return _tar_bytes(files, gzipped=False)


def _committed_manifest_bytes() -> bytes:
    head = _git_head_entries()
    entry = head.get("SOURCE_MANIFEST.json")
    if entry is None or entry[:2] != ("100644", "blob"):
        raise ValueError("committed SOURCE_MANIFEST.json missing or wrong Git type/mode")
    return _git_blob_bytes(entry[2])


def main() -> int:
    snapshot = validated_source_snapshot()
    expected_manifest = source_manifest_bytes(snapshot)
    if _committed_manifest_bytes() != expected_manifest:
        raise ValueError("committed SOURCE_MANIFEST.json does not match exact Git source snapshot")
    out = ROOT / "dist" / "VeraMesh-0.1.0-0017-live-edge.spk"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build_spk_bytes(snapshot))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
