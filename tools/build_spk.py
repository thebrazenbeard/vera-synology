#!/usr/bin/env python3
from __future__ import annotations

import gzip
import io
import os
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_MTIME = 0


def _mode_for(path: Path) -> int:
    rel = path.relative_to(ROOT).as_posix()
    if rel.startswith("spk/scripts/") or rel.startswith("payload/bin/") or rel.startswith("tools/"):
        return 0o755
    return 0o644


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
    files: list[tuple[str, bytes, int]] = []
    for path in sorted((ROOT / "payload").rglob("*")):
        rel = path.relative_to(ROOT / "payload")
        if "__pycache__" in rel.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError(f"source symlink is forbidden: payload/{rel.as_posix()}")
        if path.is_file():
            files.append((rel.as_posix(), path.read_bytes(), _mode_for(path)))
    return _tar_bytes(files, gzipped=True)


def build_spk_bytes() -> bytes:
    files: list[tuple[str, bytes, int]] = []
    for path in sorted((ROOT / "spk").rglob("*")):
        rel = path.relative_to(ROOT / "spk")
        if path.is_symlink():
            raise ValueError(f"source symlink is forbidden: spk/{rel.as_posix()}")
        if path.is_file():
            files.append((rel.as_posix(), path.read_bytes(), _mode_for(path)))
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
