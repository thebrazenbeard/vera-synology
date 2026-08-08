#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_TOP = {"dist", ".git"}
EXCLUDED_NAMES = {"SOURCE_MANIFEST.json"}


def collect() -> list[dict]:
    entries: list[dict] = []
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in EXCLUDED_TOP:
            continue
        if path.name in EXCLUDED_NAMES or "__pycache__" in rel.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError(f"source symlink is forbidden: {rel.as_posix()}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        entries.append({
            "path": rel.as_posix(),
            "type": "regular",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return entries


def main() -> int:
    out = ROOT / "SOURCE_MANIFEST.json"
    out.write_text(json.dumps(collect(), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
