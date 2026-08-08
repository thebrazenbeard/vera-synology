#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import build_spk

ROOT = Path(__file__).resolve().parents[1]


def collect() -> list[dict]:
    entries: list[dict] = []
    for rel in build_spk.validated_source_paths():
        if not (rel.startswith("payload/") or rel.startswith("spk/")):
            continue
        path = ROOT / rel
        data = path.read_bytes()
        entries.append(
            {
                "path": rel,
                "type": "regular",
                "source_mode": f"{build_spk._mode_for_rel(rel):04o}",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return entries


def main() -> int:
    out = ROOT / "SOURCE_MANIFEST.json"
    out.write_text(json.dumps(collect(), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
