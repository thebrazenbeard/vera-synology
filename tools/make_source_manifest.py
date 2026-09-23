#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import build_spk

ROOT = Path(__file__).resolve().parents[1]


def collect(snapshot: dict[str, build_spk.SourceEntry] | None = None) -> list[dict]:
    if snapshot is None:
        snapshot = build_spk.validated_source_snapshot()
    return build_spk.source_manifest_entries(snapshot)


def main() -> int:
    snapshot = build_spk.validated_source_snapshot()
    out = ROOT / "SOURCE_MANIFEST.json"
    out.write_bytes(build_spk.source_manifest_bytes(snapshot))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
