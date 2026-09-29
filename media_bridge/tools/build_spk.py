#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEDIA = ROOT / "media_bridge"
VERSION = "0.1.0-0001"
ARCH = "armada38x"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def add_tree(out: dict[str, tuple[bytes, int]], root: Path, prefix: str = "") -> None:
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsupported source entry: {path}")
        rel = path.relative_to(root).as_posix()
        name = f"{prefix}/{rel}" if prefix else rel
        mode = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
        out[name] = (path.read_bytes(), mode)


def tar_bytes(files: dict[str, tuple[bytes, int]], compress: bool) -> bytes:
    raw = io.BytesIO()
    target = raw
    gz = None
    if compress:
        gz = gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9)
        target = gz
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    if gz is not None:
        gz.close()
    return raw.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workbridge-bin", required=True)
    parser.add_argument("--tunnel-bin", required=True)
    parser.add_argument("--source-head", required=True)
    args = parser.parse_args()

    workbridge = Path(args.workbridge_bin).read_bytes()
    tunnel = Path(args.tunnel_bin).read_bytes()
    bindings = json.loads((MEDIA / "component-bindings.json").read_text(encoding="utf-8"))

    if sha256(workbridge) != bindings["workbridge_mcp"]["qualified_binary_sha256"]:
        raise SystemExit("WorkBridge ARMv7 binary digest does not match qualified binding")
    if sha256(tunnel) != bindings["openai_tunnel_client"]["qualified_binary_sha256"]:
        raise SystemExit("tunnel-client ARMv7 binary digest does not match qualified binding")

    inner: dict[str, tuple[bytes, int]] = {}
    add_tree(inner, MEDIA / "payload")
    add_tree(inner, MEDIA / "third_party", "third_party")
    inner["bin/workbridge-mcp"] = (workbridge, 0o755)
    inner["bin/tunnel-client-runtime"] = (tunnel, 0o755)

    provenance = {
        "schema": "WORKBRIDGE_MEDIA_RUNTIME_PROVENANCE_V1",
        "package_version": VERSION,
        "package_arch": ARCH,
        "source_head": args.source_head,
        "component_bindings": bindings,
        "artifacts": {
            "workbridge_mcp_sha256": sha256(workbridge),
            "tunnel_client_runtime_sha256": sha256(tunnel),
        },
    }
    inner["provenance/component-bindings.json"] = (
        (json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        0o644,
    )

    outer: dict[str, tuple[bytes, int]] = {}
    add_tree(outer, MEDIA / "spk")
    outer["package.tgz"] = (tar_bytes(inner, True), 0o644)

    output = ROOT / "dist" / f"WorkBridgeMedia-{VERSION}-{ARCH}.spk"
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = tar_bytes(outer, False)
    output.write_bytes(payload)
    print(json.dumps({"path": str(output), "sha256": sha256(payload), "bytes": len(payload)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
