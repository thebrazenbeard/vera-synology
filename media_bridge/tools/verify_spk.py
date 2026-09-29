#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import tarfile
from pathlib import Path, PurePosixPath

MEDIA_ROOT = "/var/packages/WorkBridgeMedia/shares/Media/Library"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_archive(archive: tarfile.TarFile) -> tuple[dict[str, bytes], dict[str, int]]:
    members = archive.getmembers()
    names = [member.name for member in members]
    if names != sorted(names):
        raise ValueError("archive entries are not deterministically sorted")
    if len(names) != len(set(names)):
        raise ValueError("archive contains duplicate members")

    payloads: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive path: {member.name}")
        if not member.isfile():
            raise ValueError(f"non-regular archive member: {member.name}")
        if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
            raise ValueError(f"nondeterministic archive metadata: {member.name}")
        fileobj = archive.extractfile(member)
        if fileobj is None:
            raise ValueError(f"missing archive payload: {member.name}")
        payloads[member.name] = fileobj.read()
        modes[member.name] = member.mode
    return payloads, modes


def require_armv7_elf(data: bytes, name: str) -> None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValueError(f"{name} is not ELF")
    if data[4] != 1:
        raise ValueError(f"{name} is not 32-bit ELF")
    if data[5] != 1:
        raise ValueError(f"{name} is not little-endian ELF")
    if struct.unpack("<H", data[18:20])[0] != 40:
        raise ValueError(f"{name} is not ARM ELF")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spk")
    args = parser.parse_args()
    spk_path = Path(args.spk)

    with tarfile.open(spk_path, "r:") as outer_archive:
        outer, outer_modes = read_archive(outer_archive)

    required_outer = {
        "INFO",
        "conf/privilege",
        "conf/resource",
        "conf/systemd/pkguser-workbridgemedia.service",
        "WIZARD_UIFILES/install_uifile",
        "scripts/postinst",
        "package.tgz",
    }
    missing_outer = sorted(required_outer - set(outer))
    if missing_outer:
        raise ValueError(f"missing outer SPK members: {missing_outer}")
    if outer_modes["scripts/postinst"] & 0o111 == 0:
        raise ValueError("postinst is not executable")

    info = outer["INFO"].decode("utf-8")
    for required in ('package="WorkBridgeMedia"', 'version="0.1.0-0001"', 'arch="armada38x"'):
        if required not in info:
            raise ValueError(f"INFO contract missing {required}")

    resource = json.loads(outer["conf/resource"])
    expected_shares = [{"name": "Media", "permission": {"rw": ["WorkBridgeMedia"]}}]
    if resource.get("data-share", {}).get("shares") != expected_shares:
        raise ValueError("DSM share authority differs from Media-only contract")

    privilege = json.loads(outer["conf/privilege"])
    if privilege != {
        "defaults": {"run-as": "package"},
        "username": "WorkBridgeMedia",
        "groupname": "WorkBridgeMedia",
    }:
        raise ValueError("package privilege contract mismatch")

    with tarfile.open(fileobj=io.BytesIO(outer["package.tgz"]), mode="r:gz") as inner_archive:
        inner, inner_modes = read_archive(inner_archive)

    required_inner = {
        "bin/workbridge-mcp",
        "bin/tunnel-client-runtime",
        "bin/run-workbridge-media.sh",
        "etc/workbridge-media.json",
        "provenance/component-bindings.json",
        "third_party/openai-tunnel-client-LICENSE",
        "third_party/openai-tunnel-client-NOTICE",
    }
    missing_inner = sorted(required_inner - set(inner))
    if missing_inner:
        raise ValueError(f"missing package payload members: {missing_inner}")

    for name in ("bin/workbridge-mcp", "bin/tunnel-client-runtime", "bin/run-workbridge-media.sh"):
        if inner_modes[name] & 0o111 == 0:
            raise ValueError(f"required executable mode missing: {name}")

    require_armv7_elf(inner["bin/workbridge-mcp"], "workbridge-mcp")
    require_armv7_elf(inner["bin/tunnel-client-runtime"], "tunnel-client-runtime")

    provenance = json.loads(inner["provenance/component-bindings.json"])
    if provenance.get("schema") != "WORKBRIDGE_MEDIA_RUNTIME_PROVENANCE_V1":
        raise ValueError("provenance schema mismatch")
    bindings = provenance["component_bindings"]
    if bindings["workbridge_mcp"]["commit"] != "8e0e9831adc2a6a8d41145c71c8bd64d9a489c77":
        raise ValueError("WorkBridge source binding mismatch")
    if bindings["openai_tunnel_client"]["commit"] != "a390c168ff1b2d14e73a95991c186c6aba3ff5a0":
        raise ValueError("tunnel-client source binding mismatch")

    wb_hash = sha256(inner["bin/workbridge-mcp"])
    tunnel_hash = sha256(inner["bin/tunnel-client-runtime"])
    if wb_hash != bindings["workbridge_mcp"]["qualified_binary_sha256"]:
        raise ValueError("WorkBridge binary hash mismatch")
    if tunnel_hash != bindings["openai_tunnel_client"]["qualified_binary_sha256"]:
        raise ValueError("tunnel-client binary hash mismatch")
    if provenance["artifacts"]["workbridge_mcp_sha256"] != wb_hash:
        raise ValueError("WorkBridge provenance hash mismatch")
    if provenance["artifacts"]["tunnel_client_runtime_sha256"] != tunnel_hash:
        raise ValueError("tunnel-client provenance hash mismatch")

    config = json.loads(inner["etc/workbridge-media.json"])
    if config.get("read_roots") != [MEDIA_ROOT] or config.get("write_roots") != [MEDIA_ROOT]:
        raise ValueError("WorkBridge root authority mismatch")
    if config.get("process", {}).get("enabled") is not False:
        raise ValueError("process execution must remain disabled")

    launcher = inner["bin/run-workbridge-media.sh"].decode("utf-8")
    if "--mcp.command" not in launcher or "--mcp.server-url" in launcher:
        raise ValueError("launcher must use stdio WorkBridge transport")
    if "127.0.0.1:17448" not in launcher:
        raise ValueError("health listener must remain loopback")
    if "file:$API_KEY_FILE" not in launcher:
        raise ValueError("runtime secret must be file-referenced")

    if not inner["third_party/openai-tunnel-client-LICENSE"].strip():
        raise ValueError("OpenAI tunnel-client LICENSE missing")
    if b"Copyright 2026 OpenAI" not in inner["third_party/openai-tunnel-client-NOTICE"]:
        raise ValueError("OpenAI tunnel-client NOTICE mismatch")

    print(json.dumps({
        "schema": "WORKBRIDGE_MEDIA_SPK_VERIFY_V1",
        "status": "PASS",
        "sha256": sha256(spk_path.read_bytes()),
        "bytes": spk_path.stat().st_size,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
