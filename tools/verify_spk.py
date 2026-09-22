#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

REQUIRED_OUTER = {
    "INFO",
    "package.tgz",
    "conf/PKG_DEPS",
    "conf/privilege",
    "conf/resource",
    "conf/systemd/pkguser-veramesh.service",
    "scripts/preinst",
    "scripts/postinst",
    "scripts/preuninst",
    "scripts/postuninst",
    "scripts/preupgrade",
    "scripts/postupgrade",
    "scripts/start-stop-status",
    "PACKAGE_ICON.PNG",
    "PACKAGE_ICON_256.PNG",
}
REQUIRED_PAYLOAD = {
    "bin/veramesh_lifecycle.py",
    "bin/veramesh_state.py",
    "bin/veramesh_edge.py",
    "ui/config",
    "ui/index.html",
}
INFO_LINE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="([^"\r\n]*)"')
INFO_EXPECTED = {
    "package": "VeraMesh",
    "version": "0.1.0-0017",
    "os_min_ver": "7.2-72806",
    "description": "VeraMesh DS216 live edge proxy; VeraPort authentication remains end-to-end; durable relay is not implemented.",
    "arch": "armada38x",
    "maintainer": "V.E.R.A. Build Team Two",
    "thirdparty": "yes",
    "precheckstartstop": "yes",
    "dsmuidir": "ui",
    "dsmappname": "com.vera.MeshEdge",
}
PYTHON311_INTERPRETER = "/var/packages/python311/target/bin/python3.11"
EDGE_PROGRAM = "/var/packages/VeraMesh/target/bin/veramesh_edge.py"
PRIVILEGE_EXPECTED = {
    "defaults": {"run-as": "package"},
    "username": "VeraMesh",
    "groupname": "VeraMesh",
}
RESOURCE_EXPECTED = {"systemd-user-unit": {}}
PKG_DEPS_EXPECTED = {"python311": {"os_min_ver": "7.2-72806", "pkg_min_ver": "3.11"}}
SYSTEMD_EXPECTED = {
    "Unit": {"Description": "VeraMesh DS216 live edge proxy"},
    "Service": {
        "Type": "simple",
        "ExecStart": f"{PYTHON311_INTERPRETER} {EDGE_PROGRAM} serve",
        "Restart": "no",
        "UMask": "0077",
    },
    "Install": {"WantedBy": "default.target"},
}
LIFECYCLE_PROFILE_ID = "VERA_MESH_FIRST_SLICE_LIFECYCLE_PROFILE_V1"
LIFECYCLE_PROFILE_SHA256 = "3a33143546bb9796a1fd931b319941628bf7b40b1b82ac40738676836ea50046"
METADATA_PROFILE_ID = "SPK_DS216_LIVE_EDGE_V17_PROFILE_V1"
SPK_PROFILE_DESCRIPTOR = {
    "schema": METADATA_PROFILE_ID,
    "info": INFO_EXPECTED,
    "privilege": PRIVILEGE_EXPECTED,
    "resource": RESOURCE_EXPECTED,
    "pkg_deps": PKG_DEPS_EXPECTED,
    "systemd": SYSTEMD_EXPECTED,
    "required_payload": sorted(REQUIRED_PAYLOAD),
    "lifecycle_profile_id": LIFECYCLE_PROFILE_ID,
    "lifecycle_profile_sha256": LIFECYCLE_PROFILE_SHA256,
    "first_slice_acceptance_findings": [
        "MESH-FOUR-SPK-STATUS-UNKNOWN-COLLAPSE-007",
        "MESH-FOUR-SPK-PACKAGE-OWNED-INITIAL-STOPPED-GAP-008",
        "MESH-FOUR-SPK-LIFECYCLE-RESPONDER-BINDING-010",
    ],
    "release_later_not_acceptance_transferred": [
        "MESH-FOUR-SPK-INFO-ARCH-SCOPE-006",
        "MESH-FOUR-SPK-LIFECYCLE-CROSS-INSTALL-CONTAMINATION-009",
        "MESH-FOUR-SPK-LIFECYCLE-FAIL-SAFE-STOP-011",
        "MESH-SEVEN-SPK-LIFECYCLE-INCOMPLETE-TRANSITION-RECOVERY-012",
    ],
}
SPK_PROFILE_BYTES = json.dumps(
    SPK_PROFILE_DESCRIPTOR, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")
SPK_PROFILE_SHA256 = hashlib.sha256(SPK_PROFILE_BYTES).hexdigest()


def _expected_mode(name: str, archive_kind: str) -> int:
    if archive_kind == "outer":
        return 0o755 if name.startswith("scripts/") else 0o644
    if archive_kind == "payload":
        return 0o755 if name.startswith("bin/") else 0o644
    raise ValueError(f"unknown archive kind: {archive_kind}")


def _members(tf: tarfile.TarFile, archive_kind: str) -> list[tarfile.TarInfo]:
    members = tf.getmembers()
    names = [m.name for m in members]
    if len(names) != len(set(names)):
        raise ValueError("duplicate archive member names")
    if names != sorted(names):
        raise ValueError("archive members are not sorted deterministically")
    for m in members:
        p = Path(m.name)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError("unsafe archive member path")
        if not m.isfile():
            raise ValueError("only regular files are permitted in scaffold archives")
        expected = _expected_mode(m.name, archive_kind)
        if m.mode != expected:
            raise ValueError(f"archive member mode mismatch: {m.name} expected {expected:04o} got {m.mode:04o}")
        if m.uid != 0 or m.gid != 0 or m.mtime != 0 or m.uname != "" or m.gname != "":
            raise ValueError(f"archive member metadata mismatch: {m.name}")
    return members


def _parse_info(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("INFO is not strict UTF-8") from exc
    result: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise ValueError(f"INFO malformed blank line at {number}")
        match = INFO_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"INFO malformed assignment at line {number}")
        key, value = match.groups()
        if key in result:
            raise ValueError(f"INFO duplicate field: {key}")
        result[key] = value
    if result != INFO_EXPECTED:
        missing = sorted(set(INFO_EXPECTED) - set(result))
        unexpected = sorted(set(result) - set(INFO_EXPECTED))
        wrong = sorted(k for k in set(result) & set(INFO_EXPECTED) if result[k] != INFO_EXPECTED[k])
        raise ValueError(f"INFO contract mismatch missing={missing} unexpected={unexpected} wrong={wrong}")
    return result


def _reject_duplicate_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _parse_ini_profile(data: bytes, label: str) -> dict[str, dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not strict UTF-8") from exc
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=(),
        inline_comment_prefixes=(),
        empty_lines_in_values=False,
    )
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ValueError(f"{label} malformed INI") from exc
    if parser.defaults():
        raise ValueError(f"{label} defaults are forbidden")
    return {section: dict(parser.items(section, raw=True)) for section in parser.sections()}


def _parse_systemd_profile(data: bytes) -> dict[str, dict[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("systemd unit is not strict UTF-8") from exc
    result: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            raise ValueError(f"systemd comments are forbidden in frozen profile at line {number}")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if not section or section in result:
                raise ValueError(f"systemd duplicate/invalid section at line {number}")
            current = {}
            result[section] = current
            continue
        if current is None or "=" not in line:
            raise ValueError(f"systemd malformed directive at line {number}")
        key, value = line.split("=", 1)
        if not key or key in current:
            raise ValueError(f"systemd duplicate/invalid directive at line {number}")
        current[key] = value
    return result


def _validate_metadata_profile(outer: tarfile.TarFile) -> None:
    _parse_info(outer.extractfile("INFO").read())

    privilege = _parse_json_object(outer.extractfile("conf/privilege").read(), "conf/privilege")
    if privilege != PRIVILEGE_EXPECTED:
        raise ValueError("conf/privilege closed profile mismatch")

    resource = _parse_json_object(outer.extractfile("conf/resource").read(), "conf/resource")
    if resource != RESOURCE_EXPECTED:
        raise ValueError("conf/resource closed profile mismatch")

    pkg_deps = _parse_ini_profile(outer.extractfile("conf/PKG_DEPS").read(), "conf/PKG_DEPS")
    if pkg_deps != PKG_DEPS_EXPECTED:
        raise ValueError("conf/PKG_DEPS closed profile mismatch")

    systemd = _parse_systemd_profile(outer.extractfile("conf/systemd/pkguser-veramesh.service").read())
    if systemd != SYSTEMD_EXPECTED:
        raise ValueError("systemd closed profile mismatch")
    if not systemd["Service"]["ExecStart"].startswith(PYTHON311_INTERPRETER + " "):
        raise ValueError("systemd ExecStart is not cross-bound to python311")


def _manifest_map(entries: list[dict]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("source manifest entry must be object")
        path = entry.get("path")
        if not isinstance(path, str) or path in result:
            raise ValueError("source manifest path missing or duplicated")
        if set(entry) != {"bytes", "path", "sha256", "source_mode", "type"}:
            raise ValueError(f"source manifest entry schema mismatch: {path}")
        if entry["type"] != "regular" or entry["source_mode"] not in {"0644", "0755"}:
            raise ValueError(f"source manifest entry metadata mismatch: {path}")
        if not isinstance(entry["bytes"], int) or entry["bytes"] < 0:
            raise ValueError(f"source manifest byte count invalid: {path}")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError(f"source manifest sha256 invalid: {path}")
        result[path] = entry
    return result


def _verify_member_against_manifest(path: str, data: bytes, mode: int, manifest: dict[str, dict]) -> None:
    entry = manifest.get(path)
    if entry is None:
        raise ValueError(f"source manifest missing artifact member: {path}")
    if entry["bytes"] != len(data) or entry["sha256"] != hashlib.sha256(data).hexdigest():
        raise ValueError(f"artifact/source byte identity mismatch: {path}")
    if entry["source_mode"] != f"{mode:04o}":
        raise ValueError(f"artifact/source mode identity mismatch: {path}")


def verify_bytes(spk: bytes, source_manifest: list[dict] | None = None) -> dict:
    manifest = _manifest_map(source_manifest) if source_manifest is not None else None
    with tarfile.open(fileobj=io.BytesIO(spk), mode="r:") as outer:
        om = _members(outer, "outer")
        outer_names = {m.name for m in om}
        missing = REQUIRED_OUTER - outer_names
        if missing:
            raise ValueError(f"missing outer members: {sorted(missing)}")
        package_tgz = outer.extractfile("package.tgz").read()

        with tarfile.open(fileobj=io.BytesIO(package_tgz), mode="r:gz") as inner:
            im = _members(inner, "payload")
            inner_names = {m.name for m in im}
            if any("__pycache__" in Path(n).parts or n.endswith(".pyc") for n in inner_names):
                raise ValueError("python bytecode/cache members are forbidden in package payload")
            missing = REQUIRED_PAYLOAD - inner_names
            if missing:
                raise ValueError(f"missing payload members: {sorted(missing)}")
            if manifest is not None:
                for member in im:
                    source_path = "payload/" + member.name
                    data = inner.extractfile(member).read()
                    _verify_member_against_manifest(source_path, data, member.mode, manifest)

        _validate_metadata_profile(outer)

        if manifest is not None:
            for member in om:
                if member.name == "package.tgz":
                    continue
                source_path = "spk/" + member.name
                data = outer.extractfile(member).read()
                _verify_member_against_manifest(source_path, data, member.mode, manifest)
            expected_packaged = {path for path in manifest if path.startswith(("spk/", "payload/"))}
            actual_packaged = {"spk/" + n for n in outer_names if n != "package.tgz"} | {"payload/" + n for n in inner_names}
            if actual_packaged != expected_packaged:
                raise ValueError("artifact/source manifest path-set mismatch")

    return {
        "outer_members": len(om),
        "payload_members": len(im),
        "metadata_profile": METADATA_PROFILE_ID,
        "metadata_profile_sha256": SPK_PROFILE_SHA256,
        "lifecycle_profile": LIFECYCLE_PROFILE_ID,
        "lifecycle_profile_sha256": LIFECYCLE_PROFILE_SHA256,
        "source_manifest_crossbind": source_manifest is not None,
    }


def _load_manifest(path: Path) -> list[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_object_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SOURCE_MANIFEST.json unavailable or invalid") from exc
    if not isinstance(value, list):
        raise ValueError("SOURCE_MANIFEST.json must be an array")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spk", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("SOURCE_MANIFEST.json"))
    args = parser.parse_args()
    result = verify_bytes(args.spk.read_bytes(), _load_manifest(args.manifest))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
