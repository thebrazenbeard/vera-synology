#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import re
import tarfile
from pathlib import Path

REQUIRED_OUTER = {"INFO","package.tgz","conf/PKG_DEPS","conf/privilege","conf/resource","conf/systemd/pkguser-veramesh.service","scripts/preinst","scripts/postinst","scripts/preuninst","scripts/postuninst","scripts/preupgrade","scripts/postupgrade","scripts/start-stop-status","PACKAGE_ICON.PNG","PACKAGE_ICON_256.PNG"}
REQUIRED_PAYLOAD = {"bin/veramesh_state.py","bin/veramesh_scaffold.py","ui/config","ui/index.html"}
INFO_LINE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="([^"\r\n]*)"')
INFO_EXPECTED = {"package":"VeraMesh","version":"0.0.1-0002","os_min_ver":"7.2-72806","description":"Vera Mesh first-install scaffold; Mesh transport is not implemented in this candidate.","arch":"noarch","maintainer":"V.E.R.A. Build Team Two","thirdparty":"yes","precheckstartstop":"yes","dsmuidir":"ui","dsmappname":"com.vera.MeshScaffold"}

def _expected_mode(name: str, archive_kind: str) -> int:
    if archive_kind == "outer": return 0o755 if name.startswith("scripts/") else 0o644
    if archive_kind == "payload": return 0o755 if name.startswith("bin/") else 0o644
    raise ValueError(f"unknown archive kind: {archive_kind}")

def _members(tf: tarfile.TarFile, archive_kind: str) -> list[tarfile.TarInfo]:
    members=tf.getmembers(); names=[m.name for m in members]
    if len(names)!=len(set(names)): raise ValueError("duplicate archive member names")
    if names!=sorted(names): raise ValueError("archive members are not sorted deterministically")
    for m in members:
        p=Path(m.name)
        if p.is_absolute() or ".." in p.parts: raise ValueError("unsafe archive member path")
        if not m.isfile(): raise ValueError("only regular files are permitted in scaffold archives")
        expected=_expected_mode(m.name,archive_kind)
        if m.mode!=expected: raise ValueError(f"archive member mode mismatch: {m.name} expected {expected:04o} got {m.mode:04o}")
        if m.uid!=0 or m.gid!=0 or m.mtime!=0 or m.uname!="" or m.gname!="": raise ValueError(f"archive member metadata mismatch: {m.name}")
    return members

def _parse_info(data: bytes) -> dict[str,str]:
    try: text=data.decode("utf-8")
    except UnicodeDecodeError as exc: raise ValueError("INFO is not strict UTF-8") from exc
    result={}
    for number,line in enumerate(text.splitlines(),1):
        if not line: raise ValueError(f"INFO malformed blank line at {number}")
        match=INFO_LINE.fullmatch(line)
        if match is None: raise ValueError(f"INFO malformed assignment at line {number}")
        key,value=match.groups()
        if key in result: raise ValueError(f"INFO duplicate field: {key}")
        result[key]=value
    if result!=INFO_EXPECTED:
        missing=sorted(set(INFO_EXPECTED)-set(result)); unexpected=sorted(set(result)-set(INFO_EXPECTED)); wrong=sorted(k for k in set(result)&set(INFO_EXPECTED) if result[k]!=INFO_EXPECTED[k])
        raise ValueError(f"INFO contract mismatch missing={missing} unexpected={unexpected} wrong={wrong}")
    return result

def verify_bytes(spk: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(spk),mode="r:") as outer:
        om=_members(outer,"outer"); names={m.name for m in om}; missing=REQUIRED_OUTER-names
        if missing: raise ValueError(f"missing outer members: {sorted(missing)}")
        _parse_info(outer.extractfile("INFO").read())
        privilege=json.loads(outer.extractfile("conf/privilege").read())
        if privilege.get("defaults",{}).get("run-as")!="package": raise ValueError("package must run lower privilege")
        resource=json.loads(outer.extractfile("conf/resource").read())
        if set(resource)!={"systemd-user-unit"}: raise ValueError("unexpected resource surface")
        package_tgz=outer.extractfile("package.tgz").read()
    with tarfile.open(fileobj=io.BytesIO(package_tgz),mode="r:gz") as inner:
        im=_members(inner,"payload"); names={m.name for m in im}
        if any("__pycache__" in Path(n).parts or n.endswith(".pyc") for n in names): raise ValueError("python bytecode/cache members are forbidden in package payload")
        missing=REQUIRED_PAYLOAD-names
        if missing: raise ValueError(f"missing payload members: {sorted(missing)}")
    return {"outer_members":len(om),"payload_members":len(im)}

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("spk",type=Path); args=parser.parse_args(); print(json.dumps(verify_bytes(args.spk.read_bytes()),sort_keys=True)); return 0

if __name__=="__main__": raise SystemExit(main())
