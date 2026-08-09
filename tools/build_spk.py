#!/usr/bin/env python3
from __future__ import annotations
import gzip, hashlib, io, json, os, stat, subprocess, tarfile
from pathlib import Path
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
FIXED_MTIME=0
MANIFEST=ROOT/"SOURCE_MANIFEST.json"
PATHS=ROOT/"SOURCE_PATHS.json"
OUT_NAME="VeraMesh-0.1.0-0003-target-first-repair.spk"

def git(args):
    p=subprocess.run(["git",*args],cwd=ROOT,check=True,capture_output=True)
    return p.stdout

def git_tree():
    out={}
    for rec in git(["ls-tree","-r","-z","HEAD"]).split(b"\0"):
        if not rec: continue
        meta,raw=rec.split(b"\t",1)
        mode,typ,sha=meta.decode().split(" ")
        out[raw.decode()]=(mode,typ,sha)
    return out

def blob_bytes(sha):
    return git(["cat-file","blob",sha])

def mode_for(path):
    return 0o755 if path.startswith(("spk/scripts/","payload/app/","tools/")) else 0o644

def snapshot():
    head=git_tree()
    expected=json.loads(blob_bytes(head["SOURCE_PATHS.json"][2]).decode())
    if expected!=sorted(expected) or len(expected)!=len(set(expected)): raise ValueError("SOURCE_PATHS not sorted/unique")
    allowed=set(expected)|{"SOURCE_MANIFEST.json"}
    if set(head)!=allowed: raise ValueError(f"tracked path mismatch missing={sorted(allowed-set(head))} extra={sorted(set(head)-allowed)}")
    snap={}
    for rel in expected:
        mode,typ,sha=head[rel]
        want="100755" if mode_for(rel)==0o755 else "100644"
        if typ!="blob" or mode!=want: raise ValueError(f"mode/type mismatch {rel}")
        data=blob_bytes(sha)
        work=(ROOT/rel).read_bytes()
        if work!=data: raise ValueError(f"worktree differs from HEAD {rel}")
        snap[rel]=(data,mode_for(rel))
    return snap

def manifest_bytes(snap):
    entries=[]
    for rel,(data,mode) in snap.items():
        if rel.startswith(("payload/","spk/")):
            entries.append({"bytes":len(data),"path":rel,"sha256":hashlib.sha256(data).hexdigest(),"source_mode":f"{mode:04o}","type":"regular"})
    return (json.dumps(entries,sort_keys=True,separators=(",",":"))+"\n").encode()

def tar_bytes(files,gzipped):
    raw=io.BytesIO()
    target=raw
    gz=None
    if gzipped:
        gz=gzip.GzipFile(fileobj=raw,mode="wb",filename="",mtime=FIXED_MTIME,compresslevel=9)
        target=gz
    with tarfile.open(fileobj=target,mode="w",format=tarfile.USTAR_FORMAT) as tf:
        seen=set()
        for name,data,mode in sorted(files):
            if name in seen: raise ValueError(f"duplicate member {name}")
            seen.add(name)
            ti=tarfile.TarInfo(name); ti.size=len(data); ti.mode=mode; ti.mtime=FIXED_MTIME
            ti.uid=ti.gid=0; ti.uname=ti.gname=""
            tf.addfile(ti,io.BytesIO(data))
    if gz: gz.close()
    return raw.getvalue()


ICON_SIZES=(16,24,32,48,64,72,256)

def derived_icon_bytes(source_png: bytes, size: int) -> bytes:
    if size not in ICON_SIZES:
        raise ValueError(f"unsupported icon size {size}")
    with Image.open(io.BytesIO(source_png)) as im:
        rgba=im.convert("RGBA")
        if rgba.size != (64,64):
            raise ValueError(f"canonical PACKAGE_ICON.PNG must be 64x64, got {rgba.size}")
        resized=rgba if size==64 else rgba.resize((size,size), Image.Resampling.LANCZOS)
        out=io.BytesIO()
        resized.save(out,format="PNG",optimize=True)
        return out.getvalue()

def build(snap):
    canonical_icon=snap["spk/PACKAGE_ICON.PNG"][0]

    payload=[(rel[8:],data,mode) for rel,(data,mode) in snap.items() if rel.startswith("payload/")]
    for size in ICON_SIZES:
        payload.append((f"ui/images/app_{size}.png", derived_icon_bytes(canonical_icon,size), 0o644))
    package=tar_bytes(payload,True)

    outer=[(rel[4:],data,mode) for rel,(data,mode) in snap.items() if rel.startswith("spk/")]
    outer.append(("PACKAGE_ICON_256.PNG",derived_icon_bytes(canonical_icon,256),0o644))
    outer.append(("package.tgz",package,0o644))
    return tar_bytes(outer,False)

def main():
    snap=snapshot()
    expected=manifest_bytes(snap)
    if MANIFEST.read_bytes()!=expected: raise ValueError("SOURCE_MANIFEST mismatch")
    data=build(snap)
    out=ROOT/"dist"/OUT_NAME; out.parent.mkdir(exist_ok=True); out.write_bytes(data)
    print(out); print(hashlib.sha256(data).hexdigest()); print(len(data))
if __name__=="__main__": main()
