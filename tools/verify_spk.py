#!/usr/bin/env python3
from __future__ import annotations
import hashlib, io, json, os, tarfile
from pathlib import Path
from PIL import Image
from build_spk import derived_icon_bytes

ROOT=Path(__file__).resolve().parents[1]
SPK=ROOT/"dist"/"VeraMesh-0.1.0-0003-target-first-repair.spk"

def safe_members(tf):
    names=[]
    for m in tf.getmembers():
        if m.name in names: raise ValueError(f"duplicate member:{m.name}")
        names.append(m.name)
        p=Path(m.name)
        if p.is_absolute() or ".." in p.parts: raise ValueError(f"unsafe path:{m.name}")
        if m.issym() or m.islnk(): raise ValueError(f"link forbidden:{m.name}")
    return names

def main():
    data=SPK.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:") as tf:
        outer=safe_members(tf)
        for required in ["INFO","package.tgz","conf/privilege","conf/resource","scripts/start-stop-status","PACKAGE_ICON.PNG","PACKAGE_ICON_256.PNG"]:
            if required not in outer: raise ValueError(f"missing:{required}")
        info=tf.extractfile("INFO").read().decode()
        for needle in ['package="VeraMesh"','version="0.1.0-0003"','arch="armada38x"','install_dep_packages="Node.js_v22"','dsmuidir="ui"','dsmappname="com.vera.Mesh"']:
            if needle not in info: raise ValueError(f"INFO missing {needle}")
        canonical=(ROOT/"spk/PACKAGE_ICON.PNG").read_bytes()
        icon64=tf.extractfile("PACKAGE_ICON.PNG").read()
        icon256=tf.extractfile("PACKAGE_ICON_256.PNG").read()
        if icon64!=canonical: raise ValueError("PACKAGE_ICON.PNG differs from canonical source")
        if icon256!=derived_icon_bytes(canonical,256): raise ValueError("PACKAGE_ICON_256.PNG derivation mismatch")
        for name,b,size in [("PACKAGE_ICON.PNG",icon64,(64,64)),("PACKAGE_ICON_256.PNG",icon256,(256,256))]:
            with Image.open(io.BytesIO(b)) as im:
                if im.size!=size: raise ValueError(f"{name} size {im.size}")
        pkg=tf.extractfile("package.tgz").read()
    with tarfile.open(fileobj=io.BytesIO(pkg),mode="r:gz") as pt:
        nested=safe_members(pt)
        for required in ["app/veramesh_daemon.js","ui/config","ui/index.html","ui/runtime-status.json","ui/images/app_16.png","ui/images/app_24.png","ui/images/app_32.png","ui/images/app_48.png","ui/images/app_64.png","ui/images/app_72.png","ui/images/app_256.png"]:
            if required not in nested: raise ValueError(f"payload missing:{required}")
        canonical=(ROOT/"spk/PACKAGE_ICON.PNG").read_bytes()
        for size in (16,24,32,48,64,72,256):
            observed=pt.extractfile(f"ui/images/app_{size}.png").read()
            expected=derived_icon_bytes(canonical,size)
            if observed!=expected: raise ValueError(f"ui icon derivation mismatch:{size}")
    print("SPK_OK",hashlib.sha256(data).hexdigest(),len(data),"outer",len(outer),"payload",len(nested))
if __name__=="__main__": main()
