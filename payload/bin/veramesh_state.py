#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, stat, sys
from pathlib import Path

SCHEMA="VERA_MESH_EDGE_STATE_V1"
ALLOWED_STATES={"READY","DEGRADED","BLOCKED"}
LEGACY_SCAFFOLD_STATE_V1={
    "schema":"VERA_MESH_SCAFFOLD_STATE_V1",
    "semantic_state":"BLOCKED",
    "reason":"BLOCKED_MESH_NOT_IMPLEMENTED",
    "mesh_implemented":False,
    "pairing_implemented":False,
    "tcp_mesh_listener":False,
    "trust_identity_generated":False,
    "mesh_delivery_implemented":False,
}
DEFAULT_STATE={
    "schema":SCHEMA,
    "semantic_state":"READY",
    "reason":"LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED",
    "mesh_implemented":True,
    "pairing_implemented":False,
    "tcp_mesh_listener":True,
    "trust_identity_generated":False,
    "mesh_delivery_implemented":True,
    "edge_proxy_implemented":True,
    "durable_relay_implemented":False,
    "end_to_end_veraport_auth_preserved":True,
}
def _canonical_bytes(v): return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def _validate_shape(v):
    if not isinstance(v,dict) or set(v)!=set(DEFAULT_STATE): raise ValueError("state shape mismatch")
    if v!=DEFAULT_STATE: raise ValueError("edge state contract mismatch")
    return v
def _read_regular_bytes_nofollow(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode): raise ValueError("state path is not regular")
        if stat.S_IMODE(st.st_mode)&0o077: raise ValueError("state file permissions too broad")
        with os.fdopen(fd,"rb",closefd=False) as fh: data=fh.read()
    finally: os.close(fd)
    return data,st
def read_state(path):
    data,_=_read_regular_bytes_nofollow(path)
    try: value=json.loads(data.decode("utf-8"))
    except Exception as exc: raise ValueError("state file is not strict UTF-8 JSON") from exc
    return _validate_shape(value)
def _fsync_directory(path):
    dfd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dfd)
    finally: os.close(dfd)
def _safe_remove_same_inode(path,st):
    cur=path.lstat()
    if cur.st_dev!=st.st_dev or cur.st_ino!=st.st_ino or not stat.S_ISREG(cur.st_mode):
        raise ValueError("temporary state changed during recovery")
    path.unlink()

def _legacy_archive_path(parent):
    digest=hashlib.sha256(_canonical_bytes(LEGACY_SCAFFOLD_STATE_V1)).hexdigest()[:16]
    return parent/(".legacy-scaffold-"+digest)

def _ensure_private_archive(archive,parent_stat):
    try: archive.mkdir(mode=0o700)
    except FileExistsError: pass
    st=archive.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o700:
        raise ValueError("legacy archive is not private directory")
    if st.st_uid!=parent_stat.st_uid or st.st_gid!=parent_stat.st_gid:
        raise ValueError("legacy archive ownership mismatch")
    return st

def _archive_legacy_file(src,dst,parent_stat):
    try: st=src.lstat()
    except FileNotFoundError: return False
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("legacy predecessor path is not regular")
    if stat.S_IMODE(st.st_mode)!=0o600:
        raise ValueError("legacy predecessor mode must be 0600")
    if st.st_uid!=parent_stat.st_uid or st.st_gid!=parent_stat.st_gid:
        raise ValueError("legacy predecessor ownership mismatch")
    if dst.exists() or dst.is_symlink():
        raise ValueError("legacy archive destination collision")
    os.replace(src,dst)
    return True

def _write_legacy_receipt(archive):
    entries=[]
    for name in ("lifecycle.lock","lifecycle-state.json","scaffold-state.json"):
        p=archive/name
        if not p.exists(): continue
        data,st=_read_regular_bytes_nofollow(p)
        entries.append({"path":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
    receipt={"schema":"VERA_MESH_LEGACY_MIGRATION_RECEIPT_V1","source":"VERA_MESH_SCAFFOLD_STATE_V1","files":entries}
    data=_canonical_bytes(receipt)
    out=archive/"MIGRATION_RECEIPT.json"
    if out.exists():
        existing,_=_read_regular_bytes_nofollow(out)
        if existing!=data: raise ValueError("legacy migration receipt mismatch")
        return
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,data); os.fsync(fd)
    finally: os.close(fd)

def _migrate_exact_legacy(path,parent_stat):
    archive=_legacy_archive_path(path.parent)
    legacy_present=False
    try:
        data,st=_read_regular_bytes_nofollow(path)
    except FileNotFoundError:
        data=None
    if data is not None:
        try: value=json.loads(data.decode("utf-8"))
        except Exception: return False
        if value==DEFAULT_STATE: return False
        if value!=LEGACY_SCAFFOLD_STATE_V1: return False
        if st.st_uid!=parent_stat.st_uid or st.st_gid!=parent_stat.st_gid:
            raise ValueError("legacy scaffold ownership mismatch")
        legacy_present=True
    if not legacy_present and not archive.exists():
        return False
    if (path.parent/"edge-config.json").exists() or (path.parent/"edge-config.json").is_symlink():
        raise ValueError("mixed-generation edge config blocks legacy migration")
    _ensure_private_archive(archive,parent_stat)
    for name in ("lifecycle.lock","lifecycle-state.json","scaffold-state.json"):
        _archive_legacy_file(path.parent/name,archive/name,parent_stat)
    _write_legacy_receipt(archive)
    _fsync_directory(archive)
    _fsync_directory(path.parent)
    return True

def _recover_stale_temp(tmp,final,parent_stat):
    try: lst=tmp.lstat()
    except FileNotFoundError: return False
    if not stat.S_ISREG(lst.st_mode):
        raise ValueError("temporary state path is not a regular file")
    if stat.S_IMODE(lst.st_mode)!=0o600:
        raise ValueError("temporary state mode must be 0600")
    if lst.st_uid!=parent_stat.st_uid or lst.st_gid!=parent_stat.st_gid: raise ValueError("temporary state ownership mismatch")
    fd=os.open(tmp,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fst=os.fstat(fd); data=b""; canonical=_canonical_bytes(DEFAULT_STATE)
        while True:
            chunk=os.read(fd,65536)
            if not chunk: break
            data+=chunk
            if len(data)>len(canonical)+4096: break
        if data==canonical:
            os.fsync(fd); cur=tmp.lstat()
            if cur.st_dev!=fst.st_dev or cur.st_ino!=fst.st_ino: raise ValueError("temporary state changed")
            os.replace(tmp,final); _fsync_directory(final.parent); return True
    finally: os.close(fd)
    _safe_remove_same_inode(tmp,lst); _fsync_directory(tmp.parent); return False
def initialize(path):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    pst=path.parent.lstat()
    if not stat.S_ISDIR(pst.st_mode): raise ValueError("state parent is not real directory")
    if stat.S_IMODE(pst.st_mode)&0o077:
        os.chmod(path.parent,0o700); pst=path.parent.lstat()
    _migrate_exact_legacy(path,pst)
    if path.exists() or path.is_symlink(): return read_state(path)
    tmp=path.with_name(path.name+".new"); data=_canonical_bytes(DEFAULT_STATE)
    for attempt in range(2):
        if _recover_stale_temp(tmp,path,pst): return read_state(path)
        try: fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            if attempt==0: continue
            raise ValueError("temporary state creation raced repeatedly")
        created=os.fstat(fd)
        try:
            with os.fdopen(fd,"wb",closefd=False) as fh:
                fh.write(data); fh.flush(); os.fsync(fh.fileno())
            os.close(fd); fd=-1
            cur=tmp.lstat()
            if cur.st_dev!=created.st_dev or cur.st_ino!=created.st_ino: raise ValueError("temporary state changed before promotion")
            os.replace(tmp,path); _fsync_directory(path.parent); return read_state(path)
        except Exception:
            if fd>=0: os.close(fd)
            try: _safe_remove_same_inode(tmp,created)
            except FileNotFoundError: pass
            raise
    raise ValueError("temporary state recovery exhausted")
def verify(path): return read_state(path)
def main(argv):
    if len(argv)!=3 or argv[1] not in {"initialize","verify"}:
        print("usage: veramesh_state.py {initialize|verify} STATE_PATH",file=sys.stderr); return 64
    try: state=initialize(Path(argv[2])) if argv[1]=="initialize" else verify(Path(argv[2]))
    except Exception as exc:
        print(f"BLOCKED_STATE_INTEGRITY: {exc}",file=sys.stderr); return 2
    print(json.dumps(state,sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main(sys.argv))
