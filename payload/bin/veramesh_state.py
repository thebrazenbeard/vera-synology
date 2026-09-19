#!/usr/bin/env python3
from __future__ import annotations
import json, os, stat, sys
from pathlib import Path

SCHEMA="VERA_MESH_EDGE_STATE_V1"
ALLOWED_STATES={"READY","DEGRADED","BLOCKED"}
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
def _recover_stale_temp(tmp,final,parent_stat):
    try: lst=tmp.lstat()
    except FileNotFoundError: return False
    if not stat.S_ISREG(lst.st_mode) or stat.S_IMODE(lst.st_mode)!=0o600: raise ValueError("invalid temporary state")
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
