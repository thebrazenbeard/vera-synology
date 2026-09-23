#!/usr/bin/env python3
import argparse,gzip,hashlib,io,json,stat,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];U=ROOT/"unified";VER="0.2.0-0004"
def sh(b):return hashlib.sha256(b).hexdigest()
def add(out,root,prefix,skip=set()):
 for p in sorted(root.rglob("*")):
  if p.is_dir():continue
  r=p.relative_to(root)
  if any(x in skip for x in r.parts):continue
  if p.is_symlink() or not p.is_file():raise ValueError(str(p))
  out[(Path(prefix)/r).as_posix()]=(p.read_bytes(),0o755 if p.stat().st_mode&stat.S_IXUSR else 0o644)
def tb(files,gz):
 raw=io.BytesIO();target=raw;g=None
 if gz:g=gzip.GzipFile(fileobj=raw,mode="wb",filename="",mtime=0,compresslevel=9);target=g
 with tarfile.open(fileobj=target,mode="w",format=tarfile.USTAR_FORMAT) as t:
  for n,(d,m) in sorted(files.items()):
   x=tarfile.TarInfo(n);x.size=len(d);x.mode=m;x.mtime=x.uid=x.gid=0;x.uname=x.gname="";t.addfile(x,io.BytesIO(d))
 if g:g.close()
 return raw.getvalue()
def rd(files):
 h=hashlib.sha256()
 for n,(d,m) in sorted(files.items()):h.update(n.removeprefix("relay/").encode()+b"\0"+f"{m:04o}".encode()+b"\0"+hashlib.sha256(d).digest())
 return h.hexdigest()
def main():
 a=argparse.ArgumentParser();a.add_argument("--gateway-bin",required=True);a.add_argument("--dsmctl-bin",required=True);a.add_argument("--relay-dir",required=True);a.add_argument("--source-head",required=True);x=a.parse_args()
 q={};add(q,ROOT/"payload","")
 for n,p in {"bin/veramesh_supervisor.py":U/"payload/bin/veramesh_supervisor.py","bin/veramesh_runtime_init.py":U/"payload/bin/veramesh_runtime_init.py","bin/run-veramesh-gateway.sh":U/"payload/bin/run-veramesh-gateway.sh","bin/run-verarelay.sh":U/"payload/bin/run-verarelay.sh","bin/adopt-standalone-verarelay.py":U/"payload/bin/adopt-standalone-verarelay.py","ui/config":U/"payload/ui/config","ui/index.html":U/"payload/ui/index.html","third_party/dsmctl-LICENSE":U/"third_party/dsmctl-LICENSE"}.items():q[n]=(p.read_bytes(),0o755 if n.startswith("bin/") else 0o644)
 s=q["bin/veramesh_lifecycle.py"][0].decode();o='PACKAGE_VERSION = "0.1.0-0017"'
 if s.count(o)!=1:raise ValueError("lifecycle anchor")
 q["bin/veramesh_lifecycle.py"]=(s.replace(o,'PACKAGE_VERSION = "0.2.0-0004"').encode(),0o755)
 q["bin/veramesh-gateway"]=(Path(x.gateway_bin).read_bytes(),0o755);q["bin/dsmctl"]=(Path(x.dsmctl_bin).read_bytes(),0o755)
 r={};add(r,Path(x.relay_dir),"relay",{".git","node_modules","dist"});q.update(r)
 b=json.loads((U/"component-bindings.json").read_text());p={"schema":"VERAMESH_UNIFIED_RUNTIME_PROVENANCE_V1","package_version":VER,"source_head":x.source_head,"component_bindings":b,"artifacts":{"veramesh_gateway_sha256":sh(q["bin/veramesh-gateway"][0]),"dsmctl_sha256":sh(q["bin/dsmctl"][0]),"relay_tree_sha256":rd(r)}}
 q["provenance/component-bindings.json"]=((json.dumps(p,sort_keys=True,separators=(",",":"))+"\n").encode(),0o644)
 z={};add(z,ROOT/"spk","")
 for n,p in {"INFO":U/"spk/INFO","conf/PKG_DEPS":U/"spk/conf/PKG_DEPS","conf/systemd/pkguser-veramesh.service":U/"spk/conf/systemd/pkguser-veramesh.service","scripts/postinst":U/"spk/scripts/postinst","scripts/postupgrade":U/"spk/scripts/postupgrade"}.items():z[n]=(p.read_bytes(),0o755 if n.startswith("scripts/") else 0o644)
 z["package.tgz"]=(tb(q,True),0o644);out=ROOT/"dist"/f"VeraMesh-{VER}-unified-runtime.spk";out.parent.mkdir(exist_ok=True);data=tb(z,False);out.write_bytes(data);print(json.dumps({"path":str(out),"sha256":sh(data),"bytes":len(data)}))
if __name__=="__main__":main()
