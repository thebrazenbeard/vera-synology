#!/usr/bin/env python3
import argparse,hashlib,io,json,struct,tarfile
from pathlib import Path
def sh(b):return hashlib.sha256(b).hexdigest()
def read(t):
 m=t.getmembers();n=[x.name for x in m]
 if n!=sorted(n) or len(n)!=len(set(n)):raise ValueError("archive ordering")
 for x in m:
  if not x.isfile() or x.uid or x.gid or x.mtime or Path(x.name).is_absolute() or ".." in Path(x.name).parts:raise ValueError("archive metadata")
 return {x.name:t.extractfile(x).read() for x in m},{x.name:x.mode for x in m}
def arm(b,n):
 if b[:4]!=b"\x7fELF":raise ValueError(n+" ELF")
 e="<" if b[5]==1 else ">"
 if struct.unpack(e+"H",b[18:20])[0]!=40:raise ValueError(n+" ARM")
def main():
 a=argparse.ArgumentParser();a.add_argument("spk");p=Path(a.parse_args().spk)
 with tarfile.open(p,"r:") as t:o,_=read(t)
 if 'version="0.2.0-0005"' not in o["INFO"].decode() or "veramesh_supervisor.py" not in o["conf/systemd/pkguser-veramesh.service"].decode():raise ValueError("outer contract")
 with tarfile.open(fileobj=io.BytesIO(o["package.tgz"]),mode="r:gz") as t:q,m=read(t)
 req={"bin/veramesh_edge.py","bin/veramesh_supervisor.py","bin/veramesh_runtime_init.py","bin/veramesh-gateway","bin/dsmctl","bin/run-veramesh-gateway.sh","bin/run-verarelay.sh","bin/adopt-standalone-verarelay.py","relay/package.json","provenance/component-bindings.json","third_party/dsmctl-LICENSE"}
 if not req.issubset(q):raise ValueError("payload contract")
 arm(q["bin/veramesh-gateway"],"gateway");arm(q["bin/dsmctl"],"dsmctl");v=json.loads(q["provenance/component-bindings.json"])
 if v["component_bindings"]["vera_mesh"]["commit"]!="60d233c8ccc25871b0666d00c53fa9be26c7cc74" or v["component_bindings"]["dsmctl"]["commit"]!="159c9301d1d0b89e3fc2c03215690ba71ff45634":raise ValueError("binding")
 if v["artifacts"]["veramesh_gateway_sha256"]!=sh(q["bin/veramesh-gateway"]) or v["artifacts"]["dsmctl_sha256"]!=sh(q["bin/dsmctl"]):raise ValueError("binary hash")
 h=hashlib.sha256()
 for n in sorted(k for k in q if k.startswith("relay/")):h.update(n.removeprefix("relay/").encode()+b"\0"+f"{m[n]:04o}".encode()+b"\0"+hashlib.sha256(q[n]).digest())
 if h.hexdigest()!=v["artifacts"]["relay_tree_sha256"]:raise ValueError("relay hash")
 print(json.dumps({"schema":"VERAMESH_UNIFIED_RUNTIME_VERIFY_V1","status":"PASS","sha256":sh(p.read_bytes()),"bytes":p.stat().st_size}))
if __name__=="__main__":main()
