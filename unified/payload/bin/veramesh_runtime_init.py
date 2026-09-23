#!/usr/bin/env python3
import json,os
from pathlib import Path
VAR=Path("/var/packages/VeraMesh/var"); R=VAR/"runtime"; C=R/"modules.json"
D={"schema":"VERAMESH_RUNTIME_MODULE_CONFIG_V1","modules":{"edge":{"enabled":True},"gateway":{"enabled":False},"relay":{"enabled":False}}}
def valid(v):
 if v.get("schema")!=D["schema"] or set(v.get("modules",{}))!=set(D["modules"]):raise ValueError("runtime config")
 for n,x in v["modules"].items():
  if not isinstance(x,dict) or set(x)!={"enabled"} or type(x["enabled"]) is not bool:raise ValueError(n)
 if not v["modules"]["edge"]["enabled"]:raise ValueError("edge mandatory")
def main():
 for p in (R,VAR/"gateway",VAR/"relay"):p.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(p,0o700)
 if C.exists():valid(json.loads(C.read_text()))
 else:
  d=(json.dumps(D,sort_keys=True,separators=(",",":"))+"\n").encode();fd=os.open(C,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,"wb") as f:f.write(d);f.flush();os.fsync(f.fileno())
 os.chmod(C,0o600);return 0
if __name__=="__main__":raise SystemExit(main())
