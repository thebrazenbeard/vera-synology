#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import sys
from pathlib import Path

VAR=Path("/var/packages/VeraMesh/var")
DEFAULT={"schema":"VERAMESH_RUNTIME_MODULE_CONFIG_V1","modules":{"edge":{"enabled":True},"gateway":{"enabled":False},"relay":{"enabled":False}}}
RECOVERY_SCHEMA="VERAMESH_RUNTIME_CONFIG_RECOVERY_V1"

def valid(v):
 if v.get("schema")!=DEFAULT["schema"] or set(v.get("modules",{}))!=set(DEFAULT["modules"]):raise ValueError("runtime config")
 for n,x in v["modules"].items():
  if not isinstance(x,dict) or set(x)!={"enabled"} or type(x["enabled"]) is not bool:raise ValueError(n)
 if not v["modules"]["edge"]["enabled"]:raise ValueError("edge mandatory")

def package_owner():
 u=pwd.getpwnam("VeraMesh")
 try:g=grp.getgrnam("VeraMesh").gr_gid
 except KeyError:g=u.pw_gid
 return u.pw_uid,g

def write_json_new(path,value):
 data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,"wb",closefd=False) as fh:
   fh.write(data);fh.flush();os.fsync(fh.fileno())
 finally:
  os.close(fd)
 os.chmod(path,0o600)

def quarantine_existing_config(config,runtime_dir):
 st=config.lstat()
 if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
  raise ValueError("existing runtime config is not a regular file")
 q=runtime_dir/f"modules.preinstall.uid{st.st_uid}.ino{st.st_ino}.json"
 if q.exists() or q.is_symlink():
  raise ValueError(f"runtime config quarantine collision: {q}")
 os.replace(config,q)
 return q,st

def initialize(var,status):
 if status not in {"INSTALL","UPGRADE","PRESERVE"}:raise ValueError(f"unsupported package status: {status!r}")
 runtime=var/"runtime";config=runtime/"modules.json"
 paths=(runtime,var/"gateway",var/"relay")
 for p in paths:
  p.mkdir(parents=True,exist_ok=True,mode=0o700)
  os.chmod(p,0o700)

 owner=None
 if os.geteuid()==0:
  owner=package_owner()
  for p in paths:os.chown(p,owner[0],owner[1])

 recovery=None
 if status=="INSTALL" and (config.exists() or config.is_symlink()):
  q,st=quarantine_existing_config(config,runtime)
  receipt=Path(str(q)+".receipt.json")
  recovery={"schema":RECOVERY_SCHEMA,"reason":"INSTALL_RESETS_PERSISTED_MODULE_ACTIVATION","source":str(config),"quarantine":str(q),"receipt":str(receipt),"source_uid":st.st_uid,"source_gid":st.st_gid,"source_mode":f"{stat.S_IMODE(st.st_mode):04o}","source_inode":st.st_ino}
  write_json_new(receipt,recovery)
  if owner is not None:os.chown(receipt,owner[0],owner[1])

 if config.exists():
  valid(json.loads(config.read_text()))
 else:
  write_json_new(config,DEFAULT)

 os.chmod(config,0o600)
 if owner is not None:os.chown(config,owner[0],owner[1])
 return recovery

def main(argv):
 status=argv[1] if len(argv)==2 else ("PRESERVE" if len(argv)==1 else None)
 if status is None:
  print("usage: veramesh_runtime_init.py [INSTALL|UPGRADE|PRESERVE]",file=sys.stderr);return 64
 initialize(VAR,status)
 return 0

if __name__=="__main__":raise SystemExit(main(sys.argv))
