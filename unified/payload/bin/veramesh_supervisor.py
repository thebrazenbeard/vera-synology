#!/usr/bin/env python3
import json,os,signal,subprocess,time
from pathlib import Path

ROOT=Path("/var/packages/VeraMesh"); TARGET=ROOT/"target"; VAR=ROOT/"var"; RUNTIME=VAR/"runtime"
CONFIG=RUNTIME/"modules.json"; STATUS=RUNTIME/"status.json"; PIDFILE=RUNTIME/"supervisor.pid"
PY=Path("/var/packages/python311/target/bin/python3.11")
STOP=False; RELOAD=False; RELOAD_ERROR=None; RELOAD_GENERATION=0

def atomic(path,value):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); tmp=path.with_name("."+path.name+".new")
 data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 with os.fdopen(fd,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,path); os.chmod(path,0o600)

def write_pid():
 tmp=PIDFILE.with_name("."+PIDFILE.name+".new")
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 with os.fdopen(fd,"w",encoding="ascii") as f:
  f.write(str(os.getpid())+"\n"); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,PIDFILE); os.chmod(PIDFILE,0o600)

def remove_pid():
 try:
  if int(PIDFILE.read_text().strip())==os.getpid(): PIDFILE.unlink()
 except Exception: pass

def cfg():
 v=json.loads(CONFIG.read_text())
 if v.get("schema")!="VERAMESH_RUNTIME_MODULE_CONFIG_V1": raise ValueError("runtime schema")
 m=v.get("modules")
 if not isinstance(m,dict) or set(m)!={"edge","gateway","relay"}: raise ValueError("runtime modules")
 for n,x in m.items():
  if not isinstance(x,dict) or set(x)!={"enabled"} or type(x["enabled"]) is not bool: raise ValueError("runtime module "+n)
 if not m["edge"]["enabled"]: raise ValueError("edge mandatory")
 return m

class M:
 def __init__(self,n,a,req,en): self.n=n; self.a=a; self.req=req; self.en=en; self.p=None; self.restarts=0; self.last=None; self.next=0.0
 def start(self):
  if self.en and self.p is None: self.p=subprocess.Popen(self.a,cwd=str(TARGET),stdin=subprocess.DEVNULL,start_new_session=True); self.next=0.0
 def poll(self):
  if self.p is None:return None
  r=self.p.poll()
  if r is not None:self.last=r;self.p=None
  return r
 def stop(self):
  if self.p is None:return
  self.p.terminate()
  try:self.p.wait(5)
  except subprocess.TimeoutExpired:self.p.kill();self.p.wait(5)
  self.last=self.p.returncode;self.p=None
 def set_enabled(self,value):
  if self.req and not value: raise ValueError("required module cannot be disabled")
  if value==self.en:return
  self.en=value;self.next=0.0
  if not value:self.stop()
  else:self.start()
 def state(self):
  s="DISABLED" if not self.en else ("RUNNING" if self.p is not None and self.p.poll() is None else ("RESTART_WAIT" if self.next else "STOPPED"))
  return {"enabled":self.en,"required":self.req,"state":s,"pid":self.p.pid if self.p is not None and self.p.poll() is None else None,"restart_count":self.restarts,"last_exit":self.last}

def status(ms):
 atomic(STATUS,{"schema":"VERAMESH_RUNTIME_STATUS_V1","observed_at_unix":int(time.time()),"supervisor_pid":os.getpid(),"reload_generation":RELOAD_GENERATION,"reload_error":RELOAD_ERROR,"modules":{m.n:m.state() for m in ms},"utilities":{"dsmctl":{"bundled":(TARGET/"bin/dsmctl").is_file(),"daemon":False,"credentials_provisioned":False}},"network":{"edge_loopback":"127.0.0.1:17445","gateway_loopback":"127.0.0.1:17446","public_listener_created_by_package":False}})

def sig_stop(*_):
 global STOP;STOP=True

def sig_reload(*_):
 global RELOAD;RELOAD=True

def apply_reload(ms):
 global RELOAD_ERROR
 desired=cfg();by={m.n:m for m in ms}
 by["gateway"].set_enabled(desired["gateway"]["enabled"])
 by["relay"].set_enabled(desired["relay"]["enabled"])
 RELOAD_ERROR=None

def main():
 global RELOAD,RELOAD_ERROR,RELOAD_GENERATION
 c=cfg(); ms=[M("edge",[str(PY),str(TARGET/"bin/veramesh_edge.py"),"serve"],True,True),M("gateway",[str(TARGET/"bin/run-veramesh-gateway.sh")],False,c["gateway"]["enabled"]),M("relay",[str(TARGET/"bin/run-verarelay.sh")],False,c["relay"]["enabled"])]
 signal.signal(signal.SIGTERM,sig_stop);signal.signal(signal.SIGINT,sig_stop);signal.signal(signal.SIGHUP,sig_reload)
 write_pid()
 for m in ms:m.start()
 status(ms)
 try:
  while not STOP:
   if RELOAD:
    RELOAD=False
    try:apply_reload(ms)
    except Exception as x:RELOAD_ERROR=str(x)
    finally:RELOAD_GENERATION+=1
   now=time.monotonic()
   for m in ms:
    r=m.poll()
    if r is None:continue
    if m.req:status(ms);return r or 1
    if not m.en:continue
    m.restarts+=1;m.next=now+min(60,3*max(1,m.restarts))
   for m in ms:
    if m.en and not m.req and m.p is None and m.next and now>=m.next:m.next=0;m.start()
   status(ms);time.sleep(.25)
 finally:
  for m in reversed(ms):m.stop()
  status(ms);remove_pid()
 return 0

if __name__=="__main__":raise SystemExit(main())
