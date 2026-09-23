#!/usr/bin/env python3
from __future__ import annotations
import argparse,grp,hashlib,json,os,pwd,shutil,socket,stat,subprocess,sys,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path

OLD="VeraRelay"; NEW="VeraMesh"
OLDVAR=Path("/var/packages/VeraRelay/var"); ROOT=Path("/var/packages/VeraMesh")
NEWVAR=ROOT/"var/relay"; MIG=ROOT/"var/migrations"; MOD=ROOT/"var/runtime/modules.json"; SUPPID=ROOT/"var/runtime/supervisor.pid"; RSTATUS=ROOT/"var/runtime/status.json"
SERVER=ROOT/"target/relay/src/server.js"; RP=17443; EP=17445; SCHEMA="VERAMESH_VERARELAY_ADOPTION_V1"
class E(RuntimeError): pass

def run(c,check=True):
 p=subprocess.run(c,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if check and p.returncode: raise E(f"command rc={p.returncode}: {' '.join(c)} :: {p.stdout.strip()}")
 return p

def syno():
 for x in ("/usr/syno/bin/synopkg","/usr/local/bin/synopkg","/usr/bin/synopkg"):
  if Path(x).is_file() and os.access(x,os.X_OK): return x
 x=shutil.which("synopkg")
 if not x: raise E("synopkg not found")
 return x

def status(n):
 p=run([syno(),"status",n],False);o=p.stdout.strip()
 return {"returncode":p.returncode,"output":o,"running":('"status":"running"' in o or "package is started" in o)}

def action(a,n): run([syno(),a,n])

def waitpkg(n,w,t=45):
 end=time.monotonic()+t
 while time.monotonic()<end:
  if status(n)["running"] is w:return
  time.sleep(1)
 raise E(f"{n} did not reach running={w}")

def port(p):
 try:
  with socket.create_connection(("127.0.0.1",p),1):return True
 except OSError:return False

def waitport(p,w,t=30):
 end=time.monotonic()+t
 while time.monotonic()<end:
  if port(p) is w:return
  time.sleep(.5)
 raise E(f"127.0.0.1:{p} did not reach open={w}")

def health():
 try:
  with urllib.request.urlopen("http://127.0.0.1:17443/health",timeout=3) as r:
   v=json.loads(r.read(262144).decode())
   if r.status!=200 or v.get("status")!="ok":raise E(f"bad health {r.status} {v!r}")
   return v
 except E:raise
 except Exception as x:raise E(f"health failed: {x}") from x

def package_owner():
 u=pwd.getpwnam("VeraMesh")
 try:g=grp.getgrnam("VeraMesh").gr_gid
 except KeyError:g=u.pw_gid
 return u.pw_uid,g

def filehash(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()

def resolve_state_root(root,allow_root_symlink=False):
 try:s=root.lstat()
 except FileNotFoundError as x:raise E(f"state root missing: {root}") from x
 if stat.S_ISLNK(s.st_mode):
  if not allow_root_symlink:raise E(f"state root symlink rejected: {root}")
  try:resolved=root.resolve(strict=True)
  except OSError as x:raise E(f"state root symlink cannot resolve: {root}") from x
 else:
  resolved=root.resolve(strict=True)
 try:rs=resolved.lstat()
 except OSError as x:raise E(f"resolved state root unavailable: {resolved}") from x
 if not stat.S_ISDIR(rs.st_mode) or stat.S_ISLNK(rs.st_mode):raise E(f"resolved state root is not a directory: {resolved}")
 if resolved==Path("/") or resolved==ROOT or ROOT in resolved.parents:raise E(f"unsafe resolved state root: {resolved}")
 return resolved

def manifest(root):
 root=resolve_state_root(root,False)
 e=[];nf=nb=0
 for p in sorted(root.rglob("*"),key=lambda x:x.relative_to(root).as_posix()):
  r=p.relative_to(root).as_posix();s=p.lstat();m=stat.S_IMODE(s.st_mode)
  if stat.S_ISLNK(s.st_mode):raise E(f"state symlink rejected: {r}")
  if stat.S_ISDIR(s.st_mode):e.append({"path":r,"type":"dir","mode":f"{m:04o}"});continue
  if not stat.S_ISREG(s.st_mode):raise E(f"nonregular state rejected: {r}")
  e.append({"path":r,"type":"file","mode":f"{m:04o}","bytes":s.st_size,"sha256":filehash(p)});nf+=1;nb+=s.st_size
 d=hashlib.sha256(json.dumps(e,sort_keys=True,separators=(",",":")).encode()).hexdigest()
 return e,d,nf,nb

def atomic(p,v,owner=None):
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 if p.exists() and p.is_symlink():raise E(f"refusing atomic replace of symlink: {p}")
 q=p.with_name("."+p.name+".new")
 fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try:
  with os.fdopen(fd,"w",encoding="utf-8") as f:
   json.dump(v,f,sort_keys=True,separators=(",",":"));f.write("\n");f.flush();os.fsync(f.fileno())
  os.replace(q,p);os.chmod(p,0o600)
  if owner is not None:os.chown(p,owner[0],owner[1])
 finally:
  try:q.unlink()
  except FileNotFoundError:pass

def cfg():
 v=json.loads(MOD.read_text())
 if v.get("schema")!="VERAMESH_RUNTIME_MODULE_CONFIG_V1" or set(v.get("modules",{}))!={"edge","gateway","relay"}:raise E("unexpected module config")
 if v["modules"]["edge"].get("enabled") is not True:raise E("edge not enabled")
 return v

def enable(x):
 v=cfg();v["modules"]["relay"]["enabled"]=x;atomic(MOD,v,owner=package_owner())

def node():
 for x in ("/var/packages/Node.js_v22/target/usr/local/bin/node","/var/packages/Node.js_v22/target/bin/node","/usr/local/bin/node","/usr/bin/node"):
  if Path(x).is_file() and os.access(x,os.X_OK):return x
 raise E("Node.js 22 not found")

def chownroot(p):
 uid,gid=package_owner();os.chown(p,uid,gid)
 for x in p.rglob("*"):os.chown(x,uid,gid,follow_symlinks=False)

def preflight():
 if not SERVER.is_file():raise E("unified Relay server missing")
 code="const s=require(process.argv[1]);s.loadConfig(process.argv[2]);console.log('PASS')"
 if "PASS" not in run([node(),"-e",code,str(SERVER),str(NEWVAR)]).stdout:raise E("Relay config preflight failed")

def copy(stamp):
 src=resolve_state_root(OLDVAR,True)
 e,d,nf,nb=manifest(src)
 MIG.mkdir(parents=True,exist_ok=True,mode=0o700)
 rd=MIG/f"verarelay-standalone-{stamp}";rd.mkdir(mode=0o700)
 atomic(rd/"source-manifest.json",{"schema":"VERAMESH_VERARELAY_SOURCE_MANIFEST_V1","source_link":str(OLDVAR),"source_resolved":str(src),"tree_sha256":d,"files":nf,"bytes":nb,"entries":e})
 if NEWVAR.exists():
  if NEWVAR.is_symlink() or not NEWVAR.is_dir() or any(NEWVAR.iterdir()):raise E(f"unified Relay state not empty/safe: {NEWVAR}")
  NEWVAR.rmdir()
 st=NEWVAR.with_name("relay.adopt-staging-"+stamp)
 shutil.copytree(src,st,copy_function=shutil.copy2)
 _,d2,nf2,nb2=manifest(st)
 if (d2,nf2,nb2)!=(d,nf,nb):raise E("state copy verification failed")
 st.rename(NEWVAR);chownroot(NEWVAR)
 pid=NEWVAR/"state/runtime.pid";removed=False
 if pid.exists():
  if pid.is_symlink() or not pid.is_file():raise E("unsafe stale runtime pid")
  pid.unlink();removed=True
 return {"record_dir":str(rd),"source_link":str(OLDVAR),"source_resolved":str(src),"source_tree_sha256":d,"copy_tree_sha256_before_ephemeral_cleanup":d2,"files":nf,"bytes":nb,"stale_runtime_pid_removed":removed,"original_state_preserved":src.is_dir() and OLDVAR.exists()}

def supervisor_pid():
 try:
  raw=SUPPID.read_text().strip();pid=int(raw)
 except Exception as x:raise E(f"invalid supervisor pid file: {x}") from x
 if pid<=1:raise E("invalid supervisor pid")
 try:cmd=Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\\x00",b" ").decode(errors="replace")
 except Exception as x:raise E(f"cannot inspect supervisor pid {pid}: {x}") from x
 if "veramesh_supervisor.py" not in cmd:raise E(f"pid {pid} is not VeraMesh supervisor")
 return pid

def runtime_status():
 try:return json.loads(RSTATUS.read_text())
 except Exception as x:raise E(f"runtime status unavailable: {x}") from x

def reload_modules(expect_relay,t=30):
 if not status(NEW)["running"]:raise E("VeraMesh package is not running")
 if not port(EP):raise E("VeraMesh edge not listening before reload")
 pid=supervisor_pid()
 os.kill(pid,signal.SIGHUP)
 end=time.monotonic()+t
 while time.monotonic()<end:
  if not status(NEW)["running"]:raise E("VeraMesh stopped during module reload")
  if not port(EP):raise E("VeraMesh edge dropped during module reload")
  try:
   s=runtime_status();relay=s.get("modules",{}).get("relay",{})
   if s.get("reload_error"):raise E("supervisor reload error: "+str(s["reload_error"]))
   if relay.get("enabled") is expect_relay:
    if expect_relay and relay.get("state")=="RUNNING" and port(RP):return
    if not expect_relay and relay.get("state")=="DISABLED" and not port(RP):return
  except E:raise
  except Exception:pass
  time.sleep(.25)
 raise E(f"supervisor did not converge relay enabled={expect_relay}")

def inspect():
 c=cfg()
 try:resolved=str(resolve_state_root(OLDVAR,True))
 except Exception as x:resolved=f"ERROR: {x}"
 return {"schema":SCHEMA,"mode":"INSPECT","standalone_package":status(OLD),"unified_package":status(NEW),"standalone_state_exists":OLDVAR.exists(),"standalone_state_resolved":resolved,"unified_state_exists":NEWVAR.is_dir(),"unified_state_empty":NEWVAR.is_dir() and not any(NEWVAR.iterdir()),"relay_module_enabled":c["modules"]["relay"]["enabled"],"relay_port_open":port(RP),"edge_port_open":port(EP),"node":node()}

def quarantine_copy(r):
 sc=r.get("state_copy")
 if not sc or not NEWVAR.is_dir():return
 rd=Path(sc["record_dir"]);q=rd/"failed-unified-state"
 if q.exists():raise E(f"failed-copy quarantine already exists: {q}")
 NEWVAR.rename(q)
 NEWVAR.mkdir(mode=0o700);chownroot(NEWVAR)

def rollback(was,r,why,unified_changed):
 r["rollback"]={"attempted":True,"reason":why,"unified_changed":unified_changed,"errors":[]}
 if unified_changed:
  try:enable(False);reload_modules(False);quarantine_copy(r)
  except Exception as x:r["rollback"]["errors"].append("restore unified: "+str(x))
 else:
  try:quarantine_copy(r)
  except Exception as x:r["rollback"]["errors"].append("quarantine copied state: "+str(x))
 if was:
  try:
   if not status(OLD)["running"]:action("start",OLD)
   waitpkg(OLD,True);waitport(RP,True);r["rollback"]["standalone_health"]=health()
  except Exception as x:r["rollback"]["errors"].append("restore standalone: "+str(x))

def apply():
 if os.geteuid()!=0:raise E("--apply requires root")
 b=inspect()
 if not b["standalone_package"]["running"]:raise E("standalone VeraRelay must be running before adoption")
 if not b["unified_package"]["running"]:raise E("VeraMesh must be running before adoption")
 if b["relay_module_enabled"]:raise E("unified Relay already enabled")
 if not b["standalone_state_exists"]:raise E("standalone state missing")
 if b["standalone_state_resolved"].startswith("ERROR:"):raise E(b["standalone_state_resolved"])
 if b["unified_state_exists"] and not b["unified_state_empty"]:raise E("unified Relay state not empty")
 if not b["edge_port_open"]:raise E("VeraMesh edge not listening")
 hb=health();stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
 r={"schema":SCHEMA,"status":"IN_PROGRESS","migration_id":stamp,"before":b,"standalone_health_before":hb}
 unified_changed=False
 try:
  action("stop",OLD);waitpkg(OLD,False);waitport(RP,False)
  r["state_copy"]=copy(stamp);preflight();r["unified_config_preflight"]="PASS"
  enable(True);unified_changed=True;reload_modules(True);ha=health()
  if status(OLD)["running"]:raise E("standalone Relay restarted unexpectedly")
  if not cfg()["modules"]["relay"]["enabled"]:raise E("unified Relay did not remain enabled")
  r.update({"status":"PASS","unified_relay_health":ha,"standalone_package_final":status(OLD),"unified_package_final":status(NEW),"edge_loopback":"PASS" if port(EP) else "FAIL","relay_loopback":"PASS" if port(RP) else "FAIL","standalone_state_preserved":OLDVAR.exists(),"unified_relay_enabled":True,"safe_to_uninstall_standalone_after_review":True})
  atomic(Path(r["state_copy"]["record_dir"])/"qualification.json",r);return r
 except Exception as x:
  r["status"]="FAIL";r["error"]=str(x);rollback(b["standalone_package"]["running"],r,str(x),unified_changed)
  try:atomic(MIG/f"verarelay-standalone-{stamp}"/"qualification.json",r)
  except Exception:pass
  raise E(json.dumps(r,sort_keys=True)) from x

def main():
 a=argparse.ArgumentParser();a.add_argument("--apply",action="store_true");x=a.parse_args()
 try:print(json.dumps(apply() if x.apply else inspect(),indent=2,sort_keys=True));return 0
 except Exception as e:print(json.dumps({"schema":SCHEMA,"status":"FAIL","error":str(e)},indent=2,sort_keys=True),file=sys.stderr);return 1

if __name__=="__main__":raise SystemExit(main())
