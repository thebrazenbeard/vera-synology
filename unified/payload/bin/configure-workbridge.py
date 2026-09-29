#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, pwd, secrets, stat, sys
from pathlib import Path

ROOT = Path("/var/packages/VeraMesh")
VAR = ROOT / "var"
WB = VAR / "workbridge"
GW = VAR / "gateway"
TOKEN = WB / "bearer-token"
WB_CONFIG = WB / "config.json"
GW_CONFIG = GW / "workbridge.json"
TOKEN_ENV = "VERAMESH_WORKBRIDGE_TOKEN"

class ConfigError(RuntimeError):
    pass

def package_owner():
    user = pwd.getpwnam("VeraMesh")
    return user.pw_uid, user.pw_gid

def normalize_roots(values):
    out=[];seen=set()
    for raw in values:
        p=Path(raw)
        if not p.is_absolute():
            raise ConfigError(f"root must be absolute: {raw}")
        try:
            resolved=p.resolve(strict=True)
        except OSError as exc:
            raise ConfigError(f"root unavailable: {raw}: {exc}") from exc
        if not resolved.is_dir():
            raise ConfigError(f"root is not a directory: {raw}")
        key=str(p)
        if key not in seen:
            seen.add(key);out.append(key)
    if not out:
        raise ConfigError("at least one root is required")
    return out

def sha256_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def atomic_private_json(path,value,owner):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=path.with_name("."+path.name+".new")
    data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    finally:
        os.close(fd)
    os.chown(tmp,*owner);os.replace(tmp,path);os.chmod(path,0o600)

def ensure_token(owner):
    TOKEN.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if TOKEN.exists():
        st=TOKEN.lstat()
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600:
            raise ConfigError("existing WorkBridge token must be a 0600 regular file")
        value=TOKEN.read_text().strip()
        if len(value)<32 or any(ch.isspace() for ch in value):
            raise ConfigError("existing WorkBridge token is invalid")
        return
    value=secrets.token_urlsafe(48)
    fd=os.open(TOKEN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"w",encoding="ascii",closefd=False) as f:
            f.write(value+"\n");f.flush();os.fsync(f.fileno())
    finally:
        os.close(fd)
    os.chown(TOKEN,*owner)

def configs(roots,profile):
    writable=profile in {"write","operator"}
    process=profile=="operator"
    grants=[];working=[]
    if process:
        shell=Path("/bin/sh").resolve(strict=True)
        if not shell.is_file():
            raise ConfigError("resolved /bin/sh is not a regular file")
        grants=[{"name":"shell","path":"/bin/sh","sha256":sha256_file(shell)}]
        working=list(roots)
    workbridge={
        "schema":"WORKBRIDGE_CONFIG_V1",
        "read_roots":list(roots),
        "write_roots":list(roots) if writable else [],
        "limits":{"max_read_bytes":67108864,"max_write_bytes":67108864,"max_directory_entries":10000},
        "process":{"enabled":process,"allowed_executables":grants,"working_roots":working,"max_runtime_seconds":900,"max_output_bytes":16777216,"max_args":256},
        "http":{"listen":"127.0.0.1:17447","path":"/mcp","bearer_token_env":TOKEN_ENV}
    }
    gateway={"schema":"VERAMESH_WORKBRIDGE_UPSTREAM_V1","endpoint":"http://127.0.0.1:17447/mcp","bearer_token_env":TOKEN_ENV,"timeout_seconds":10,"allowed_roots":list(roots)}
    return workbridge,gateway

def main(argv=None):
    p=argparse.ArgumentParser(description="Configure the bundled NAS-local WorkBridge backend.")
    p.add_argument("--root",action="append",default=[],help="absolute admitted root; repeatable")
    p.add_argument("--profile",choices=["read","write","operator"],default="read")
    p.add_argument("--apply",action="store_true",help="write private configs and token")
    args=p.parse_args(argv)
    try:
        roots=normalize_roots(args.root)
        wb,gw=configs(roots,args.profile)
        plan={"schema":"VERAMESH_NAS_WORKBRIDGE_PLAN_V1","profile":args.profile,"roots":roots,"workbridge_listen":"127.0.0.1:17447","gateway_upstream":"loopback","apply":args.apply,"process_grants":[x["name"] for x in wb["process"]["allowed_executables"]]}
        if not args.apply:
            print(json.dumps(plan,indent=2,sort_keys=True));return 0
        if os.geteuid()!=0:
            raise ConfigError("--apply must run as root so ownership can be set to the VeraMesh package user")
        owner=package_owner()
        for d in (WB,GW):
            d.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(d,0o700);os.chown(d,*owner)
        ensure_token(owner)
        atomic_private_json(WB_CONFIG,wb,owner)
        atomic_private_json(GW_CONFIG,gw,owner)
        plan["configured"]=True;plan["restart_or_gateway_reload_required"]=True
        print(json.dumps(plan,indent=2,sort_keys=True));return 0
    except Exception as exc:
        print(json.dumps({"schema":"VERAMESH_NAS_WORKBRIDGE_PLAN_V1","status":"FAIL","error":str(exc)},indent=2),file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
