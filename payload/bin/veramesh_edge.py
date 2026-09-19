#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import select
import signal
import socket
import stat
import threading
import time
from pathlib import Path

STATE = Path("/var/packages/VeraMesh/var/vera/scaffold-state.json")
CONFIG = Path("/var/packages/VeraMesh/var/vera/edge-config.json")
LIFECYCLE_STATE = Path("/var/packages/VeraMesh/var/vera/lifecycle-state.json")
RUN_DIR = Path("/var/packages/VeraMesh/tmp/run")
CONTROL_SOCKET = RUN_DIR / "control.sock"
MAX_REQUEST = 4096
CONNECTION_TIMEOUT_SECONDS = 1.0
BUFFER_SIZE = 65536
MAX_BUFFER_BYTES = 1_048_576

STATUS_FIELDS = {
    "schema": "VERA_MESH_EDGE_STATUS_V1",
    "package_runtime": "RUNNING",
    "mesh_semantic_state": "READY",
    "reason": "LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED",
    "pairing_implemented": False,
    "tcp_mesh_listener": True,
    "mesh_delivery_implemented": True,
    "edge_proxy_implemented": True,
    "durable_relay_implemented": False,
    "end_to_end_veraport_auth_preserved": True,
}

def _reject_duplicates(pairs):
    out={}
    for k,v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key: {k}")
        out[k]=v
    return out

def _load_lifecycle():
    import veramesh_lifecycle as lifecycle
    return lifecycle

def _load_state():
    import veramesh_state as state
    return state

def _read_private_json(path: Path) -> dict:
    fd=os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("edge config is not a regular file")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("edge config mode must be 0600")
        if st.st_uid != os.geteuid():
            raise ValueError("edge config owner must be package user")
        data=b""
        while True:
            chunk=os.read(fd,4096)
            if not chunk: break
            data += chunk
            if len(data)>8192:
                raise ValueError("edge config too large")
    finally:
        os.close(fd)
    value=json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    if not isinstance(value,dict):
        raise ValueError("edge config must be object")
    return value

def _validate_config(value: dict) -> dict:
    expected={
        "schema","listen_host","listen_port","target_host","target_port",
        "connect_timeout_s","idle_timeout_s","max_connections"
    }
    if set(value)!=expected or value.get("schema")!="VERA_MESH_EDGE_CONFIG_V1":
        raise ValueError("edge config schema mismatch")
    if value["listen_host"]!="127.0.0.1":
        raise ValueError("edge listener must be loopback-only")
    for key in ("listen_port","target_port","max_connections"):
        if isinstance(value[key],bool) or not isinstance(value[key],int):
            raise ValueError(f"{key} must be integer")
    if not 1024 <= value["listen_port"] <= 65535:
        raise ValueError("listen_port outside policy")
    if not 1 <= value["target_port"] <= 65535:
        raise ValueError("target_port outside policy")
    if not 1 <= value["max_connections"] <= 128:
        raise ValueError("max_connections outside policy")
    target=value["target_host"]
    if not isinstance(target,str) or not target or any(ch.isspace() for ch in target):
        raise ValueError("target_host invalid")
    for key in ("connect_timeout_s","idle_timeout_s"):
        number=value[key]
        if isinstance(number,bool) or not isinstance(number,(int,float)) or number <= 0:
            raise ValueError(f"{key} must be positive number")
    if value["connect_timeout_s"]>30 or value["idle_timeout_s"]>3600:
        raise ValueError("timeout outside policy")
    return value

def load_config(path: Path = CONFIG) -> dict:
    return _validate_config(_read_private_json(path))

def status_payload(binding) -> dict:
    state=_load_state().verify(STATE)
    result=dict(STATUS_FIELDS)
    if state["semantic_state"]!="READY" or state["reason"]!=STATUS_FIELDS["reason"]:
        raise ValueError("semantic state/status mismatch")
    result.update({
        "lifecycle_profile_id": binding.lifecycle_profile_id,
        "lifecycle_profile_sha256": binding.lifecycle_profile_sha256,
        "package_version": binding.package_version,
        "installation_incarnation_id": binding.installation_incarnation_id,
        "start_generation": binding.start_generation,
        "start_transition_id": binding.start_transition_id,
        "process_instance_id": binding.process_instance_id,
    })
    return result

def _prepare_control_socket() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    st=RUN_DIR.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(RUN_DIR,0o700)
        st=RUN_DIR.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError("run directory is not private real directory")
    if CONTROL_SOCKET.exists() or CONTROL_SOCKET.is_symlink():
        st=CONTROL_SOCKET.lstat()
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError("control socket path substituted by non-socket")
        CONTROL_SOCKET.unlink()

def _read_request_bytes(conn: socket.socket):
    buf=bytearray()
    while True:
        try:
            chunk=conn.recv(min(1024, MAX_REQUEST+1-len(buf)))
        except TimeoutError:
            return None,"REQUEST_TIMEOUT"
        except ConnectionResetError:
            return None,"CLIENT_DISCONNECTED"
        if not chunk:
            return (bytes(buf),None) if buf else (None,"EMPTY_REQUEST")
        buf.extend(chunk)
        if len(buf)>MAX_REQUEST:
            return None,"REQUEST_TOO_LARGE"
        newline=buf.find(b"\n")
        if newline>=0:
            if bytes(buf[newline+1:]).strip():
                return None,"MULTIPLE_OR_TRAILING_REQUEST_DATA"
            return bytes(buf[:newline]),None

def _send_json_response(conn: socket.socket, response: dict) -> bool:
    payload=(json.dumps(response,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")
    try:
        conn.sendall(payload)
    except (BrokenPipeError,ConnectionResetError):
        return False
    return True

def _make_data_listener(config: dict) -> socket.socket:
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind((config["listen_host"],config["listen_port"]))
        server.listen(config["max_connections"])
        server.setblocking(False)
        return server
    except Exception:
        server.close()
        raise

def _proxy_connection(client: socket.socket, config: dict, stop: threading.Event) -> None:
    target=None
    try:
        target=socket.create_connection(
            (config["target_host"],config["target_port"]),
            timeout=float(config["connect_timeout_s"]),
        )
        client.setblocking(False)
        target.setblocking(False)
        peers={client:target,target:client}
        readable_open={client:True,target:True}
        pending={client:bytearray(),target:bytearray()}
        shutdown_write={client:False,target:False}
        last_activity=time.monotonic()

        while not stop.is_set():
            now=time.monotonic()
            if now-last_activity >= float(config["idle_timeout_s"]):
                return

            read_list=[]
            for src in (client,target):
                dst=peers[src]
                if readable_open[src] and len(pending[dst]) < MAX_BUFFER_BYTES:
                    read_list.append(src)
            write_list=[dst for dst in (client,target) if pending[dst]]

            if not read_list and not write_list:
                return

            readable,writable,_=select.select(read_list,write_list,[],0.5)

            for src in readable:
                dst=peers[src]
                try:
                    data=src.recv(BUFFER_SIZE)
                except BlockingIOError:
                    continue
                if data:
                    pending[dst].extend(data)
                    if len(pending[dst]) > MAX_BUFFER_BYTES:
                        raise RuntimeError("proxy buffer exceeded invariant")
                    last_activity=time.monotonic()
                else:
                    readable_open[src]=False

            for dst in writable:
                if not pending[dst]:
                    continue
                try:
                    sent=dst.send(pending[dst])
                except BlockingIOError:
                    continue
                if sent <= 0:
                    return
                del pending[dst][:sent]
                last_activity=time.monotonic()

            for src in (client,target):
                dst=peers[src]
                if not readable_open[src] and not pending[dst] and not shutdown_write[dst]:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    shutdown_write[dst]=True

            if (
                not readable_open[client]
                and not readable_open[target]
                and not pending[client]
                and not pending[target]
            ):
                return
    except (OSError,TimeoutError,RuntimeError):
        return
    finally:
        for sock in (target,client):
            if sock is not None:
                try: sock.close()
                except OSError: pass

def serve() -> int:
    _load_state().verify(STATE)
    config=load_config(CONFIG)
    lifecycle=_load_lifecycle()
    binding=lifecycle.capture_startup_binding(LIFECYCLE_STATE)
    _prepare_control_socket()
    stop=threading.Event()
    sem=threading.BoundedSemaphore(config["max_connections"])
    threads=[]

    def _term(_signum,_frame):
        stop.set()
    signal.signal(signal.SIGTERM,_term)
    signal.signal(signal.SIGINT,_term)

    control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    data=_make_data_listener(config)
    try:
        control.bind(str(CONTROL_SOCKET))
        os.chmod(CONTROL_SOCKET,0o600)
        control.listen(8)
        control.setblocking(False)
        while not stop.is_set():
            readable,_,_=select.select([control,data],[],[],0.5)
            for server in readable:
                if server is control:
                    conn,_=control.accept()
                    with conn:
                        conn.settimeout(CONNECTION_TIMEOUT_SECONDS)
                        raw,error=_read_request_bytes(conn)
                        if error is not None:
                            response={"error":error}
                        else:
                            try: request=json.loads(raw.decode("utf-8"))
                            except Exception: request=None
                            response=status_payload(binding) if request=={"op":"status"} else {"error":"UNSUPPORTED_OPERATION"}
                        _send_json_response(conn,response)
                else:
                    conn,_=data.accept()
                    if not sem.acquire(blocking=False):
                        conn.close()
                        continue
                    def run(c=conn):
                        try: _proxy_connection(c,config,stop)
                        finally: sem.release()
                    thread=threading.Thread(target=run,daemon=True)
                    thread.start()
                    threads.append(thread)
    finally:
        stop.set()
        control.close()
        data.close()
        for thread in threads:
            thread.join(timeout=1.0)
        try:
            if CONTROL_SOCKET.exists() and stat.S_ISSOCK(CONTROL_SOCKET.lstat().st_mode):
                CONTROL_SOCKET.unlink()
        except FileNotFoundError:
            pass
    return 0

def main(argv: list[str]) -> int:
    if argv[1:]==["serve"]:
        return serve()
    print("usage: veramesh_edge.py serve",file=__import__("sys").stderr)
    return 64

if __name__=="__main__":
    raise SystemExit(main(__import__("sys").argv))
