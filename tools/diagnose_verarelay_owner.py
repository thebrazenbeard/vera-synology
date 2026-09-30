#!/usr/bin/env python3
"""Read-only DSM VeraRelay listener-to-process custody investigation.

This tool never starts, stops, adopts, or writes package state.
A positive report is diagnostic evidence, not deployment/identity attestation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import urllib.request

PORT = 17443
LISTEN = "0A"
LOOPBACK_V4 = "0100007F"


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def numeric_pid(value):
    if type(value) is int and 1 < value < 1_000_000_000:
        return value
    return None


def read_pid(path: Path):
    try:
        if path.is_symlink() or not path.is_file():
            return None
        raw = path.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9]{1,9}", raw):
            return None
        return numeric_pid(int(raw))
    except (OSError, ValueError):
        return None


def process(proc_root: Path, pid: int):
    root = proc_root / str(pid)
    try:
        argv = [x.decode("utf-8") for x in
                root.joinpath("cmdline").read_bytes().split(b"\0") if x]
        info = {}
        for line in root.joinpath("status").read_text().splitlines():
            if line.startswith(("Uid:", "PPid:")):
                info[line.split(":", 1)[0]] = line.split(":", 1)[1].split()[0]
        return {"argv": argv, "uid": int(info["Uid"]),
                "ppid": int(info["PPid"])}
    except (OSError, KeyError, ValueError, UnicodeError):
        return None


def exact_node_entry(proc_root: Path, pid, script: Path, uid: int, parent=None):
    if not pid:
        return False
    p = process(proc_root, pid)
    if not p or p["uid"] != uid or len(p["argv"]) != 2:
        return False
    node, entry = p["argv"]
    if Path(node).name != "node" or entry != str(script):
        return False
    return parent is None or p["ppid"] == parent


def listening_inodes(proc_root: Path):
    found = []
    try:
        lines = (proc_root / "net/tcp").read_text().splitlines()[1:]
        for line in lines:
            cols = line.split()
            address, hexport = cols[1].split(":")
            if (address == LOOPBACK_V4 and int(hexport, 16) == PORT
                    and cols[3] == LISTEN):
                found.append(cols[9])
    except (OSError, IndexError, ValueError):
        return []
    return found


def owns_socket(proc_root: Path, pid: int, inode: str):
    try:
        for fd in (proc_root / str(pid) / "fd").iterdir():
            try:
                if os.readlink(fd) == "socket:[" + inode + "]":
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def health_local():
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:17443/health", timeout=3
        ) as response:
            if response.status != 200:
                return None
            return json.loads(response.read(8192))
    except (OSError, ValueError):
        return None


def inspect(package_root: Path, proc_root: Path, package_uid: int,
            health_probe=health_local, socket_probe=owns_socket):
    var = package_root / "var"
    runtime = package_root / "target/app/runtime.js"
    server = package_root / "target/app/server.js"
    observed_state = read_json(var / "state/runtime.json")
    state = observed_state if isinstance(observed_state, dict) else {}
    file_pid = read_pid(var / "state/runtime.pid")
    runtime_pid = numeric_pid(state.get("runtimePid"))
    server_pid = numeric_pid(state.get("serverPid"))
    inodes = listening_inodes(proc_root)
    observed_health = health_probe()
    health = observed_health if isinstance(observed_health, dict) else {}
    runtime_ok = exact_node_entry(proc_root, runtime_pid, runtime, package_uid)
    server_ok = exact_node_entry(
        proc_root, server_pid, server, package_uid, parent=runtime_pid
    )
    socket_ok = (len(inodes) == 1 and server_pid is not None
                 and socket_probe(proc_root, server_pid, inodes[0]))
    audit = health.get("audit")
    audit_ok = isinstance(audit, dict) and audit.get("ok") is True
    health_ok = (health.get("status") == "ok"
                 and health.get("bindAddress") == "127.0.0.1"
                 and health.get("port") == PORT
                 and health.get("nodeRole") == "relay"
                 and audit_ok)
    chain_ok = bool(state.get("status") == "running" and runtime_ok
                    and server_ok and socket_ok and health_ok)
    if not inodes:
        outcome = "NO_LOCAL_LISTENER_OR_PROC_VISIBILITY"
    elif chain_ok and file_pid == runtime_pid:
        outcome = "PROCESS_CHAIN_MATCHES_PIDFILE"
    elif chain_ok:
        outcome = "STALE_OR_MISSING_PIDFILE_CANDIDATE"
    else:
        outcome = "UNVERIFIED_OR_FOREIGN_LISTENER"
    return {
        "schema": "VERARELAY_READONLY_CUSTODY_DIAGNOSTIC_V1",
        "outcome": outcome,
        "claim_ceiling": "NON_ATTESTING_READONLY_DIAGNOSTIC",
        "package_root": str(package_root),
        "package_uid": package_uid,
        "pidfile_pid": file_pid,
        "state_runtime_pid": runtime_pid,
        "state_server_pid": server_pid,
        "loopback_listeners": len(inodes),
        "runtime_argv_uid_match": runtime_ok,
        "server_parent_argv_uid_match": server_ok,
        "server_socket_inode_match": bool(socket_ok),
        "health_metadata_audit_match": health_ok,
        "reported_version": health.get("version"),
        "pidfile_requires_manual_review": outcome == "STALE_OR_MISSING_PIDFILE_CANDIDATE",
        "mutations_performed": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package-root", type=Path,
                   default=Path("/var/packages/VeraRelay"))
    p.add_argument("--proc-root", type=Path, default=Path("/proc"))
    args = p.parse_args()
    try:
        import pwd
        uid = pwd.getpwnam("VeraRelay").pw_uid
    except (ImportError, KeyError):
        p.error("VeraRelay package user is absent or unavailable")
    result = inspect(args.package_root, args.proc_root, uid)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["outcome"] == "PROCESS_CHAIN_MATCHES_PIDFILE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
