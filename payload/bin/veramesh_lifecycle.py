#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, NamedTuple

SCHEMA = "VERA_MESH_PACKAGE_LIFECYCLE_STATE_V2"
PROFILE_ID = "VERA_MESH_FIRST_SLICE_LIFECYCLE_PROFILE_V1"
SERIALIZATION_CANDIDATE = "PYTHON_FCNTL_FLOCK_TARGET_QUALIFICATION_REQUIRED"
PACKAGE_VERSION = "0.1.0-0017"
INSTALLATION_STATES = {"CURRENT", "RETIRED"}
ALLOWED_STATES = {"STOPPED", "STARTING", "RUNNING", "STOPPING", "UNKNOWN"}
STOPPED_PROVENANCE = {"POSTINSTALL_NOT_STARTED", "AUTHORIZED_STOP"}
STATE_KEYS = {
    "schema",
    "installation_incarnation_id",
    "installation_status",
    "lifecycle_generation",
    "lifecycle_state",
    "stopped_provenance",
    "process_instance_id",
    "process_start_generation",
    "transition_id",
    "process_start_transition_id",
}
ID_RE = re.compile(r"[0-9a-f]{32}")
MAX_GENERATION = (1 << 63) - 1

STATE_PATH = Path("/var/packages/VeraMesh/var/vera/lifecycle-state.json")
LOCK_PATH = Path("/var/packages/VeraMesh/var/vera/lifecycle.lock")
SOCKET_PATH = Path("/var/packages/VeraMesh/tmp/run/control.sock")
CTL = "/usr/syno/bin/synosystemctl"
UNIT = "pkguser-veramesh.service"
SOCKET_TIMEOUT_SECONDS = 1.0
MAX_RESPONSE = 4096

STATUS_BASE = {
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

FIRST_SLICE_ACCEPTANCE_FINDINGS = [
    "MESH-FOUR-SPK-STATUS-UNKNOWN-COLLAPSE-007",
    "MESH-FOUR-SPK-PACKAGE-OWNED-INITIAL-STOPPED-GAP-008",
    "MESH-FOUR-SPK-LIFECYCLE-RESPONDER-BINDING-010",
]
RELEASE_LATER_NOT_ACCEPTANCE_TRANSFERRED = [
    "MESH-FOUR-SPK-INFO-ARCH-SCOPE-006",
    "MESH-FOUR-SPK-LIFECYCLE-CROSS-INSTALL-CONTAMINATION-009",
    "MESH-FOUR-SPK-LIFECYCLE-FAIL-SAFE-STOP-011",
    "MESH-SEVEN-SPK-LIFECYCLE-INCOMPLETE-TRANSITION-RECOVERY-012",
]

LIFECYCLE_PROFILE = {
    "schema": "VERA_MESH_FIRST_SLICE_LIFECYCLE_PROFILE_V1",
    "profile_id": PROFILE_ID,
    "state_schema": SCHEMA,
    "status_exit_contract": {"RUNNING": 0, "STOPPED": 3, "UNKNOWN": 4},
    "fresh_install_stopped_provenance": "POSTINSTALL_NOT_STARTED",
    "transition_linearization": "MONOTONIC_GENERATION_PLUS_FRESH_TRANSITION_ID",
    "running_responder_binding": [
        "installation_incarnation_id",
        "start_generation",
        "start_transition_id",
        "process_instance_id",
        "lifecycle_profile_sha256",
        "package_version",
    ],
    "ordinary_start": "STABLE_STOPPED_TO_STARTING_BEFORE_MANAGER_THEN_EXACT_RESPONDER_TO_RUNNING",
    "ordinary_stop": "STABLE_RUNNING_TO_STOPPING_BEFORE_MANAGER_THEN_MANAGER_SUCCESS_PLUS_SEMANTIC_ABSENCE_TO_STOPPED",
    "transitional_reentry": "STARTING_STOPPING_UNKNOWN_RETURN_UNKNOWN_WITHOUT_MANAGER_EFFECT",
    "start_on_invalid_authority": "FORBIDDEN",
    "first_slice_acceptance_findings": FIRST_SLICE_ACCEPTANCE_FINDINGS,
    "release_later_not_acceptance_transferred": RELEASE_LATER_NOT_ACCEPTANCE_TRANSFERRED,
}
LIFECYCLE_PROFILE_BYTES = json.dumps(
    LIFECYCLE_PROFILE, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")
LIFECYCLE_PROFILE_SHA256 = hashlib.sha256(LIFECYCLE_PROFILE_BYTES).hexdigest()


class ProbeResult(str, Enum):
    LIVE = "LIVE"
    ABSENT = "ABSENT"
    ERROR = "ERROR"


class ProbeObservation(NamedTuple):
    result: ProbeResult
    installation_incarnation_id: str | None = None
    start_generation: int | None = None
    start_transition_id: str | None = None
    process_instance_id: str | None = None
    lifecycle_profile_id: str | None = None
    lifecycle_profile_sha256: str | None = None
    package_version: str | None = None

    @classmethod
    def absent(cls) -> "ProbeObservation":
        return cls(ProbeResult.ABSENT)

    @classmethod
    def error(cls) -> "ProbeObservation":
        return cls(ProbeResult.ERROR)

    @classmethod
    def live(
        cls,
        installation_incarnation_id: str,
        start_generation: int,
        process_instance_id: str,
        start_transition_id: str | None = None,
    ) -> "ProbeObservation":
        return cls(
            ProbeResult.LIVE,
            installation_incarnation_id,
            start_generation,
            start_transition_id,
            process_instance_id,
            PROFILE_ID,
            LIFECYCLE_PROFILE_SHA256,
            PACKAGE_VERSION,
        )


class StartupBinding(NamedTuple):
    installation_incarnation_id: str
    start_generation: int
    start_transition_id: str
    process_instance_id: str
    lifecycle_profile_id: str
    lifecycle_profile_sha256: str
    package_version: str


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def _validate_state(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise ValueError("lifecycle state shape mismatch")
    if value.get("schema") != SCHEMA:
        raise ValueError("wrong lifecycle state schema")
    if not _valid_id(value.get("installation_incarnation_id")):
        raise ValueError("invalid installation lifecycle incarnation")
    if value.get("installation_status") not in INSTALLATION_STATES:
        raise ValueError("invalid installation status")
    generation = value.get("lifecycle_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or not 0 <= generation <= MAX_GENERATION:
        raise ValueError("invalid lifecycle generation")
    lifecycle_state = value.get("lifecycle_state")
    if lifecycle_state not in ALLOWED_STATES:
        raise ValueError("invalid lifecycle state")
    provenance = value.get("stopped_provenance")
    process_id = value.get("process_instance_id")
    process_start_generation = value.get("process_start_generation")
    transition_id = value.get("transition_id")
    process_start_transition_id = value.get("process_start_transition_id")
    if not _valid_id(transition_id):
        raise ValueError("invalid lifecycle transition id")
    if process_start_transition_id is not None and not _valid_id(process_start_transition_id):
        raise ValueError("invalid process start transition id")

    if value["installation_status"] == "RETIRED":
        if lifecycle_state != "UNKNOWN" or provenance is not None or process_id is not None or process_start_generation is not None or process_start_transition_id is not None:
            raise ValueError("retired installation may not carry current lifecycle authority")
        return value

    if lifecycle_state == "STOPPED":
        if provenance not in STOPPED_PROVENANCE:
            raise ValueError("STOPPED requires valid provenance")
        if process_id is not None or process_start_generation is not None or process_start_transition_id is not None:
            raise ValueError("STOPPED may not carry process authority")
    elif lifecycle_state == "RUNNING":
        if provenance is not None:
            raise ValueError("RUNNING may not carry stopped provenance")
        if not _valid_id(process_id):
            raise ValueError("RUNNING requires process instance")
        if (
            isinstance(process_start_generation, bool)
            or not isinstance(process_start_generation, int)
            or not 0 <= process_start_generation < generation
        ):
            raise ValueError("RUNNING requires valid process start generation")
    else:
        if provenance is not None or process_id is not None or process_start_generation is not None or process_start_transition_id is not None:
            raise ValueError("transitional/unknown state may not carry stable authority")
    return value


def _ensure_parent(path: Path) -> os.stat_result:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("lifecycle parent is not a real directory")
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(path, 0o700)
        st = path.lstat()
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise ValueError("lifecycle parent permissions are not private")
    return st


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_lifecycle_state(path: Path = STATE_PATH) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("lifecycle state path is not a regular file")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError("lifecycle state permissions too broad")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > 8192:
                raise ValueError("lifecycle state too large")
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("lifecycle state is not strict UTF-8 JSON") from exc
    return _validate_state(value)


def write_lifecycle_state_atomic(path: Path, value: dict) -> dict:
    value = _validate_state(dict(value))
    parent_stat = _ensure_parent(path.parent)
    data = _canonical_bytes(value)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.new")
    fd = -1
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = os.fstat(fd)
        if not stat.S_ISREG(created.st_mode):
            raise ValueError("lifecycle temp is not regular")
        if created.st_uid != parent_stat.st_uid or created.st_gid != parent_stat.st_gid:
            raise ValueError("lifecycle temp ownership mismatch")
        with os.fdopen(fd, "wb", closefd=False) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.close(fd)
        fd = -1
        current = temp.lstat()
        if current.st_dev != created.st_dev or current.st_ino != created.st_ino or not stat.S_ISREG(current.st_mode):
            raise ValueError("lifecycle temp changed before promotion")
        os.replace(temp, path)
        _fsync_directory(path.parent)
        return read_lifecycle_state(path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def lifecycle_writer_lock(lock_path: Path = LOCK_PATH) -> Iterator[None]:
    parent_stat = _ensure_parent(lock_path.parent)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("lifecycle lock is not a regular file")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("lifecycle lock mode is not 0600")
        if st.st_uid != parent_stat.st_uid or st.st_gid != parent_stat.st_gid:
            raise ValueError("lifecycle lock ownership mismatch")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _next_generation(value: dict) -> int:
    generation = value["lifecycle_generation"]
    if generation >= MAX_GENERATION:
        raise OverflowError("lifecycle generation exhausted")
    return generation + 1


def _state_after(
    value: dict,
    lifecycle_state: str,
    provenance: str | None = None,
    process_instance_id: str | None = None,
    process_start_generation: int | None = None,
    process_start_transition_id: str | None = None,
    transition_id: str | None = None,
) -> dict:
    result = dict(value)
    result["lifecycle_generation"] = _next_generation(value)
    result["lifecycle_state"] = lifecycle_state
    result["stopped_provenance"] = provenance
    result["process_instance_id"] = process_instance_id
    result["process_start_generation"] = process_start_generation
    result["process_start_transition_id"] = process_start_transition_id
    if transition_id is not None:
        if not _valid_id(transition_id):
            raise ValueError("invalid lifecycle transition id")
        result["transition_id"] = transition_id
    return _validate_state(result)


def _new_install_state(incarnation_id: str, transition_id: str) -> dict:
    return _validate_state(
        {
            "schema": SCHEMA,
            "installation_incarnation_id": incarnation_id,
            "installation_status": "CURRENT",
            "lifecycle_generation": 0,
            "lifecycle_state": "STOPPED",
            "stopped_provenance": "POSTINSTALL_NOT_STARTED",
            "process_instance_id": None,
            "process_start_generation": None,
            "transition_id": transition_id,
            "process_start_transition_id": None,
        }
    )


def _normalize_probe(value: object) -> ProbeObservation:
    if isinstance(value, ProbeObservation):
        return value
    if isinstance(value, ProbeResult):
        return ProbeObservation(value)
    return ProbeObservation.error()


def _safe_probe(probe: Callable[[], object]) -> ProbeObservation:
    try:
        return _normalize_probe(probe())
    except Exception:
        return ProbeObservation.error()


def bootstrap_install(
    state_path: Path = STATE_PATH,
    lock_path: Path = LOCK_PATH,
    probe: Callable[[], object] | None = None,
    incarnation_factory: Callable[[], str] | None = None,
    transition_factory: Callable[[], str] | None = None,
) -> dict:
    probe = probe or probe_control_socket
    incarnation_factory = incarnation_factory or (lambda: secrets.token_hex(16))
    transition_factory = transition_factory or (lambda: secrets.token_hex(16))
    with lifecycle_writer_lock(lock_path):
        try:
            read_lifecycle_state(state_path)
        except FileNotFoundError:
            pass
        except Exception:
            raise
        if _safe_probe(probe).result is not ProbeResult.ABSENT:
            raise ValueError("fresh install cannot prove semantic control socket absent")
        incarnation_id = incarnation_factory()
        if not _valid_id(incarnation_id):
            raise ValueError("invalid installation incarnation factory output")
        transition_id = transition_factory()
        if not _valid_id(transition_id):
            raise ValueError("invalid transition factory output")
        return write_lifecycle_state_atomic(state_path, _new_install_state(incarnation_id, transition_id))


def _archive_retired_state(state_path: Path, current: dict) -> Path:
    raw = _canonical_bytes(current)
    archive = state_path.with_name(
        f"lifecycle-state.retired.{current['installation_incarnation_id']}.g{current['lifecycle_generation']}.json"
    )
    if archive.exists() or archive.is_symlink():
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            existing = os.read(fd, 8192)
            if os.read(fd, 1):
                raise ValueError("retired lifecycle archive too large")
        finally:
            os.close(fd)
        if existing != raw:
            raise ValueError("retired lifecycle archive collision")
        return archive
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(state_path.parent)
    return archive


def recover_retired_upgrade(
    state_path: Path = STATE_PATH,
    lock_path: Path = LOCK_PATH,
    probe: Callable[[], object] | None = None,
    incarnation_factory: Callable[[], str] | None = None,
    transition_factory: Callable[[], str] | None = None,
) -> dict | None:
    probe = probe or probe_control_socket
    incarnation_factory = incarnation_factory or (lambda: secrets.token_hex(16))
    transition_factory = transition_factory or (lambda: secrets.token_hex(16))
    with lifecycle_writer_lock(lock_path):
        current = read_lifecycle_state(state_path)
        if current["installation_status"] != "RETIRED":
            return None
        if _safe_probe(probe).result is not ProbeResult.ABSENT:
            raise ValueError("retired upgrade recovery cannot prove semantic control socket absent")
        incarnation_id = incarnation_factory()
        transition_id = transition_factory()
        if not _valid_id(incarnation_id):
            raise ValueError("invalid installation incarnation factory output")
        if not _valid_id(transition_id):
            raise ValueError("invalid transition factory output")
        _archive_retired_state(state_path, current)
        return write_lifecycle_state_atomic(
            state_path,
            _new_install_state(incarnation_id, transition_id),
        )


def postinstall_context(
    pkg_status: str,
    state_path: Path = STATE_PATH,
    lock_path: Path = LOCK_PATH,
    probe: Callable[[], object] | None = None,
    incarnation_factory: Callable[[], str] | None = None,
    transition_factory: Callable[[], str] | None = None,
) -> dict | None:
    if pkg_status == "INSTALL":
        return bootstrap_install(state_path, lock_path, probe, incarnation_factory, transition_factory)
    if pkg_status == "UPGRADE":
        return recover_retired_upgrade(state_path, lock_path, probe, incarnation_factory, transition_factory)
    return None


def retire_uninstall(state_path: Path = STATE_PATH, lock_path: Path = LOCK_PATH) -> dict:
    with lifecycle_writer_lock(lock_path):
        current = read_lifecycle_state(state_path)
        if current["installation_status"] == "RETIRED":
            return current
        retired = dict(current)
        retired["installation_status"] = "RETIRED"
        retired["lifecycle_generation"] = _next_generation(current)
        retired["lifecycle_state"] = "UNKNOWN"
        retired["stopped_provenance"] = None
        retired["process_instance_id"] = None
        retired["process_start_generation"] = None
        retired["process_start_transition_id"] = None
        return write_lifecycle_state_atomic(state_path, retired)


def _best_effort_unknown(state_path: Path, value: dict) -> None:
    try:
        write_lifecycle_state_atomic(state_path, _state_after(value, "UNKNOWN"))
    except Exception:
        pass


def _live_matches_start(observation: ProbeObservation, starting: dict) -> bool:
    return (
        observation.result is ProbeResult.LIVE
        and observation.lifecycle_profile_id == PROFILE_ID
        and observation.lifecycle_profile_sha256 == LIFECYCLE_PROFILE_SHA256
        and observation.package_version == PACKAGE_VERSION
        and observation.installation_incarnation_id == starting["installation_incarnation_id"]
        and observation.start_generation == starting["lifecycle_generation"]
        and observation.start_transition_id == starting["transition_id"]
        and _valid_id(observation.process_instance_id)
    )


def _live_matches_running(observation: ProbeObservation, running: dict) -> bool:
    return (
        observation.result is ProbeResult.LIVE
        and observation.lifecycle_profile_id == PROFILE_ID
        and observation.lifecycle_profile_sha256 == LIFECYCLE_PROFILE_SHA256
        and observation.package_version == PACKAGE_VERSION
        and observation.installation_incarnation_id == running["installation_incarnation_id"]
        and observation.start_generation == running["process_start_generation"]
        and observation.start_transition_id == running["process_start_transition_id"]
        and observation.process_instance_id == running["process_instance_id"]
    )


def start_transition(
    state_path: Path,
    lock_path: Path,
    manager_start: Callable[[], int],
    probe: Callable[[], object],
) -> int:
    try:
        with lifecycle_writer_lock(lock_path):
            try:
                current = read_lifecycle_state(state_path)
            except Exception:
                return 4
            if current["installation_status"] != "CURRENT" or current["lifecycle_state"] != "STOPPED":
                return 4
            try:
                start_transition_id = secrets.token_hex(16)
                starting = _state_after(current, "STARTING", transition_id=start_transition_id)
                write_lifecycle_state_atomic(state_path, starting)
            except Exception:
                return 4
            try:
                manager_rc = manager_start()
            except Exception:
                manager_rc = -1
            if manager_rc != 0:
                _best_effort_unknown(state_path, starting)
                return 4
            observation = _safe_probe(probe)
            if not _live_matches_start(observation, starting):
                _best_effort_unknown(state_path, starting)
                return 4
            try:
                running = _state_after(
                    starting,
                    "RUNNING",
                    process_instance_id=observation.process_instance_id,
                    process_start_generation=starting["lifecycle_generation"],
                    process_start_transition_id=starting["transition_id"],
                )
                write_lifecycle_state_atomic(state_path, running)
            except Exception:
                return 4
            return 0
    except Exception:
        return 4


def stop_transition(
    state_path: Path,
    lock_path: Path,
    manager_stop: Callable[[], int],
    probe: Callable[[], object],
) -> int:
    try:
        with lifecycle_writer_lock(lock_path):
            try:
                current = read_lifecycle_state(state_path)
            except Exception:
                # Fail-safe process shutdown is allowed only after the writer lock is
                # securely held. Evidence authority remains UNKNOWN and existing bytes
                # are deliberately preserved. This release-later safety fix may ride the
                # first-slice source head but is not part of first-slice acceptance.
                try:
                    manager_stop()
                except Exception:
                    pass
                _safe_probe(probe)
                return 4
            if current["installation_status"] != "CURRENT":
                return 4
            if current["lifecycle_state"] == "STOPPED":
                return 0 if _safe_probe(probe).result is ProbeResult.ABSENT else 4
            if current["lifecycle_state"] != "RUNNING":
                return 4
            try:
                stop_transition_id = secrets.token_hex(16)
                stopping = _state_after(current, "STOPPING", transition_id=stop_transition_id)
                write_lifecycle_state_atomic(state_path, stopping)
            except Exception:
                return 4

            try:
                manager_rc = manager_stop()
            except Exception:
                manager_rc = -1
            if manager_rc != 0:
                _best_effort_unknown(state_path, stopping)
                return 4
            observation = _safe_probe(probe)
            if observation.result is not ProbeResult.ABSENT:
                _best_effort_unknown(state_path, stopping)
                return 4
            try:
                stopped = _state_after(stopping, "STOPPED", "AUTHORIZED_STOP")
                write_lifecycle_state_atomic(state_path, stopped)
            except Exception:
                return 4
            return 0
    except Exception:
        return 4


def status_code(state_path: Path = STATE_PATH, probe: Callable[[], object] | None = None) -> int:
    probe = probe or probe_control_socket
    try:
        before = read_lifecycle_state(state_path)
        if before["installation_status"] != "CURRENT":
            return 4
        if before["lifecycle_state"] in {"STARTING", "STOPPING", "UNKNOWN"}:
            return 4
        observed = _safe_probe(probe)
        after = read_lifecycle_state(state_path)
    except Exception:
        return 4
    if before != after:
        return 4
    if before["lifecycle_state"] == "RUNNING":
        return 0 if _live_matches_running(observed, before) else 4
    if before["lifecycle_state"] == "STOPPED":
        return 3 if observed.result is ProbeResult.ABSENT else 4
    return 4


def capture_startup_binding(
    state_path: Path = STATE_PATH,
    process_instance_factory: Callable[[], str] | None = None,
) -> StartupBinding:
    process_instance_factory = process_instance_factory or (lambda: secrets.token_hex(16))
    state = read_lifecycle_state(state_path)
    if state["installation_status"] != "CURRENT" or state["lifecycle_state"] != "STARTING":
        raise ValueError("daemon startup requires current STARTING lifecycle authority")
    process_id = process_instance_factory()
    if not _valid_id(process_id):
        raise ValueError("invalid process instance factory output")
    return StartupBinding(
        state["installation_incarnation_id"],
        state["lifecycle_generation"],
        state["transition_id"],
        process_id,
        PROFILE_ID,
        LIFECYCLE_PROFILE_SHA256,
        PACKAGE_VERSION,
    )


def _parse_status_response(data: bytes) -> ProbeObservation:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("control status response is not strict JSON") from exc
    required = dict(STATUS_BASE)
    for key, expected in required.items():
        if value.get(key) != expected:
            raise ValueError("control status response semantic contract mismatch")
    if set(value) != set(required) | {
        "lifecycle_profile_id",
        "lifecycle_profile_sha256",
        "package_version",
        "installation_incarnation_id",
        "start_generation",
        "start_transition_id",
        "process_instance_id",
    }:
        raise ValueError("control status response shape mismatch")
    if (
        value["lifecycle_profile_id"] != PROFILE_ID
        or value["lifecycle_profile_sha256"] != LIFECYCLE_PROFILE_SHA256
        or value["package_version"] != PACKAGE_VERSION
    ):
        raise ValueError("control status response lifecycle profile mismatch")
    if not _valid_id(value["installation_incarnation_id"]) or not _valid_id(value["process_instance_id"]):
        raise ValueError("control status response identity invalid")
    start_generation = value["start_generation"]
    if isinstance(start_generation, bool) or not isinstance(start_generation, int) or not 0 <= start_generation <= MAX_GENERATION:
        raise ValueError("control status response generation invalid")
    if not _valid_id(value["start_transition_id"]):
        raise ValueError("control status response transition id invalid")
    return ProbeObservation.live(
        value["installation_incarnation_id"],
        start_generation,
        value["process_instance_id"],
        value["start_transition_id"],
    )


def probe_control_socket() -> ProbeObservation:
    try:
        st = SOCKET_PATH.lstat()
    except FileNotFoundError:
        return ProbeObservation.absent()
    if not stat.S_ISSOCK(st.st_mode):
        return ProbeObservation.error()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(SOCKET_TIMEOUT_SECONDS)
        client.connect(str(SOCKET_PATH))
        client.sendall(b'{"op":"status"}\n')
        buf = bytearray()
        while True:
            chunk = client.recv(1024)
            if not chunk:
                return ProbeObservation.error()
            buf.extend(chunk)
            if len(buf) > MAX_RESPONSE:
                return ProbeObservation.error()
            newline = buf.find(b"\n")
            if newline >= 0:
                if bytes(buf[newline + 1:]).strip():
                    return ProbeObservation.error()
                return _parse_status_response(bytes(buf[:newline]))
    except (OSError, ValueError):
        return ProbeObservation.error()
    finally:
        client.close()


def _manager_call(verb: str) -> int:
    try:
        proc = subprocess.run([CTL, verb, UNIT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return 255
    return proc.returncode


def main(argv: list[str]) -> int:
    if argv[1:] == ["status"]:
        return status_code()
    if argv[1:] == ["start"]:
        return start_transition(STATE_PATH, LOCK_PATH, lambda: _manager_call("start"), probe_control_socket)
    if argv[1:] == ["stop"]:
        return stop_transition(STATE_PATH, LOCK_PATH, lambda: _manager_call("stop"), probe_control_socket)
    if argv[1:] == ["retire-uninstall"]:
        try:
            retire_uninstall()
        except Exception as exc:
            print(f"LIFECYCLE_UNKNOWN: {exc}", file=sys.stderr)
            return 4
        return 0
    if len(argv) == 3 and argv[1] == "postinstall":
        try:
            postinstall_context(argv[2])
        except Exception as exc:
            print(f"LIFECYCLE_UNKNOWN: {exc}", file=sys.stderr)
            return 4
        return 0
    print("usage: veramesh_lifecycle.py {postinstall PKG_STATUS|retire-uninstall|start|stop|status}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
