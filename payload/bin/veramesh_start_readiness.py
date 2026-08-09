#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import secrets
import socket
import stat
import sys
import time
from enum import Enum
from typing import Callable, NamedTuple


ALGORITHM_PROFILE_ID = "VERA_MESH_START_READINESS_ALGORITHM_V1"
ALGORITHM_PROFILE = {
    "schema": ALGORITHM_PROFILE_ID,
    "manager_start_count": "EXACTLY_ONCE_AFTER_DURABLE_STARTING",
    "serialization": "HOLD_LIFECYCLE_WRITER_LOCK_THROUGH_READINESS_WINDOW",
    "clock": "MONOTONIC",
    "retryable": [
        "ABSENT",
        "NOT_READY_TRANSIENT_TARGET_QUALIFIED_ONLY",
    ],
    "terminal_fail_closed": [
        "WRONG_LIVE_BINDING",
        "MALFORMED_OR_OVERSIZED_OR_TRAILING_RESPONSE",
        "NON_SOCKET_SUBSTITUTION",
        "PROFILE_OR_PACKAGE_OR_INCARNATION_OR_GENERATION_OR_TRANSITION_OR_PROCESS_MISMATCH",
        "UNQUALIFIED_TRANSPORT_ERROR",
        "DEADLINE_EXPIRED",
    ],
    "deadline_seconds": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "poll_interval_seconds": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "probe_timeout_cap_seconds": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "transient_errno_allowlist": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "cutoff_boundary": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "package_center_status": "LOCK_FREE_RC4_WHILE_STARTING",
}
ALGORITHM_PROFILE_BYTES = json.dumps(
    ALGORITHM_PROFILE, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")
ALGORITHM_PROFILE_SHA256 = hashlib.sha256(ALGORITHM_PROFILE_BYTES).hexdigest()


class ReadinessKind(str, Enum):
    LIVE = "LIVE"
    ABSENT = "ABSENT"
    NOT_READY_TRANSIENT = "NOT_READY_TRANSIENT"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"


class ReadinessObservation(NamedTuple):
    kind: ReadinessKind
    payload: object | None = None
    cause: str | None = None

    @classmethod
    def live(cls, payload: object) -> "ReadinessObservation":
        return cls(ReadinessKind.LIVE, payload, None)

    @classmethod
    def absent(cls) -> "ReadinessObservation":
        return cls(ReadinessKind.ABSENT, None, None)

    @classmethod
    def not_ready_transient(cls, cause: str) -> "ReadinessObservation":
        return cls(ReadinessKind.NOT_READY_TRANSIENT, None, cause)

    @classmethod
    def integrity_error(cls, cause: str) -> "ReadinessObservation":
        return cls(ReadinessKind.INTEGRITY_ERROR, None, cause)

    @classmethod
    def transport_error(cls, cause: str) -> "ReadinessObservation":
        return cls(ReadinessKind.TRANSPORT_ERROR, None, cause)


class ReadinessPolicy(NamedTuple):
    deadline_seconds: float
    poll_interval_seconds: float
    probe_timeout_cap_seconds: float
    transient_errnos: frozenset[int]
    accept_live_at_cutoff: bool

    def validate(self) -> "ReadinessPolicy":
        numeric = (
            self.deadline_seconds,
            self.poll_interval_seconds,
            self.probe_timeout_cap_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0.0
            for value in numeric
        ):
            raise ValueError("readiness timing policy must contain positive finite numeric bounds")
        if self.poll_interval_seconds > self.deadline_seconds:
            raise ValueError("readiness poll interval exceeds parent deadline")
        if self.probe_timeout_cap_seconds > self.deadline_seconds:
            raise ValueError("readiness probe cap exceeds parent deadline")
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in self.transient_errnos):
            raise ValueError("transient errno allowlist must contain positive integers only")
        if not isinstance(self.accept_live_at_cutoff, bool):
            raise ValueError("cutoff boundary policy must be boolean")
        return self


# Deliberately unbound in this source-only successor. A later DS216 qualification
# must materialize a versioned numeric policy and rebind the artifact/reviews.
TARGET_POLICY: ReadinessPolicy | None = None


def _load_lifecycle():
    import veramesh_lifecycle as lifecycle
    return lifecycle


def _unknown(api, state_path, starting) -> int:
    try:
        api._best_effort_unknown(state_path, starting)
    except Exception:
        pass
    return 4


def _within_cutoff(observed_at: float, deadline_at: float, policy: ReadinessPolicy) -> bool:
    if observed_at < deadline_at:
        return True
    return policy.accept_live_at_cutoff and observed_at == deadline_at


def start_transition_bounded(
    state_path,
    lock_path,
    manager_start: Callable[[], int],
    probe: Callable[[float, ReadinessPolicy], ReadinessObservation],
    policy: ReadinessPolicy,
    *,
    api=None,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    transition_factory: Callable[[], str] | None = None,
) -> int:
    api = api or _load_lifecycle()
    transition_factory = transition_factory or (lambda: secrets.token_hex(16))
    try:
        policy = policy.validate()
    except Exception:
        return 4

    try:
        with api.lifecycle_writer_lock(lock_path):
            try:
                current = api.read_lifecycle_state(state_path)
            except Exception:
                return 4
            if current.get("installation_status") != "CURRENT" or current.get("lifecycle_state") != "STOPPED":
                return 4

            try:
                transition_id = transition_factory()
                starting = api._state_after(current, "STARTING", transition_id=transition_id)
                api.write_lifecycle_state_atomic(state_path, starting)
            except Exception:
                return 4

            try:
                manager_rc = manager_start()
            except Exception:
                manager_rc = -1
            if manager_rc != 0:
                return _unknown(api, state_path, starting)

            try:
                started_at = float(monotonic())
            except Exception:
                return _unknown(api, state_path, starting)
            deadline_at = started_at + float(policy.deadline_seconds)

            while True:
                try:
                    before_probe = float(monotonic())
                except Exception:
                    return _unknown(api, state_path, starting)
                remaining = deadline_at - before_probe
                if remaining <= 0.0:
                    return _unknown(api, state_path, starting)

                timeout_budget = min(float(policy.probe_timeout_cap_seconds), remaining)
                try:
                    observation = probe(timeout_budget, policy)
                except Exception:
                    return _unknown(api, state_path, starting)
                if not isinstance(observation, ReadinessObservation):
                    return _unknown(api, state_path, starting)

                try:
                    completed_at = float(monotonic())
                except Exception:
                    return _unknown(api, state_path, starting)

                if observation.kind is ReadinessKind.LIVE:
                    if not _within_cutoff(completed_at, deadline_at, policy):
                        return _unknown(api, state_path, starting)
                    try:
                        if not api._live_matches_start(observation.payload, starting):
                            return _unknown(api, state_path, starting)
                        process_id = getattr(observation.payload, "process_instance_id", None)
                        if process_id is None and isinstance(observation.payload, dict):
                            process_id = observation.payload.get("process_instance_id")
                        running = api._state_after(
                            starting,
                            "RUNNING",
                            process_instance_id=process_id,
                            process_start_generation=starting["lifecycle_generation"],
                            process_start_transition_id=starting["transition_id"],
                        )
                        api.write_lifecycle_state_atomic(state_path, running)
                    except Exception:
                        return 4
                    return 0

                if observation.kind not in {ReadinessKind.ABSENT, ReadinessKind.NOT_READY_TRANSIENT}:
                    return _unknown(api, state_path, starting)

                remaining_after_probe = deadline_at - completed_at
                if remaining_after_probe <= 0.0:
                    return _unknown(api, state_path, starting)

                sleep_for = min(float(policy.poll_interval_seconds), remaining_after_probe)
                if sleep_for <= 0.0:
                    return _unknown(api, state_path, starting)
                try:
                    sleeper(sleep_for)
                except Exception:
                    return _unknown(api, state_path, starting)
    except Exception:
        return 4


def _set_remaining_socket_timeout(client, deadline_at: float, monotonic: Callable[[], float]) -> bool:
    try:
        remaining = float(deadline_at) - float(monotonic())
    except Exception:
        return False
    if not math.isfinite(remaining) or remaining <= 0.0:
        return False
    client.settimeout(remaining)
    return True


def probe_control_socket_bounded(
    timeout_seconds: float,
    policy: ReadinessPolicy,
    *,
    api=None,
    monotonic: Callable[[], float] = time.monotonic,
) -> ReadinessObservation:
    api = api or _load_lifecycle()
    try:
        timeout_seconds = float(timeout_seconds)
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0.0:
            return ReadinessObservation.integrity_error("invalid_probe_budget")
        deadline_at = float(monotonic()) + timeout_seconds
    except Exception:
        return ReadinessObservation.integrity_error("invalid_probe_budget")

    try:
        st = api.SOCKET_PATH.lstat()
    except FileNotFoundError:
        return ReadinessObservation.absent()
    except OSError as exc:
        if exc.errno in policy.transient_errnos:
            return ReadinessObservation.not_ready_transient(f"lstat_errno_{exc.errno}")
        return ReadinessObservation.transport_error(f"lstat_errno_{exc.errno}")

    if not stat.S_ISSOCK(st.st_mode):
        return ReadinessObservation.integrity_error("control_path_not_socket")

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if not _set_remaining_socket_timeout(client, deadline_at, monotonic):
            return ReadinessObservation.transport_error("probe_deadline_expired")
        client.connect(str(api.SOCKET_PATH))

        if not _set_remaining_socket_timeout(client, deadline_at, monotonic):
            return ReadinessObservation.transport_error("probe_deadline_expired")
        client.sendall(b'{"op":"status"}\n')

        buf = bytearray()
        newline = -1
        while True:
            if not _set_remaining_socket_timeout(client, deadline_at, monotonic):
                return ReadinessObservation.transport_error("probe_deadline_expired")
            chunk = client.recv(1024)
            if not chunk:
                if newline < 0:
                    return ReadinessObservation.integrity_error("eof_before_complete_response")
                try:
                    parsed = api._parse_status_response(bytes(buf[:newline]))
                except ValueError:
                    return ReadinessObservation.integrity_error("invalid_status_response")
                return ReadinessObservation.live(parsed)

            buf.extend(chunk)
            if len(buf) > api.MAX_RESPONSE:
                return ReadinessObservation.integrity_error("oversized_response")

            if newline < 0:
                newline = buf.find(b"\n")
            if newline >= 0 and newline != len(buf) - 1:
                return ReadinessObservation.integrity_error("trailing_response_bytes")
    except (TimeoutError, socket.timeout):
        return ReadinessObservation.transport_error("probe_deadline_expired")
    except OSError as exc:
        if exc.errno in policy.transient_errnos:
            return ReadinessObservation.not_ready_transient(f"socket_errno_{exc.errno}")
        return ReadinessObservation.transport_error(f"socket_errno_{exc.errno}")
    finally:
        client.close()


def runtime_start(*, api=None, manager_start=None) -> int:
    api = api or _load_lifecycle()
    policy = TARGET_POLICY
    if policy is None:
        return 4
    manager_start = manager_start or (lambda: api._manager_call("start"))
    return start_transition_bounded(
        api.STATE_PATH,
        api.LOCK_PATH,
        manager_start,
        lambda timeout, selected: probe_control_socket_bounded(timeout, selected, api=api),
        policy,
        api=api,
    )


def main(argv: list[str]) -> int:
    if argv[1:] != ["start"]:
        print("usage: veramesh_start_readiness.py start", file=sys.stderr)
        return 64
    if TARGET_POLICY is None:
        print(
            "LIFECYCLE_UNKNOWN: start readiness target policy is not qualified/bound",
            file=sys.stderr,
        )
        return 4
    return runtime_start()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
