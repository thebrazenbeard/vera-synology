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


ALGORITHM_PROFILE_ID = "VERA_MESH_START_READINESS_ALGORITHM_V2"
ALGORITHM_PROFILE = {
    "schema": ALGORITHM_PROFILE_ID,
    "manager_start_count": "EXACTLY_ONCE_AFTER_DURABLE_STARTING",
    "serialization": "HOLD_LIFECYCLE_WRITER_LOCK_THROUGH_READINESS_WINDOW",
    "clock": "MONOTONIC_NS_INTEGER",
    "retryable": [
        "ABSENT",
        "NOT_READY_TRANSIENT_TARGET_QUALIFIED_STAGE_AND_ERRNO_ONLY",
    ],
    "terminal_fail_closed": [
        "WRONG_LIVE_BINDING",
        "MALFORMED_OR_OVERSIZED_OR_TRAILING_RESPONSE",
        "NON_SOCKET_SUBSTITUTION",
        "PROFILE_OR_PACKAGE_OR_INCARNATION_OR_GENERATION_OR_TRANSITION_OR_PROCESS_MISMATCH",
        "UNQUALIFIED_TRANSPORT_ERROR",
        "DEADLINE_EXPIRED",
    ],
    "deadline_ns": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "poll_interval_ns": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "probe_timeout_cap_ns": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "transient_stage_errno_allowlist": "TARGET_QUALIFIED_PROFILE_INPUT_UNBOUND",
    "cutoff_boundary": "STRICT_OBSERVED_AT_NS_LT_DEADLINE_AT_NS",
    "probe_boundary": "PRE_LSTAT_THROUGH_EOF_FINALITY_ONE_ABSOLUTE_DEADLINE",
    "package_center_status": "LOCK_FREE_RC4_WHILE_STARTING",
}
ALGORITHM_PROFILE_BYTES = json.dumps(
    ALGORITHM_PROFILE, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("utf-8")
ALGORITHM_PROFILE_SHA256 = hashlib.sha256(ALGORITHM_PROFILE_BYTES).hexdigest()

NS_PER_SECOND = 1_000_000_000


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
    deadline_ns: int
    poll_interval_ns: int
    probe_timeout_cap_ns: int
    transient_stage_errnos: frozenset[tuple[str, int]]

    def validate(self) -> "ReadinessPolicy":
        numeric = (self.deadline_ns, self.poll_interval_ns, self.probe_timeout_cap_ns)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in numeric):
            raise ValueError("readiness timing policy must contain positive integer nanosecond bounds")
        if self.poll_interval_ns > self.deadline_ns:
            raise ValueError("readiness poll interval exceeds parent deadline")
        if self.probe_timeout_cap_ns > self.deadline_ns:
            raise ValueError("readiness probe cap exceeds parent deadline")
        for value in self.transient_stage_errnos:
            if (
                not isinstance(value, tuple)
                or len(value) != 2
                or value[0] not in {"LSTAT", "CONNECT", "SEND", "RECEIVE", "FINALITY"}
                or isinstance(value[1], bool)
                or not isinstance(value[1], int)
                or value[1] <= 0
            ):
                raise ValueError("transient allowlist must contain closed (stage, positive errno) pairs")
        return self


# Deliberately unbound in this source-only successor. A later DS216 qualification
# must materialize a versioned integer-nanosecond policy and rebind the artifact/reviews.
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


def _deadline_expired(deadline_at_ns: int, monotonic_ns: Callable[[], int]) -> bool:
    try:
        now_ns = monotonic_ns()
    except Exception:
        return True
    return isinstance(now_ns, bool) or not isinstance(now_ns, int) or now_ns >= deadline_at_ns


def start_transition_bounded(
    state_path,
    lock_path,
    manager_start: Callable[[], int],
    probe: Callable[[int, ReadinessPolicy], ReadinessObservation],
    policy: ReadinessPolicy,
    *,
    api=None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
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
                started_at_ns = monotonic_ns()
            except Exception:
                return _unknown(api, state_path, starting)
            if isinstance(started_at_ns, bool) or not isinstance(started_at_ns, int):
                return _unknown(api, state_path, starting)
            deadline_at_ns = started_at_ns + policy.deadline_ns
            if deadline_at_ns <= started_at_ns:
                return _unknown(api, state_path, starting)

            while True:
                try:
                    before_probe_ns = monotonic_ns()
                except Exception:
                    return _unknown(api, state_path, starting)
                if isinstance(before_probe_ns, bool) or not isinstance(before_probe_ns, int):
                    return _unknown(api, state_path, starting)
                remaining_ns = deadline_at_ns - before_probe_ns
                if remaining_ns <= 0:
                    return _unknown(api, state_path, starting)

                timeout_budget_ns = min(policy.probe_timeout_cap_ns, remaining_ns)
                try:
                    observation = probe(timeout_budget_ns, policy)
                except Exception:
                    return _unknown(api, state_path, starting)
                if not isinstance(observation, ReadinessObservation):
                    return _unknown(api, state_path, starting)

                try:
                    completed_at_ns = monotonic_ns()
                except Exception:
                    return _unknown(api, state_path, starting)
                if isinstance(completed_at_ns, bool) or not isinstance(completed_at_ns, int):
                    return _unknown(api, state_path, starting)

                if observation.kind is ReadinessKind.LIVE:
                    if completed_at_ns >= deadline_at_ns:
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

                remaining_after_probe_ns = deadline_at_ns - completed_at_ns
                if remaining_after_probe_ns <= 0:
                    return _unknown(api, state_path, starting)

                sleep_ns = min(policy.poll_interval_ns, remaining_after_probe_ns)
                if sleep_ns <= 0:
                    return _unknown(api, state_path, starting)
                try:
                    sleeper(sleep_ns / NS_PER_SECOND)
                except Exception:
                    return _unknown(api, state_path, starting)
    except Exception:
        return 4


def _set_remaining_socket_timeout(
    client, deadline_at_ns: int, monotonic_ns: Callable[[], int]
) -> str | None:
    try:
        now_ns = monotonic_ns()
    except Exception:
        return "probe_deadline_expired"
    if isinstance(now_ns, bool) or not isinstance(now_ns, int):
        return "probe_deadline_expired"
    remaining_ns = deadline_at_ns - now_ns
    if remaining_ns <= 0:
        return "probe_deadline_expired"
    seconds = remaining_ns / NS_PER_SECOND
    # Socket APIs require seconds as float. Runtime acceptance still uses the
    # integer absolute deadline after every blocking result, so float rounding
    # can never authorize a late result.
    timeout = math.nextafter(seconds, 0.0)
    if timeout <= 0.0:
        timeout = seconds
    try:
        client.settimeout(timeout)
    except Exception:
        return "socket_timeout_configuration_error"
    return None


def _classify_oserror(
    exc: OSError,
    stage: str,
    policy: ReadinessPolicy,
    deadline_at_ns: int,
    monotonic_ns: Callable[[], int],
) -> ReadinessObservation:
    if _deadline_expired(deadline_at_ns, monotonic_ns):
        return ReadinessObservation.transport_error("probe_deadline_expired")
    cause = f"{stage.lower()}_errno_{exc.errno}"
    if (stage, exc.errno) in policy.transient_stage_errnos:
        return ReadinessObservation.not_ready_transient(cause)
    return ReadinessObservation.transport_error(cause)


def probe_control_socket_bounded(
    timeout_ns: int,
    policy: ReadinessPolicy,
    *,
    api=None,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> ReadinessObservation:
    api = api or _load_lifecycle()
    if isinstance(timeout_ns, bool) or not isinstance(timeout_ns, int) or timeout_ns <= 0:
        return ReadinessObservation.integrity_error("invalid_probe_budget")
    try:
        started_ns = monotonic_ns()
    except Exception:
        return ReadinessObservation.integrity_error("invalid_probe_budget")
    if isinstance(started_ns, bool) or not isinstance(started_ns, int):
        return ReadinessObservation.integrity_error("invalid_probe_budget")
    deadline_at_ns = started_ns + timeout_ns
    if deadline_at_ns <= started_ns:
        return ReadinessObservation.integrity_error("invalid_probe_budget")

    try:
        st = api.SOCKET_PATH.lstat()
    except FileNotFoundError:
        if _deadline_expired(deadline_at_ns, monotonic_ns):
            return ReadinessObservation.transport_error("probe_deadline_expired")
        return ReadinessObservation.absent()
    except OSError as exc:
        return _classify_oserror(exc, "LSTAT", policy, deadline_at_ns, monotonic_ns)

    if _deadline_expired(deadline_at_ns, monotonic_ns):
        return ReadinessObservation.transport_error("probe_deadline_expired")
    if not stat.S_ISSOCK(st.st_mode):
        return ReadinessObservation.integrity_error("control_path_not_socket")

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            timeout_error = _set_remaining_socket_timeout(client, deadline_at_ns, monotonic_ns)
            if timeout_error is not None:
                return ReadinessObservation.transport_error(timeout_error)
            client.connect(str(api.SOCKET_PATH))
        except (TimeoutError, socket.timeout):
            return ReadinessObservation.transport_error("probe_deadline_expired")
        except OSError as exc:
            return _classify_oserror(exc, "CONNECT", policy, deadline_at_ns, monotonic_ns)
        if _deadline_expired(deadline_at_ns, monotonic_ns):
            return ReadinessObservation.transport_error("probe_deadline_expired")

        try:
            timeout_error = _set_remaining_socket_timeout(client, deadline_at_ns, monotonic_ns)
            if timeout_error is not None:
                return ReadinessObservation.transport_error(timeout_error)
            client.sendall(b'{"op":"status"}\n')
        except (TimeoutError, socket.timeout):
            return ReadinessObservation.transport_error("probe_deadline_expired")
        except OSError as exc:
            return _classify_oserror(exc, "SEND", policy, deadline_at_ns, monotonic_ns)
        if _deadline_expired(deadline_at_ns, monotonic_ns):
            return ReadinessObservation.transport_error("probe_deadline_expired")

        buf = bytearray()
        newline = -1
        while True:
            stage = "FINALITY" if newline >= 0 else "RECEIVE"
            try:
                timeout_error = _set_remaining_socket_timeout(client, deadline_at_ns, monotonic_ns)
                if timeout_error is not None:
                    return ReadinessObservation.transport_error(timeout_error)
                chunk = client.recv(1024)
            except (TimeoutError, socket.timeout):
                return ReadinessObservation.transport_error("probe_deadline_expired")
            except OSError as exc:
                return _classify_oserror(exc, stage, policy, deadline_at_ns, monotonic_ns)
            if _deadline_expired(deadline_at_ns, monotonic_ns):
                return ReadinessObservation.transport_error("probe_deadline_expired")

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
