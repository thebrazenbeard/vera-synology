"""Host-admin-pinned R185 source/owner-key record; never a rights grant.

The NAS service account may READ but must not be able to replace this record.
It is installed only after an administrator separately inspects the real
owner packet and enrolls a genuine owner public key. This module neither
creates a key nor verifies source use rights, a private DEV bank or a GPU lease.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat


SCHEMA = "VERA_TRAININGDAY_R185_HOST_OWNER_SOURCE_PIN_V1"
STATUS = "HOST_SOURCE_PIN_INTEGRITY_ONLY_RIGHTS_HOLD"
FROZEN_R185 = {
    "corpus_id": "R18_ARITHMETIC",
    "r185_packet_sha256": "9b075ef15141da1de06e1324de151aebd3ca5cd0fac5fcfd15b85f7c804ef154",
    "manifest_sha256": "90b55cf8742f9222c91f88e5727dcd0113322e4721e4fd3d1bdcdf65f40d0836",
    "train_content_sha256": "3ef5d72682da4702235f05649f11582af49d73f551bb27a01715acab46099178",
    "selected_id_v2_sha256": "031f636d4bfea753e62c14008a3b4f1833a238956480e624ec783269e0b618e2",
}
FIELDS = frozenset({"schema", "generation", "owner_subject_id",
                    "owner_public_key_hex", "owner_key_sha256",
                    "revoked_owner_key_sha256"}) | frozenset(FROZEN_R185)
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,119}\Z")
MAX_BYTES = 8192


class SourcePinError(ValueError):
    """Malformed, untrusted, or changed NAS host source enrollment."""


def _need(ok):
    if not ok:
        raise SourcePinError("R185 host source pin rejected")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        _need(key not in obj)
        obj[key] = value
    return obj


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def inspect_pin_bytes(raw):
    """Strict SOURCE-ONLY format check against physically observed R185 hashes.

    This does not authenticate where the public key came from. An external
    NAS administrator must validate actual owner identity before installation.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    try:
        pin = json.loads(raw.decode("utf-8", errors="strict"),
                         object_pairs_hook=_unique,
                         parse_constant=lambda _: _need(False))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise SourcePinError("R185 host source pin rejected") from exc
    _need(type(pin) is dict and set(pin) == FIELDS and raw == _canonical(pin))
    _need(pin["schema"] == SCHEMA and type(pin["generation"]) is int
          and 1 <= pin["generation"] <= 2**63 - 2)
    _need(type(pin["owner_subject_id"]) is str
          and SUBJECT.fullmatch(pin["owner_subject_id"]) is not None)
    for key, expected in FROZEN_R185.items():
        _need(type(pin[key]) is str and pin[key] == expected)
    _need(type(pin["owner_public_key_hex"]) is str
          and HEX64.fullmatch(pin["owner_public_key_hex"]) is not None)
    key_sha = hashlib.sha256(bytes.fromhex(pin["owner_public_key_hex"])).hexdigest()
    _need(type(pin["owner_key_sha256"]) is str
          and pin["owner_key_sha256"] == key_sha)
    revoked = pin["revoked_owner_key_sha256"]
    _need(type(revoked) is list and len(revoked) <= 128
          and all(type(x) is str and HEX64.fullmatch(x) is not None for x in revoked)
          and revoked == sorted(set(revoked)) and key_sha not in revoked)
    return {
        "schema": SCHEMA, "status": STATUS,
        "source_pin_sha256": hashlib.sha256(raw).hexdigest(),
        "enrollment_generation": pin["generation"],
        "owner_key_fingerprint_sha256": key_sha,
        "train_content_sha256": FROZEN_R185["train_content_sha256"],
        "owner_identity_authenticated": False,
        "owner_source_use_rights_verified": False,
        "protected_dev_exclusion_custody_verified": False,
        "gpu_lease_granted": False,
        "authorizes_training": False,
    }


def load_host_owned_pin(path):
    """Check root-owned non-writable ancestry and read exact bytes by FD.

    No path is accepted from a network request; service unit must provide an
    exact administrator-controlled absolute path. Service UID is non-root.
    """
    _need(type(path) in (str, Path))
    target = Path(path)
    _need(target.is_absolute())
    # Every ancestor must be root-owned and not writable by a service user.
    for parent in (target.parent,) + tuple(target.parents)[1:]:
        try:
            mode = parent.lstat()
        except OSError as exc:
            raise SourcePinError("R185 host source pin parent unavailable") from exc
        _need(stat.S_ISDIR(mode.st_mode) and mode.st_uid == 0
              and not mode.st_mode & 0o022)
    fd = None
    try:
        fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(fd)
        _need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
              and not metadata.st_mode & 0o022 and 0 < metadata.st_size <= MAX_BYTES)
        raw = os.read(fd, MAX_BYTES + 1)
    except OSError as exc:
        raise SourcePinError("R185 host source pin file unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)
    return inspect_pin_bytes(raw)
