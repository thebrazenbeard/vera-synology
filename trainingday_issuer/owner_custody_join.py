"""Bind untrusted R185 source-pin and private-custody summaries, ALWAYS HOLD.

This is an offline, source-only compatibility check. It receives neither
protected prompts/answers nor a DEV nonce, creates no key, performs no owner
signature verification, and does not assert actual NAS/source custody. The
result MUST NOT be consumed as an independent rights or training grant.
"""

import hashlib
import json
import re

from trainingday_issuer.owner_source_pin import (
    FROZEN_R185, SourcePinError, inspect_pin_bytes,
)
from trainingday_issuer.private_dev_candidate import (
    GENERATOR_SCHEMA, SCHEMA as PRIVATE_SCHEMA, STATUS as PRIVATE_STATUS,
)


SCHEMA = "VERA_R18_OWNER_PRIVATE_CUSTODY_JOIN_CANDIDATE_V1"
STATUS = "CONSISTENT_UNAUTHENTICATED_HOLD"
DOMAIN = SCHEMA.encode("ascii") + b"\x00"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PRIVATE_FIELDS = frozenset({
    "schema", "status", "corpus_id", "manifest_sha256", "train_sha256",
    "train_content_sha256", "selected_id_v2_sha256",
    "generator_source_sha256", "dev_generator_schema", "dev_count",
    "dev_sha256", "protected_exclusion_count",
    "protected_exclusion_sha256", "private_content_returned",
    "independent_custody_authenticated", "owner_identity_authenticated",
    "source_use_rights_verified", "host_ratification_authenticated",
    "authorizes_training", "authorizes_eval_unseal",
})
FALSE_FIELDS = frozenset({
    "private_content_returned", "independent_custody_authenticated",
    "owner_identity_authenticated", "source_use_rights_verified",
    "host_ratification_authenticated", "authorizes_training",
    "authorizes_eval_unseal",
})
DIGEST_FIELDS = frozenset({
    "manifest_sha256", "train_sha256", "train_content_sha256",
    "selected_id_v2_sha256", "generator_source_sha256",
    "dev_sha256", "protected_exclusion_sha256",
})


class CustodyJoinError(ValueError):
    """An untrusted source/custody summary cannot be structurally joined."""


def _require(ok):
    if not ok:
        raise CustodyJoinError("R185 source/private custody candidate rejected")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def join_owner_and_private_custody(owner_pin_bytes, private_commitment):
    """Return an answer-free candidate commitment with NO authenticated grant.

    `inspect_pin_bytes` checks only canonical pin shape/source constants, not
    that the bytes were physically loaded from a root-owned NAS enrollment.
    The private summary likewise may be caller-forged: even a consistent join
    supplies no owner identity, independent evaluator, source rights, lease,
    protected eval access or physical training authority.
    """
    try:
        pin = inspect_pin_bytes(owner_pin_bytes)
    except SourcePinError as exc:
        raise CustodyJoinError("R185 source/private custody candidate rejected") from exc
    _require(type(private_commitment) is dict
             and set(private_commitment) == PRIVATE_FIELDS)
    _require(private_commitment["schema"] == PRIVATE_SCHEMA
             and private_commitment["status"] == PRIVATE_STATUS
             and private_commitment["corpus_id"] == FROZEN_R185["corpus_id"]
             and private_commitment["dev_generator_schema"] == GENERATOR_SCHEMA)
    for field in DIGEST_FIELDS:
        value = private_commitment[field]
        _require(type(value) is str and HEX64.fullmatch(value) is not None)
    for field in FALSE_FIELDS:
        _require(private_commitment[field] is False)
    _require(type(private_commitment["dev_count"]) is int
             and private_commitment["dev_count"] == 64
             and type(private_commitment["protected_exclusion_count"]) is int
             and private_commitment["protected_exclusion_count"] == 128)
    for field in ("manifest_sha256", "train_content_sha256",
                  "selected_id_v2_sha256"):
        _require(private_commitment[field] == FROZEN_R185[field])
    payload = {
        "owner_source_pin_sha256": pin["source_pin_sha256"],
        "owner_key_fingerprint_sha256": pin["owner_key_fingerprint_sha256"],
        "enrollment_generation": pin["enrollment_generation"],
        "corpus_id": FROZEN_R185["corpus_id"],
        "r185_packet_sha256": FROZEN_R185["r185_packet_sha256"],
        "manifest_sha256": private_commitment["manifest_sha256"],
        "train_sha256": private_commitment["train_sha256"],
        "train_content_sha256": private_commitment["train_content_sha256"],
        "selected_id_v2_sha256": private_commitment["selected_id_v2_sha256"],
        "generator_source_sha256": private_commitment["generator_source_sha256"],
        "dev_generator_schema": GENERATOR_SCHEMA,
        "dev_count": 64,
        "dev_sha256": private_commitment["dev_sha256"],
        "protected_exclusion_count": 128,
        "protected_exclusion_sha256": private_commitment["protected_exclusion_sha256"],
    }
    return {
        "schema": SCHEMA, "status": STATUS,
        "candidate_join_sha256": hashlib.sha256(DOMAIN + _canonical(payload)).hexdigest(),
        **payload,
        "source_pin_host_custody_authenticated": False,
        "owner_identity_authenticated": False,
        "source_use_rights_verified": False,
        "protected_dev_exclusion_custody_verified": False,
        "host_ratification_authenticated": False,
        "gpu_lease_granted": False,
        "authorizes_training": False,
        "authorizes_eval_unseal": False,
    }
