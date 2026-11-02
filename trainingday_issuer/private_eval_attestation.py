"""Offline verification of a separately signed private DEV commitment: HOLD only.

The evaluator's private key and raw protected cases must remain outside the
NAS witness service. Its administrator may independently enroll a public key,
canonical aggregate commitment and detached RSA-PSS signature into root-owned,
service-readable files. This reader checks *that enrollment's integrity* but
cannot itself prove the evaluator's identity or original source provenance.

No HTTP route, key provisioner, grant, private answer or DEV nonce exists here.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .owner_custody_join import CustodyJoinError, join_owner_and_private_custody
from .owner_source_pin import SourcePinError, inspect_pin_bytes


SCHEMA = "VERA_R18_PRIVATE_EVALUATOR_ATTESTATION_CANDIDATE_V1"
STATUS = "SIGNED_ENROLLED_COMMITMENT_UNQUALIFIED_HOLD"
DOMAIN = (SCHEMA + "\x00").encode("ascii")
RSA_SIGOPT = ["-sigopt", "rsa_padding_mode:pss", "-sigopt",
              "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"]
MAX_SOURCE_PIN = 8192
MAX_COMMITMENT = 8192
MAX_PUBLIC_KEY = 4096
SIGNATURE_BYTES = 384
PINNED_OPENSSL = "/usr/bin/openssl"


class EvaluatorAttestationError(ValueError):
    """A claimed private evaluator attestation failed to verify."""


def _reject(condition):
    if not condition:
        raise EvaluatorAttestationError("private evaluator attestation rejected")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        _reject(key not in obj)
        obj[key] = value
    return obj


def _load_host_enrolled_file(path, *, max_bytes, exact_size=None):
    """Read only a root-owned file under fully root-owned, unwritable ancestry.

    Service configuration must fix every path before startup; user-supplied
    HTTP paths and mutable service-owned mount points are not trusted here.
    """
    _reject(isinstance(path, (str, Path)))
    target = Path(path)
    _reject(target.is_absolute())
    for parent in target.parents:
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise EvaluatorAttestationError("enrolled evaluator path inaccessible") from exc
        _reject(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022)
    descriptor = None
    try:
        descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        _reject(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022 and metadata.st_nlink == 1
                and 0 < metadata.st_size <= max_bytes)
        if exact_size is not None:
            _reject(metadata.st_size == exact_size)
        result = os.read(descriptor, max_bytes + 1)
        _reject(len(result) == metadata.st_size)
        return result
    except OSError as exc:
        raise EvaluatorAttestationError("enrolled evaluator file inaccessible") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_pinned_openssl(openssl):
    """Never delegate cryptographic truth to a caller-selected executable.

    NAS root must protect the installed system OpenSSL binary and directories.
    This is host OS trust, not a verified binary supply-chain attestation.
    """
    _reject(type(openssl) is str and openssl == PINNED_OPENSSL)
    candidate = Path(PINNED_OPENSSL)
    for parent in candidate.parents:
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise EvaluatorAttestationError("system cryptography unavailable") from exc
        _reject(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise EvaluatorAttestationError("system cryptography unavailable") from exc
    _reject(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
            and not metadata.st_mode & 0o022
            and bool(metadata.st_mode & 0o111))


def verify_relative_to_evaluator_public_key(owner_pin_bytes,
                                            private_commitment_bytes,
                                            signature_bytes,
                                            evaluator_public_pem,
                                            *, openssl="/usr/bin/openssl"):
    """Verify exact-byte signature against a separately supplied trust anchor.

    A caller-supplied public key is NOT host enrollment. The result explicitly
    says that cryptographic signature validity is only relative to those
    caller-supplied bytes and gives no rights, eval unseal or training grant.
    """
    _require_pinned_openssl(openssl)
    _reject(type(owner_pin_bytes) is bytes
            and 0 < len(owner_pin_bytes) <= MAX_SOURCE_PIN)
    _reject(type(private_commitment_bytes) is bytes
            and 0 < len(private_commitment_bytes) <= MAX_COMMITMENT)
    _reject(type(signature_bytes) is bytes
            and len(signature_bytes) == SIGNATURE_BYTES)
    _reject(type(evaluator_public_pem) is bytes
            and 100 <= len(evaluator_public_pem) <= MAX_PUBLIC_KEY
            and evaluator_public_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
            and evaluator_public_pem.endswith(b"-----END PUBLIC KEY-----\n"))
    try:
        private_commitment = json.loads(
            private_commitment_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _: _reject(False),
        )
        _reject(private_commitment_bytes == _canonical(private_commitment))
        inspect_pin_bytes(owner_pin_bytes)
        join = join_owner_and_private_custody(owner_pin_bytes, private_commitment)
    except (UnicodeError, ValueError, TypeError, RecursionError,
            SourcePinError, CustodyJoinError) as exc:
        raise EvaluatorAttestationError("private evaluator attestation rejected") from exc
    # Temporary verification material is aggregate-only, never private DEV
    # prompts, answers, or nonce. The signer owns its independent private key.
    with tempfile.TemporaryDirectory(prefix="vera-private-eval-verify-") as root:
        root = Path(root)
        content = root / "content"
        signature = root / "signature"
        public = root / "public.pem"
        content.write_bytes(DOMAIN + private_commitment_bytes)
        signature.write_bytes(signature_bytes)
        public.write_bytes(evaluator_public_pem)
        try:
            result = subprocess.run(
                [openssl, "dgst", "-sha256", "-verify", str(public)]
                + RSA_SIGOPT + ["-signature", str(signature), str(content)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvaluatorAttestationError("private evaluator cryptography unavailable") from exc
        _reject(result.returncode == 0 and result.stdout.strip() == b"Verified OK")
    return {
        "schema": SCHEMA, "status": STATUS,
        "candidate_join_sha256": join["candidate_join_sha256"],
        "owner_source_pin_sha256": join["owner_source_pin_sha256"],
        "private_commitment_sha256": hashlib.sha256(private_commitment_bytes).hexdigest(),
        "evaluator_public_pem_sha256": hashlib.sha256(evaluator_public_pem).hexdigest(),
        "evaluator_signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "evaluator_signature_valid_relative_to_supplied_key": True,
        "independent_evaluator_identity_authenticated": False,
        "root_owned_artifact_integrity_checked": False,
        "independent_key_enrollment_authenticated": False,
        "protected_dev_exclusion_custody_verified": False,
        "source_use_rights_verified": False,
        "gpu_lease_granted": False,
        "authorizes_training": False,
        "authorizes_eval_unseal": False,
    }


def load_host_enrolled_evaluator_attestation(*, owner_pin_path,
                                             private_commitment_path,
                                             signature_path, public_pem_path,
                                             openssl="/usr/bin/openssl"):
    """Read four fixed root-owned artifacts, verify, remain in HARD HOLD.

    Root ownership certifies only installation-file protection, not that a
    separate evaluator held genuine R16/R18 data or reviewed source rights.
    """
    owner_pin = _load_host_enrolled_file(owner_pin_path, max_bytes=MAX_SOURCE_PIN)
    commitment = _load_host_enrolled_file(private_commitment_path,
                                          max_bytes=MAX_COMMITMENT)
    signature = _load_host_enrolled_file(signature_path,
                                         max_bytes=SIGNATURE_BYTES,
                                         exact_size=SIGNATURE_BYTES)
    public = _load_host_enrolled_file(public_pem_path, max_bytes=MAX_PUBLIC_KEY)
    result = verify_relative_to_evaluator_public_key(
        owner_pin, commitment, signature, public, openssl=openssl)
    result["root_owned_artifact_integrity_checked"] = True
    return result
