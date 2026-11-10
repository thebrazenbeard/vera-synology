"""Host-owned RSA-PSS receipt signing on DSM Python 3.8 + OpenSSL 1.1.1.

This is an isolated, offline-provisioned signing primitive, not a rights issuer.
An unsigned or caller-selected public key is not trusted enrollment. Callers
cannot choose the signing key. Receipt signatures are only meaningful after
independent service-key enrollment, host custody, and source-rights checks.
"""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


DOMAIN = b"VERA_TRAININGDAY_NAS_ISSUER_RSA_PSS_SHA256_HOLD_V1\x00"
ALGORITHM = "RSA_PSS_SHA256_MGF1_SHA256_SALT32"
PRIVATE_NAME = "issuer-rsapss-private.pem"
PUBLIC_NAME = "issuer-rsapss-public.pem"
MAX_MESSAGE = 16 * 1024
HEX_SIGNATURE = re.compile(r"[0-9a-f]{768}\Z")
RSA_SIGOPT = ["-sigopt", "rsa_padding_mode:pss",
              "-sigopt", "rsa_pss_saltlen:32",
              "-sigopt", "rsa_mgf1_md:sha256"]
HOLD_RECEIPT_FIELDS = frozenset({
    "schema", "seq", "nonce", "previous_head", "request_sha256",
    "event_kind", "created_unix", "head", "status", "reason",
    "rights_admitted", "gpu_lease_granted", "physical_training_authorized",
    "local_receipt_mac",
})


class IssuerKeyError(ValueError):
    """No signing is permitted without exact protected host key custody."""


def _secure_root(root):
    p = Path(root)
    try:
        st = p.lstat()
    except OSError as exc:
        raise IssuerKeyError("private signer directory absent") from exc
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise IssuerKeyError("private signer directory unsafe")
    return p


def _read_owned(root, name):
    p = root / name
    try:
        fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise IssuerKeyError("issuer signing identity unavailable") from exc
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or not 32 <= st.st_size <= 4096):
            raise IssuerKeyError("issuer signing identity permissions invalid")
        value = os.read(fd, 4097)
        if len(value) != st.st_size:
            raise IssuerKeyError("issuer signing identity changed")
        return value
    finally:
        os.close(fd)


def _invoke(openssl, args, *, timeout=3):
    try:
        result = subprocess.run([openssl] + args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IssuerKeyError("issuer cryptographic operation unavailable") from exc
    if result.returncode != 0:
        raise IssuerKeyError("issuer cryptographic operation failed")
    return result.stdout


def _tmp(root):
    fd, name = tempfile.mkstemp(prefix=".issuer-", dir=str(root))
    os.fchmod(fd, 0o600)
    os.close(fd)
    return Path(name)


def _sync(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def provision_signer(root, *, openssl="/usr/bin/openssl"):
    """One-time private key enrollment from local service administrator only.

    Fails rather than overwriting an existing key. This function MUST NOT be
    exposed as an HTTP endpoint, RPC handler, or client-supplied key selector.
    """
    root = _secure_root(root)
    private = root / PRIVATE_NAME
    public = root / PUBLIC_NAME
    if private.exists() or public.exists() or private.is_symlink() or public.is_symlink():
        raise IssuerKeyError("issuer signing identity already provisioned")
    priv_tmp, pub_tmp = _tmp(root), _tmp(root)
    try:
        _invoke(openssl, ["genpkey", "-algorithm", "RSA", "-pkeyopt",
                          "rsa_keygen_bits:3072", "-out", str(priv_tmp)], timeout=90)
        _invoke(openssl, ["pkey", "-in", str(priv_tmp), "-pubout", "-out", str(pub_tmp)])
        # A key pair is not published unless this installed OpenSSL binary
        # actually performs the complete signing/verification round trip.
        _crypto_self_test(openssl, priv_tmp, pub_tmp, root)
        os.chmod(str(priv_tmp), 0o600)
        os.chmod(str(pub_tmp), 0o600)
        _sync(priv_tmp)
        _sync(pub_tmp)
        # link() is atomic exclusive publication; it cannot replace a key.
        os.link(str(priv_tmp), str(private))
        os.link(str(pub_tmp), str(public))
        _sync(root)
        key = _read_owned(root, PUBLIC_NAME)
        return {"status": "SIGNER_PROVISIONED_NOT_AUTHORITY_ENROLLED_HOLD",
                "issuer_public_pem_sha256": hashlib.sha256(key).hexdigest()}
    except OSError as exc:
        raise IssuerKeyError("issuer signer provisioning failed closed") from exc
    finally:
        for p in (priv_tmp, pub_tmp):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        # A partial key pair is never repaired or overwritten automatically.
        # The operator must inspect it under a separate protected procedure.


class HostOwnedSigner:
    """RSA-PSS private key remains a protected NAS file; never returned."""

    def __init__(self, root, *, openssl="/usr/bin/openssl"):
        self.root = _secure_root(root)
        self.openssl = openssl
        _read_owned(self.root, PRIVATE_NAME)
        self.public_pem = _read_owned(self.root, PUBLIC_NAME)
        self.public_pem_sha256 = hashlib.sha256(self.public_pem).hexdigest()
        # Independently derive the public identity from the private material.
        derived = _invoke(openssl, ["pkey", "-in", str(self.root / PRIVATE_NAME),
                                    "-pubout"])
        if derived != self.public_pem:
            raise IssuerKeyError("issuer public/private key identity mismatch")
        _crypto_self_test(openssl, self.root / PRIVATE_NAME,
                          self.root / PUBLIC_NAME, self.root)

    def sign_hold(self, exact_receipt_bytes):
        if (type(exact_receipt_bytes) is not bytes or not exact_receipt_bytes
                or len(exact_receipt_bytes) > MAX_MESSAGE):
            raise IssuerKeyError("issuer receipt invalid")
        from .nas_witness import RESPONSE_SCHEMA, StateError, _decode_exact, canonical
        try:
            receipt = _decode_exact(exact_receipt_bytes)
        except StateError as exc:
            raise IssuerKeyError("issuer receipt must be canonical JSON") from exc
        if (type(receipt) is not dict or set(receipt) != HOLD_RECEIPT_FIELDS
                or receipt.get("schema") != RESPONSE_SCHEMA
                or receipt.get("status") != "HOLD"
                or any(receipt.get(flag) is not False for flag in (
                    "rights_admitted", "gpu_lease_granted",
                    "physical_training_authorized"))
                or exact_receipt_bytes != canonical(receipt)):
            raise IssuerKeyError("issuer cannot sign an unsupported or granting receipt")
        data = _tmp(self.root)
        signature = _tmp(self.root)
        try:
            with open(str(data), "wb") as file:
                file.write(DOMAIN + exact_receipt_bytes)
                file.flush()
                os.fsync(file.fileno())
            _invoke(self.openssl, ["dgst", "-sha256", "-sign",
                                   str(self.root / PRIVATE_NAME)] + RSA_SIGOPT
                                   + ["-out", str(signature), str(data)])
            result = signature.read_bytes()
            if len(result) != 384:
                raise IssuerKeyError("issuer signature malformed")
            return {"issuer_public_pem_sha256": self.public_pem_sha256,
                    "issuer_signature_algorithm": ALGORITHM,
                    "issuer_rsapss_signature_hex": result.hex()}
        finally:
            for path in (data, signature):
                path.unlink()


def verify_relative_to_pinned_public_key(public_pem_path, exact_receipt_bytes,
                                         signature_hex, *, openssl="/usr/bin/openssl"):
    """Check signature *relative to caller's explicitly PINNED* public key.

    The caller must enroll this exact public key through a trusted route. A
    supplied PEM in an HTTP response can never be treated as a trust root.
    """
    if (type(exact_receipt_bytes) is not bytes or not exact_receipt_bytes
            or len(exact_receipt_bytes) > MAX_MESSAGE
            or type(signature_hex) is not str
            or HEX_SIGNATURE.fullmatch(signature_hex) is None):
        return False
    with tempfile.TemporaryDirectory(prefix="vera-issuer-verify-") as directory:
        content = Path(directory) / "content"
        sig = Path(directory) / "sig"
        with open(str(content), "wb") as file:
            file.write(DOMAIN + exact_receipt_bytes)
        with open(str(sig), "wb") as file:
            file.write(bytes.fromhex(signature_hex))
        try:
            _invoke(openssl, ["dgst", "-sha256", "-verify",
                              str(public_pem_path)] + RSA_SIGOPT
                              + ["-signature", str(sig), str(content)])
        except IssuerKeyError:
            return False
        return True


def _crypto_self_test(openssl, private, public, root):
    """Verify real OpenSSL CLI capability, not only its reported version.

    OpenSSL 1.1.1 can GENERATE Ed25519 keys but its CLI cannot sign them:
    pkeyutl lacks -rawin and dgst explicitly excludes Ed25519. The fixed
    RSA-PSS/SHA-256 primitive works through dgst on 1.1.1 and 3.x.
    """
    data, signature = _tmp(root), _tmp(root)
    try:
        with open(str(data), "wb") as file:
            file.write(DOMAIN + b"startup-key-capability-test")
            file.flush()
            os.fsync(file.fileno())
        _invoke(openssl, ["dgst", "-sha256", "-sign", str(private)]
                         + RSA_SIGOPT + ["-out", str(signature), str(data)],
                timeout=10)
        if len(signature.read_bytes()) != 384:
            raise IssuerKeyError("issuer cryptographic self-test signature malformed")
        _invoke(openssl, ["dgst", "-sha256", "-verify", str(public)]
                         + RSA_SIGOPT + ["-signature", str(signature), str(data)],
                timeout=10)
    finally:
        for path in (data, signature):
            path.unlink()
