"""Only synthetic private/evaluator inputs; never use physical DEV/keys."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from trainingday_issuer.owner_source_pin import FROZEN_R185, SCHEMA as OWNER_SCHEMA
from trainingday_issuer.private_dev_candidate import (
    GENERATOR_SCHEMA, SCHEMA as PRIVATE_SCHEMA, STATUS as PRIVATE_STATUS,
)
from trainingday_issuer.private_eval_attestation import (
    DOMAIN, RSA_SIGOPT, EvaluatorAttestationError,
    load_host_enrolled_evaluator_attestation,
    verify_relative_to_evaluator_public_key,
)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def owner_pin():
    key = b"K" * 32
    return canonical({
        "schema": OWNER_SCHEMA, "generation": 1,
        "owner_subject_id": "patrick-r185-owner",
        "owner_public_key_hex": key.hex(),
        "owner_key_sha256": hashlib.sha256(key).hexdigest(),
        "revoked_owner_key_sha256": [], **FROZEN_R185,
    })


def private_commitment():
    return canonical({
        "schema": PRIVATE_SCHEMA, "status": PRIVATE_STATUS,
        "corpus_id": "R18_ARITHMETIC",
        "manifest_sha256": FROZEN_R185["manifest_sha256"],
        "train_sha256": "a" * 64,
        "train_content_sha256": FROZEN_R185["train_content_sha256"],
        "selected_id_v2_sha256": FROZEN_R185["selected_id_v2_sha256"],
        "generator_source_sha256": "b" * 64,
        "dev_generator_schema": GENERATOR_SCHEMA,
        "dev_count": 64, "dev_sha256": "c" * 64,
        "protected_exclusion_count": 128,
        "protected_exclusion_sha256": "d" * 64,
        "private_content_returned": False,
        "independent_custody_authenticated": False,
        "owner_identity_authenticated": False,
        "source_use_rights_verified": False,
        "host_ratification_authenticated": False,
        "authorizes_training": False,
        "authorizes_eval_unseal": False,
    })


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL command is required")
class PrivateEvaluatorAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vera-eval-key-fixture-")
        cls.private = Path(cls.tmp.name) / "private.pem"
        cls.public = Path(cls.tmp.name) / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:3072", "-out", str(cls.private)],
                       capture_output=True, check=True, timeout=30)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private),
                        "-pubout", "-out", str(cls.public)],
                       capture_output=True, check=True, timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.pin = owner_pin()
        self.summary = private_commitment()
        self.public_key = self.public.read_bytes()
        with tempfile.TemporaryDirectory(prefix="vera-eval-sign-fixture-") as directory:
            message = Path(directory) / "message"
            sig_path = Path(directory) / "sig"
            message.write_bytes(DOMAIN + self.summary)
            subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                            str(self.private)] + RSA_SIGOPT
                           + ["-out", str(sig_path), str(message)],
                           capture_output=True, check=True, timeout=10)
            self.sig = sig_path.read_bytes()
        self.assertEqual(len(self.sig), 384)

    def verify(self, pin=None, summary=None, sig=None, key=None):
        return verify_relative_to_evaluator_public_key(
            self.pin if pin is None else pin,
            self.summary if summary is None else summary,
            self.sig if sig is None else sig,
            self.public_key if key is None else key,
            openssl=shutil.which("openssl"),
        )

    def test_genuine_rsapss_signature_checks_without_any_training_authority(self):
        result = self.verify()
        self.assertEqual(result["status"], "SIGNED_ENROLLED_COMMITMENT_UNQUALIFIED_HOLD")
        self.assertEqual(len(result["candidate_join_sha256"]), 64)
        self.assertEqual(result["evaluator_public_pem_sha256"],
                         hashlib.sha256(self.public_key).hexdigest())
        self.assertTrue(result["evaluator_signature_valid_relative_to_supplied_key"])
        for field in ("independent_evaluator_identity_authenticated",
                      "root_owned_artifact_integrity_checked",
                      "independent_key_enrollment_authenticated",
                      "source_use_rights_verified",
                      "protected_dev_exclusion_custody_verified", "gpu_lease_granted",
                      "authorizes_training", "authorizes_eval_unseal"):
            self.assertIs(result[field], False)
        self.assertNotIn("answer", json.dumps(result))
        self.assertNotIn("nonce", json.dumps(result))

    def test_tamper_any_signed_summary_bit_rejected(self):
        altered = json.loads(self.summary)
        altered["dev_sha256"] = "e" * 64
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(summary=canonical(altered))

    def test_forged_signature_rejected(self):
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(sig=b"\x00" * 384)

    def test_successful_untrusted_command_cannot_replace_openssl(self):
        # A naive verifier that trusts returncode==0 accepts /bin/true
        # without evaluating any cryptographic signature whatsoever.
        with self.assertRaises(EvaluatorAttestationError):
            verify_relative_to_evaluator_public_key(
                self.pin, self.summary, b"\x00" * 384,
                b"-----BEGIN PUBLIC KEY-----\n" + b"A" * 250
                + b"\n-----END PUBLIC KEY-----\n",
                openssl="/bin/true",
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(key=b"-----BEGIN PUBLIC KEY-----\n" + b"A" * 250
                        + b"\n-----END PUBLIC KEY-----\n")

    def test_changed_owner_pin_does_not_gain_authority(self):
        modified = json.loads(self.pin)
        modified["owner_subject_id"] = "other-r185-owner"
        altered = self.verify(pin=canonical(modified))
        self.assertNotEqual(self.verify()["candidate_join_sha256"],
                            altered["candidate_join_sha256"])
        self.assertIs(altered["authorizes_training"], False)

    def test_canonical_and_positive_grant_rejection(self):
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(summary=b" " + self.summary)
        mutated = json.loads(self.summary)
        mutated["authorizes_training"] = True
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(summary=canonical(mutated))
        dup = self.summary[:-1] + b',"status":"HOLD"}'
        with self.assertRaises(EvaluatorAttestationError):
            self.verify(summary=dup)

    def test_forged_key_and_signature_can_pass_only_untrusted_relative_verifier(self):
        # An adversary can generate its own matching pair. This is why a
        # relative signature result cannot assert an independent identity.
        result = self.verify()
        self.assertTrue(result["evaluator_signature_valid_relative_to_supplied_key"])
        self.assertFalse(result["independent_evaluator_identity_authenticated"])
        self.assertFalse(result["root_owned_artifact_integrity_checked"])
        self.assertFalse(result["independent_key_enrollment_authenticated"])

    def test_untrusted_directory_enrollment_rejected(self):
        with tempfile.TemporaryDirectory(prefix="vera-untrusted-enrollment-") as temp:
            root = Path(temp)
            paths = [root / name for name in ("owner", "commitment", "sig", "pub")]
            for path, body in zip(paths, [self.pin, self.summary, self.sig, self.public_key]):
                path.write_bytes(body)
            with self.assertRaises(EvaluatorAttestationError):
                load_host_enrolled_evaluator_attestation(
                    owner_pin_path=paths[0], private_commitment_path=paths[1],
                    signature_path=paths[2], public_pem_path=paths[3],
                    openssl=shutil.which("openssl"))

    @unittest.skipUnless(os.geteuid() == 0, "root-only enrollment test")
    def test_root_enrollment_can_be_verified_but_not_promoted_to_authority(self):
        # Mount/workspace ancestor may be world-writable; avoid asserting a
        # positive result when no protected root-owned test directory exists.
        base = Path.cwd()
        if any(parent.stat().st_mode & 0o022 for parent in (base,) + tuple(base.parents)):
            self.skipTest("working directory ancestors not protected")
        with tempfile.TemporaryDirectory(prefix="vera-root-enroll-", dir=str(base)) as temp:
            root = Path(temp)
            os.chmod(str(root), 0o700)
            paths = [root / name for name in ("owner", "commitment", "sig", "pub")]
            for path, body in zip(paths, [self.pin, self.summary, self.sig, self.public_key]):
                path.write_bytes(body)
                os.chmod(str(path), 0o644)
            result = load_host_enrolled_evaluator_attestation(
                owner_pin_path=paths[0], private_commitment_path=paths[1],
                signature_path=paths[2], public_pem_path=paths[3],
                openssl=shutil.which("openssl"))
            self.assertTrue(result["root_owned_artifact_integrity_checked"])
            self.assertFalse(result["independent_key_enrollment_authenticated"])
            self.assertFalse(result["independent_evaluator_identity_authenticated"])
            self.assertFalse(result["authorizes_eval_unseal"])
            self.assertFalse(result["authorizes_training"])
            # Replace the signature with a same-UID symlink to another file:
            # O_NOFOLLOW must deny the substitution even for valid bytes.
            paths[2].unlink()
            paths[2].symlink_to(paths[0])
            with self.assertRaises(EvaluatorAttestationError):
                load_host_enrolled_evaluator_attestation(
                    owner_pin_path=paths[0], private_commitment_path=paths[1],
                    signature_path=paths[2], public_pem_path=paths[3],
                    openssl=shutil.which("openssl"))


if __name__ == "__main__":
    unittest.main()
