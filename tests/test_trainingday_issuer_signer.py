"""Synthetic RSA-PSS issuer-key tests; never a corpus-rights/GPU grant."""

import hashlib
import hmac
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from trainingday_issuer.issuer_signer import (
    ALGORITHM, HostOwnedSigner, IssuerKeyError, PRIVATE_NAME, PUBLIC_NAME,
    provision_signer, verify_relative_to_pinned_public_key,
)
from trainingday_issuer.nas_witness import (REQUEST_DOMAIN, SCHEMA,
                                            StateError, WitnessEngine, canonical, provision)


class HostOwnedSignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private"
        provision(self.root)
        self.claim = provision_signer(self.root)
        self.engine = WitnessEngine(self.root, now=lambda: 1762045200)
        self.signer = HostOwnedSigner(self.root)
        request = {"schema": SCHEMA, "nonce": "a" * 32,
                   "previous_head": "0" * 64, "request_sha256": "b" * 64,
                   "event_kind": "PREFLIGHT", "expires_unix": 1762045260}
        raw = canonical(request)
        mac = hmac.new((self.root / "broker.key").read_bytes(),
                       REQUEST_DOMAIN + raw, hashlib.sha256).hexdigest()
        self.receipt = self.engine.append(raw, mac)

    def test_host_private_key_signs_real_hold_receipt_only(self):
        data = canonical(self.receipt)
        signed = self.signer.sign_hold(data)
        self.assertEqual(len(signed["issuer_rsapss_signature_hex"]), 768)
        self.assertEqual(signed["issuer_signature_algorithm"], ALGORITHM)
        self.assertEqual(signed["issuer_public_pem_sha256"],
                         hashlib.sha256((self.root / PUBLIC_NAME).read_bytes()).hexdigest())
        self.assertTrue(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, data, signed["issuer_rsapss_signature_hex"]))
        self.assertFalse(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, data + b" ", signed["issuer_rsapss_signature_hex"]))
        self.assertNotIn("PRIVATE KEY", str(signed))
        self.assertEqual(self.receipt["status"], "HOLD")
        self.assertFalse(self.receipt["physical_training_authorized"])

    def _next(self, engine):
        request = {"schema": SCHEMA, "nonce": "c" * 32,
                   "previous_head": self.receipt["head"],
                   "request_sha256": "d" * 64, "event_kind": "PREFLIGHT",
                   "expires_unix": 1762045260}
        raw = canonical(request)
        mac = hmac.new((self.root / "broker.key").read_bytes(),
                       REQUEST_DOMAIN + raw, hashlib.sha256).hexdigest()
        return engine.append(raw, mac)

    def test_signed_durable_append_verifies_after_restart(self):
        engine = WitnessEngine(self.root, now=lambda: 1762045201,
                               signer=self.signer)
        receipt = self._next(engine)
        self.assertEqual(receipt["seq"], 2)
        signature = receipt.pop("issuer_rsapss_signature_hex")
        algorithm = receipt.pop("issuer_signature_algorithm")
        fingerprint = receipt.pop("issuer_public_pem_sha256")
        self.assertEqual(algorithm, ALGORITHM)
        self.assertEqual(fingerprint, self.signer.public_pem_sha256)
        self.assertTrue(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, canonical(receipt), signature))
        self.assertEqual(WitnessEngine(self.root).health()["seq"], 2)
        self.assertFalse(receipt["physical_training_authorized"])

    def test_signer_failure_while_locked_does_not_consume_nonce(self):
        engine = WitnessEngine(self.root, now=lambda: 1762045201,
                               signer=self.signer)
        (self.root / PRIVATE_NAME).rename(self.root / "held-private.pem")
        with self.assertRaises(StateError):
            self._next(engine)
        self.assertEqual(self.engine.health()["seq"], 1)

    def test_cannot_sign_positive_or_extra_field_receipt(self):
        for bad in (
            dict(self.receipt, status="ADMIT"),
            dict(self.receipt, rights_admitted=True),
            dict(self.receipt, gpu_lease_granted=True),
            dict(self.receipt, physical_training_authorized=True),
            dict(self.receipt, external_grant=True),
        ):
            with self.subTest(bad=bad), self.assertRaises(IssuerKeyError):
                self.signer.sign_hold(canonical(bad))
        with self.assertRaises(IssuerKeyError):
            self.signer.sign_hold(b"not json")

    def test_wrong_public_key_and_forged_signature_rejected(self):
        other = Path(self.temp.name) / "other"
        provision(other)
        provision_signer(other)
        payload = canonical(self.receipt)
        sig = self.signer.sign_hold(payload)["issuer_rsapss_signature_hex"]
        self.assertFalse(verify_relative_to_pinned_public_key(
            other / PUBLIC_NAME, payload, sig))
        self.assertFalse(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, payload, "0" * 768))
        self.assertFalse(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, payload, "not-a-signature"))

    def test_caller_selected_success_program_cannot_spoof_receipt_verification(self):
        # /bin/true exits zero without cryptographically verifying anything.
        # A forged 384-byte signature must not become "verified" just because
        # an untrusted caller supplied a successful executable path.
        self.assertFalse(verify_relative_to_pinned_public_key(
            self.root / PUBLIC_NAME, canonical(self.receipt), "0" * 768,
            openssl="/bin/true"))

    def test_private_key_ownership_and_provisioning_are_fail_closed(self):
        with self.assertRaises(IssuerKeyError):
            provision_signer(self.root)
        self.assertEqual(stat.S_IMODE((self.root / PRIVATE_NAME).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / PUBLIC_NAME).stat().st_mode), 0o600)
        (self.root / PRIVATE_NAME).chmod(0o644)
        with self.assertRaises(IssuerKeyError):
            HostOwnedSigner(self.root)

    def test_missing_openssl_refuses_key_creation(self):
        other = Path(self.temp.name) / "missing-openssl"
        provision(other)
        with self.assertRaises(IssuerKeyError):
            provision_signer(other, openssl="/missing/openssl")
        self.assertFalse((other / PRIVATE_NAME).exists())
        self.assertFalse((other / PUBLIC_NAME).exists())

    def test_signer_uses_111_compatible_cli_not_ed25519_pkeyutl(self):
        from trainingday_issuer import issuer_signer
        real_run = issuer_signer.subprocess.run
        calls = []

        def observe(argv, **kwargs):
            calls.append(argv)
            self.assertNotIn("-rawin", argv)
            self.assertNotIn("pkeyutl", argv)
            return real_run(argv, **kwargs)

        with patch.object(issuer_signer.subprocess, "run", side_effect=observe):
            signed = self.signer.sign_hold(canonical(self.receipt))
            self.assertTrue(verify_relative_to_pinned_public_key(
                self.root / PUBLIC_NAME, canonical(self.receipt),
                signed["issuer_rsapss_signature_hex"]))
        self.assertEqual(sum("dgst" in argv for argv in calls), 2)

    def test_provisioning_aborts_if_crypto_self_test_fails(self):
        from trainingday_issuer import issuer_signer
        other = Path(self.temp.name) / "self-test-failure"
        provision(other)
        original_invoke = issuer_signer._invoke

        def reject_signing(openssl, argv, **kwargs):
            if argv[0] == "dgst":
                raise IssuerKeyError("crypto self-test unsupported")
            return original_invoke(openssl, argv, **kwargs)

        with patch.object(issuer_signer, "_invoke", side_effect=reject_signing):
            with self.assertRaises(IssuerKeyError):
                provision_signer(other)
        self.assertFalse((other / PRIVATE_NAME).exists())
        self.assertFalse((other / PUBLIC_NAME).exists())


if __name__ == "__main__":
    unittest.main()
