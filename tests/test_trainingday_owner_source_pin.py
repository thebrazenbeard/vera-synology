"""Synthetic root-owner enrollment checks; no live owner keys or source rows."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from trainingday_issuer.owner_source_pin import (
    FROZEN_R185, SCHEMA, SourcePinError, inspect_pin_bytes,
    load_host_owned_pin,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def fixture():
    # A synthetic public key is not proof of Patrick's owner identity.
    public_hex = "12" * 32
    return dict(schema=SCHEMA, generation=1, owner_subject_id="synthetic-owner-1",
                owner_public_key_hex=public_hex,
                owner_key_sha256=hashlib.sha256(bytes.fromhex(public_hex)).hexdigest(),
                revoked_owner_key_sha256=[], **FROZEN_R185)


class OwnerSourcePinTests(unittest.TestCase):
    def test_valid_synthetic_pin_reports_only_integrity_and_holds(self):
        raw = canonical(fixture())
        status = inspect_pin_bytes(raw)
        self.assertEqual(status["source_pin_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(status["train_content_sha256"],
                         "3ef5d72682da4702235f05649f11582af49d73f551bb27a01715acab46099178")
        for field in ("owner_identity_authenticated", "owner_source_use_rights_verified",
                      "protected_dev_exclusion_custody_verified",
                      "gpu_lease_granted", "authorizes_training"):
            self.assertIs(status[field], False)

    def test_frozen_r185_content_and_packet_are_independently_pinned(self):
        for field in ("corpus_id", "r185_packet_sha256", "manifest_sha256",
                      "train_content_sha256", "selected_id_v2_sha256"):
            pin = fixture()
            pin[field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(SourcePinError):
                inspect_pin_bytes(canonical(pin))

    def test_forged_or_revoked_owner_public_key_rejected(self):
        pin = fixture()
        pin["owner_public_key_hex"] = "34" * 32
        with self.assertRaises(SourcePinError):
            inspect_pin_bytes(canonical(pin))
        pin = fixture()
        pin["revoked_owner_key_sha256"] = [pin["owner_key_sha256"]]
        with self.assertRaises(SourcePinError):
            inspect_pin_bytes(canonical(pin))

    def test_coforged_key_and_fingerprint_remain_non_grant(self):
        # A caller can choose a different internally consistent key pair;
        # only protected host installation/authenticated owner proves origin.
        pin = fixture()
        pin["owner_public_key_hex"] = "34" * 32
        pin["owner_key_sha256"] = hashlib.sha256(bytes.fromhex(
            pin["owner_public_key_hex"])).hexdigest()
        status = inspect_pin_bytes(canonical(pin))
        self.assertIs(status["owner_identity_authenticated"], False)
        self.assertIs(status["owner_source_use_rights_verified"], False)
        self.assertIs(status["authorizes_training"], False)

    def test_ambiguous_or_malformed_enrollment_rejected(self):
        for changed in (
            lambda p: p.update(generation=True),
            lambda p: p.update(generation=0),
            lambda p: p.update(extra="ADMIT"),
            lambda p: p.update(owner_subject_id="x"),
            lambda p: p.update(revoked_owner_key_sha256=["a" * 64, "a" * 64]),
            lambda p: p.update(owner_public_key_hex="F" * 64),
        ):
            pin = fixture()
            changed(pin)
            with self.subTest(change=changed), self.assertRaises(SourcePinError):
                inspect_pin_bytes(canonical(pin))
        raw = canonical(fixture())
        with self.assertRaises(SourcePinError):
            inspect_pin_bytes(raw.replace(b'"generation":1',
                                          b'"generation":1,"generation":1'))
        with self.assertRaises(SourcePinError):
            inspect_pin_bytes(json.dumps(fixture(), indent=2).encode("utf-8"))

    def test_host_loader_rejects_unprotected_parent_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "pin.json"
            path.write_bytes(canonical(fixture()))
            # /tmp is shared and not a root-owned protected ancestor.
            with self.assertRaises(SourcePinError):
                load_host_owned_pin(path)
            link = Path(root) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(SourcePinError):
                load_host_owned_pin(link)

if __name__ == "__main__":
    unittest.main()
