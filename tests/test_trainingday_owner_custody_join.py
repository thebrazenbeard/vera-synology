"""Synthetic cross-binding only; no authentic owner, evaluator or training grant."""

import hashlib
import json
import unittest

from trainingday_issuer.owner_source_pin import FROZEN_R185, SCHEMA as OWNER_SCHEMA
from trainingday_issuer.private_dev_candidate import (
    GENERATOR_SCHEMA, SCHEMA as DEV_SCHEMA, STATUS as DEV_STATUS,
)
from trainingday_issuer.owner_custody_join import (
    CustodyJoinError, join_owner_and_private_custody,
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def owner_pin(public_key=b"K" * 32):
    return _canonical({
        "schema": OWNER_SCHEMA, "generation": 1,
        "owner_subject_id": "patrick-r185-owner",
        "owner_public_key_hex": public_key.hex(),
        "owner_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "revoked_owner_key_sha256": [],
        **FROZEN_R185,
    })


def private_record():
    return {
        "schema": DEV_SCHEMA, "status": DEV_STATUS,
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
    }


class OwnerCustodyJoinTests(unittest.TestCase):
    def test_frozen_cross_binding_yields_only_hold(self):
        result = join_owner_and_private_custody(owner_pin(), private_record())
        self.assertEqual(result["status"], "CONSISTENT_UNAUTHENTICATED_HOLD")
        self.assertEqual(result["manifest_sha256"], FROZEN_R185["manifest_sha256"])
        self.assertEqual(result["dev_count"], 64)
        self.assertEqual(result["protected_exclusion_count"], 128)
        self.assertFalse(result["owner_identity_authenticated"])
        self.assertFalse(result["source_use_rights_verified"])
        self.assertFalse(result["protected_dev_exclusion_custody_verified"])
        self.assertFalse(result["gpu_lease_granted"])
        self.assertFalse(result["authorizes_training"])
        self.assertFalse(result["authorizes_eval_unseal"])
        self.assertNotIn("owner_public_key_hex", result)
        self.assertNotIn("dev_nonce", result)
        self.assertEqual(result, join_owner_and_private_custody(owner_pin(), private_record()))

    def test_changed_train_digest_rejected(self):
        candidate = private_record()
        candidate["train_content_sha256"] = "f" * 64
        with self.assertRaises(CustodyJoinError):
            join_owner_and_private_custody(owner_pin(), candidate)

    def test_changed_selected_id_rejected(self):
        candidate = private_record()
        candidate["selected_id_v2_sha256"] = "f" * 64
        with self.assertRaises(CustodyJoinError):
            join_owner_and_private_custody(owner_pin(), candidate)

    def test_positive_authority_claim_rejected(self):
        for field in ("owner_identity_authenticated", "source_use_rights_verified",
                      "host_ratification_authenticated", "authorizes_training",
                      "authorizes_eval_unseal", "independent_custody_authenticated"):
            candidate = private_record()
            candidate[field] = True
            with self.subTest(field=field), self.assertRaises(CustodyJoinError):
                join_owner_and_private_custody(owner_pin(), candidate)

    def test_unknown_fields_or_bad_status_rejected(self):
        candidate = private_record()
        candidate["dev_nonce"] = "secret"
        with self.assertRaises(CustodyJoinError):
            join_owner_and_private_custody(owner_pin(), candidate)
        candidate = private_record()
        candidate["status"] = "ADMITTED"
        with self.assertRaises(CustodyJoinError):
            join_owner_and_private_custody(owner_pin(), candidate)

    def test_exclusion_change_changes_commitment_not_authority(self):
        original = join_owner_and_private_custody(owner_pin(), private_record())
        alternate = private_record()
        alternate["protected_exclusion_sha256"] = "e" * 64
        changed = join_owner_and_private_custody(owner_pin(), alternate)
        self.assertNotEqual(original["candidate_join_sha256"],
                            changed["candidate_join_sha256"])
        self.assertFalse(changed["authorizes_training"])

    def test_coforged_owner_key_cannot_gain_authority(self):
        first = join_owner_and_private_custody(owner_pin(b"K" * 32), private_record())
        second = join_owner_and_private_custody(owner_pin(b"L" * 32), private_record())
        self.assertNotEqual(first["candidate_join_sha256"], second["candidate_join_sha256"])
        self.assertFalse(first["owner_identity_authenticated"])
        self.assertFalse(second["owner_identity_authenticated"])


if __name__ == "__main__":
    unittest.main()
