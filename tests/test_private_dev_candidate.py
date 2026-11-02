"""Synthetic-only private DEV/exclusion commitment checks; no real gold."""

import copy
import hashlib
import json
import unittest

from trainingday_issuer.private_dev_candidate import (
    CandidateError, build_private_dev_candidate, _generate_private_dev_jsonl,
)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def hash_prompt(value):
    return hashlib.sha256(" ".join(value.split()).casefold().encode("utf-8")).hexdigest()


class PrivateDevCandidateTests(unittest.TestCase):
    def setUp(self):
        self.nonce = bytes(range(32))
        self.train = [{"id": "train-{:04d}".format(i),
                       "prompt_sha256": hash_prompt("Start with {}. add 1.".format(i)),
                       "answer_sha256": hashlib.sha256(str(i + 1).encode()).hexdigest()}
                      for i in range(1024)]
        selected = hashlib.sha256(
            b"VERA_TRAININGDAY_SELECTED_ID_DIGEST_V2\x00"
            + json.dumps([r["id"] for r in self.train],
                         ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        self.subject = {
            "corpus_id": "R18_ARITHMETIC",
            "manifest_sha256": "a" * 64,
            "train_sha256": "b" * 64,
            "train_content_sha256": hashlib.sha256(canonical(self.train)).hexdigest(),
            "selected_id_v2_sha256": selected,
            "generator_source_sha256": "c" * 64,
        }
        self.r16 = [{"id": "r16-{}".format(i), "prompt": "R16 private {}?".format(i)}
                    for i in range(64)]
        self.r18 = [{"id": "ood-{}".format(i), "prompt": "R18 private {}?".format(i)}
                    for i in range(64)]

    def make(self, **overrides):
        args = {"subject": self.subject, "train_index": self.train,
                "r16_protected": self.r16, "r18_external_ood": self.r18,
                "dev_nonce": self.nonce}
        args.update(overrides)
        return build_private_dev_candidate(**args)

    def test_deterministic_hashes_and_non_grant(self):
        one, two = self.make(), self.make()
        self.assertEqual(one, two)
        self.assertEqual(one["dev_count"], 64)
        self.assertEqual(one["protected_exclusion_count"], 128)
        self.assertEqual(one["status"], "PRIVATE_CANDIDATE_UNAUTHENTICATED_HOLD")
        self.assertEqual(one["train_content_sha256"], self.subject["train_content_sha256"])
        for flag in ("independent_custody_authenticated", "owner_identity_authenticated",
                     "source_use_rights_verified", "host_ratification_authenticated",
                     "authorizes_training", "authorizes_eval_unseal"):
            self.assertIs(one[flag], False)
        encoded = json.dumps(one)
        for secret in ("R16 private", "R18 private", "Start with", "dev-", "r16-",
                       "ood-", '"prompt"', '"answer"', self.nonce.hex()):
            self.assertNotIn(secret, encoded)

    def test_private_dev_changes_with_nonce_but_never_returns_rows(self):
        original = self.make()
        alternate = self.make(dev_nonce=bytes(range(1, 33)))
        self.assertNotEqual(original["dev_sha256"], alternate["dev_sha256"])
        self.assertEqual(original["protected_exclusion_sha256"],
                         alternate["protected_exclusion_sha256"])
        private_bytes = _generate_private_dev_jsonl(self.nonce)
        self.assertEqual(hashlib.sha256(private_bytes).hexdigest(),
                         original["dev_sha256"])
        self.assertEqual(len(private_bytes.strip().split(b"\n")), 64)

    def test_reject_protected_train_prompt_overlap(self):
        r16 = copy.deepcopy(self.r16)
        r16[0]["prompt"] = "Start with 3. add 1."
        with self.assertRaises(CandidateError):
            self.make(r16_protected=r16)

    def test_reject_private_dev_train_and_ood_overlap(self):
        dev = json.loads(_generate_private_dev_jsonl(self.nonce).split(b"\n")[0])
        train = copy.deepcopy(self.train)
        train[0]["prompt_sha256"] = hash_prompt(dev["prompt"])
        subject = dict(self.subject)
        subject["train_content_sha256"] = hashlib.sha256(canonical(train)).hexdigest()
        with self.assertRaises(CandidateError):
            self.make(train_index=train, subject=subject)
        r18 = copy.deepcopy(self.r18)
        r18[0]["prompt"] = dev["prompt"]
        with self.assertRaises(CandidateError):
            self.make(r18_external_ood=r18)

    def test_reject_malformed_provenance_and_forged_content(self):
        for field in ("answer_sha256", "prompt_sha256"):
            train = copy.deepcopy(self.train)
            train[0][field] = "f" * 64
            with self.assertRaises(CandidateError):
                self.make(train_index=train)
        subject = dict(self.subject)
        subject["train_content_sha256"] = "0" * 64
        with self.assertRaises(CandidateError):
            self.make(subject=subject)
        with self.assertRaises(CandidateError):
            self.make(dev_nonce=b"weak")
        with self.assertRaises(CandidateError):
            self.make(r16_protected=self.r16[:-1])
        bad = copy.deepcopy(self.r18)
        bad[0]["answer"] = "private gold must not be supplied"
        with self.assertRaises(CandidateError):
            self.make(r18_external_ood=bad)
        with self.assertRaises(CandidateError):
            self.make(r18_external_ood=self.r16)

    def test_order_changes_exclusion_commitment(self):
        original = self.make()
        other = self.make(r16_protected=list(reversed(self.r16)))
        self.assertNotEqual(original["protected_exclusion_sha256"],
                            other["protected_exclusion_sha256"])


if __name__ == "__main__":
    unittest.main()
