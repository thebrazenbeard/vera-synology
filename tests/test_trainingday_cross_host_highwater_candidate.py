"""Synthetic-only cross-host comparison tests. No independent trust enrollment."""

import hashlib
import hmac
from pathlib import Path
import sqlite3
import tempfile
import unittest

from trainingday_issuer.cross_host_highwater_candidate import (
    DOMAIN, GENESIS, HighwaterHold, PeerHighwaterCandidate, SCHEMA,
    canonical,
)


class CrossHostHighwaterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "lappy-state"
        self.root.mkdir(mode=0o700)
        self.peer_key = b"p" * 32  # test-only; never a host identity
        self.store = PeerHighwaterCandidate(
            self.root, expected_peer="thesimsvault", expected_epoch=7,
            peer_hmac_key=self.peer_key)

    def receipt(self, seq, previous, *, head=None, nonce=None, epoch=7,
                peer="thesimsvault"):
        record = {"schema": SCHEMA, "peer": peer, "epoch": epoch, "seq": seq,
                  "previous_head": previous,
                  "head": head or hashlib.sha256(str(seq).encode()).hexdigest(),
                  "nonce": nonce or ("%032x" % seq)}
        raw = canonical(record)
        mac = hmac.new(self.peer_key, DOMAIN + raw, hashlib.sha256).hexdigest()
        return raw, mac

    def test_two_successive_peer_receipts_are_still_hard_hold(self):
        first_raw, first_mac = self.receipt(1, GENESIS)
        first = self.store.observe(first_raw, first_mac)
        second_raw, second_mac = self.receipt(2, first["head"])
        second = self.store.observe(second_raw, second_mac)
        self.assertEqual(second["seq"], 2)
        for field in ("peer_identity_authenticated", "cross_host_custody_authenticated",
                      "external_rollback_anchor_authenticated", "rights_admitted",
                      "gpu_lease_granted", "physical_training_authorized"):
            self.assertIs(second[field], False)
        self.assertEqual(self.store.health(), second)

    def test_replay_and_stale_host_rollbacks_rejected_if_floor_survives(self):
        raw1, mac1 = self.receipt(1, GENESIS)
        first = self.store.observe(raw1, mac1)
        raw2, mac2 = self.receipt(2, first["head"])
        self.store.observe(raw2, mac2)
        for raw, mac in ((raw1, mac1), (raw2, mac2)):
            with self.assertRaisesRegex(HighwaterHold, "stale"):
                self.store.observe(raw, mac)
        self.assertEqual(self.store.health()["seq"], 2)

    def test_invalid_key_peer_epoch_or_skipped_sequence_rejected(self):
        raw, mac = self.receipt(1, GENESIS)
        with self.assertRaisesRegex(HighwaterHold, "HMAC"):
            self.store.observe(raw, "0" * 64)
        with self.assertRaisesRegex(HighwaterHold, "peer identity or epoch"):
            self.store.observe(*self.receipt(1, GENESIS, peer="untrusted-node"))
        with self.assertRaisesRegex(HighwaterHold, "peer identity or epoch"):
            self.store.observe(*self.receipt(1, GENESIS, epoch=6))
        with self.assertRaisesRegex(HighwaterHold, "stale"):
            self.store.observe(*self.receipt(2, GENESIS))
        self.assertEqual(self.store.health()["seq"], 0)

    def test_divergent_previous_head_and_nonce_reuse_rejected(self):
        raw, mac = self.receipt(1, GENESIS)
        first = self.store.observe(raw, mac)
        with self.assertRaisesRegex(HighwaterHold, "stale"):
            self.store.observe(*self.receipt(2, GENESIS))
        with self.assertRaisesRegex(HighwaterHold, "replayed nonce"):
            self.store.observe(*self.receipt(2, first["head"], nonce="%032x" % 1))
        self.assertEqual(self.store.health()["seq"], 1)

    def test_noncanonical_duplicate_and_boolean_seq_rejected(self):
        raw, mac = self.receipt(1, GENESIS)
        for bad in (raw + b" ", raw.replace(b'"seq":1', b'"seq":true'),
                    raw.replace(b'"seq":1', b'"seq":1,"seq":1')):
            with self.assertRaises(HighwaterHold):
                self.store.observe(bad, mac)
        self.assertEqual(self.store.health()["seq"], 0)

    def test_symlink_and_world_writable_anchor_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(HighwaterHold, "private"):
            self.store.health()
        self.root.chmod(0o700)
        self.assertEqual(self.store.health()["seq"], 0)
        alt = Path(self.temp.name) / "link"
        alt.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(HighwaterHold, "private"):
            PeerHighwaterCandidate(alt, expected_peer="thesimsvault",
                                   expected_epoch=7, peer_hmac_key=self.peer_key)

    def test_whole_state_rollback_is_undetectable_without_real_second_host(self):
        first_raw, first_mac = self.receipt(1, GENESIS)
        first = self.store.observe(first_raw, first_mac)
        snapshot = Path(self.temp.name) / "old.sqlite3"
        with sqlite3.connect(str(self.root / "peer_highwater.sqlite3")) as source:
            with sqlite3.connect(str(snapshot)) as backup:
                source.backup(backup)
        second_raw, second_mac = self.receipt(2, first["head"])
        self.store.observe(second_raw, second_mac)
        self.assertEqual(self.store.health()["seq"], 2)
        # A privileged attacker can replace this *entire* local DB with a
        # formerly valid version. Without a retained peer state it looks valid.
        with sqlite3.connect(str(snapshot)) as source:
            with sqlite3.connect(str(self.root / "peer_highwater.sqlite3")) as target:
                source.backup(target)
        self.assertEqual(self.store.health()["seq"], 1)
        accepted_again = self.store.observe(second_raw, second_mac)
        self.assertEqual(accepted_again["seq"], 2)
        self.assertIs(accepted_again["external_rollback_anchor_authenticated"], False)

    def test_two_host_collusion_or_joint_rollback_has_no_external_proof(self):
        second = Path(self.temp.name) / "nas-state"
        second.mkdir(mode=0o700)
        nas = PeerHighwaterCandidate(second, expected_peer="lappy",
                                     expected_epoch=7, peer_hmac_key=b"n" * 32)
        self.assertEqual((self.store.health()["seq"], nas.health()["seq"]), (0, 0))
        self.assertIs(self.store.health()["cross_host_custody_authenticated"], False)
        self.assertIs(nas.health()["external_rollback_anchor_authenticated"], False)


if __name__ == "__main__":
    unittest.main()
