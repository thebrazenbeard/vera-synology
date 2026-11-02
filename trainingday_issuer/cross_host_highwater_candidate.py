"""Source-only peer-held high-water comparison; NEVER a training grant.

The HMAC key, peer identity, epoch and local state root are supplied by the
caller. This can detect a stale *peer* while an independent host retains its
newer state; it cannot authenticate that host or detect rollback of both.
"""

from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat


SCHEMA = "VERA_TRAININGDAY_CROSS_HOST_HWM_CANDIDATE_V1"
DOMAIN = b"VERA_TRAININGDAY_CROSS_HOST_HWM_CANDIDATE_V1\x00"
GENESIS = "0" * 64
MAX_RECEIPT = 2048
MAX_SEQ = (2 ** 63) - 1
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PEER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
FIELDS = frozenset({"schema", "peer", "epoch", "seq", "previous_head",
                    "head", "nonce"})


class HighwaterHold(ValueError):
    """Untrusted, replayed, inconsistent, or unavailable peer evidence."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HighwaterHold("duplicate key")
        result[key] = value
    return result


def _decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECEIPT:
        raise HighwaterHold("receipt length invalid")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_no_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               HighwaterHold("nonfinite value")))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise HighwaterHold("receipt malformed") from exc
    if type(value) is not dict or set(value) != FIELDS or raw != canonical(value):
        raise HighwaterHold("receipt not canonical or fields invalid")
    if (value["schema"] != SCHEMA or type(value["peer"]) is not str
            or PEER.fullmatch(value["peer"]) is None
            or type(value["epoch"]) is not int or not 1 <= value["epoch"] <= MAX_SEQ
            or type(value["seq"]) is not int or not 1 <= value["seq"] <= MAX_SEQ
            or type(value["nonce"]) is not str
            or HEX32.fullmatch(value["nonce"]) is None
            or type(value["previous_head"]) is not str
            or HEX64.fullmatch(value["previous_head"]) is None
            or type(value["head"]) is not str
            or HEX64.fullmatch(value["head"]) is None
            or value["head"] == value["previous_head"]):
        raise HighwaterHold("receipt field value invalid")
    return value


def _private_dir(root):
    try:
        info = root.lstat()
    except OSError as exc:
        raise HighwaterHold("private anchor directory unavailable") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.geteuid()):
        raise HighwaterHold("anchor directory not owned/private")


class PeerHighwaterCandidate:
    """An *individual host's* local comparison floor; not independent authority.

    A second process on a physically separate host must retain its own floor.
    A caller-controlled key or a cloned database makes this non-authoritative.
    """

    def __init__(self, state_root, *, expected_peer, expected_epoch, peer_hmac_key):
        self.root = Path(state_root)
        _private_dir(self.root)
        if (type(expected_peer) is not str or PEER.fullmatch(expected_peer) is None
                or type(expected_epoch) is not int or not 1 <= expected_epoch <= MAX_SEQ
                or type(peer_hmac_key) is not bytes or len(peer_hmac_key) != 32):
            raise HighwaterHold("caller-supplied peer parameters invalid")
        self.expected_peer = expected_peer
        self.expected_epoch = expected_epoch
        self.peer_hmac_key = peer_hmac_key
        self.db_path = self.root / "peer_highwater.sqlite3"
        old_mask = os.umask(0o077)
        try:
            with closing(self._db()) as db:
                db.execute("CREATE TABLE IF NOT EXISTS floor (id INTEGER PRIMARY KEY"
                           " CHECK(id=1), seq INTEGER NOT NULL, head TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY)")
                db.execute("INSERT OR IGNORE INTO floor VALUES (1,0,?)", (GENESIS,))
        except sqlite3.Error as exc:
            raise HighwaterHold("anchor database initialization failed") from exc
        finally:
            os.umask(old_mask)

    def _db(self):
        _private_dir(self.root)
        try:
            if self.db_path.is_symlink():
                raise HighwaterHold("anchor database symlink rejected")
            if self.db_path.exists():
                info = self.db_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077):
                    raise HighwaterHold("anchor database not owned/private")
            db = sqlite3.connect(str(self.db_path), timeout=3, isolation_level=None)
            db.execute("PRAGMA busy_timeout=3000")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            return db
        except sqlite3.Error as exc:
            raise HighwaterHold("anchor database inaccessible") from exc

    def health(self):
        with closing(self._db()) as db:
            row = db.execute("SELECT seq,head FROM floor WHERE id=1").fetchone()
            if row is None:
                raise HighwaterHold("local high-water floor missing")
            seq, head = row
        return self._hold(seq, head)

    @staticmethod
    def _hold(seq, head):
        return {"schema": SCHEMA, "status": "PEER_HWM_STRUCTURAL_HOLD",
                "seq": seq, "head": head,
                "peer_identity_authenticated": False,
                "cross_host_custody_authenticated": False,
                "external_rollback_anchor_authenticated": False,
                "rights_admitted": False, "gpu_lease_granted": False,
                "physical_training_authorized": False}

    def observe(self, raw, mac_hex):
        record = _decode(raw)
        if (record["peer"] != self.expected_peer
                or record["epoch"] != self.expected_epoch):
            raise HighwaterHold("peer identity or epoch mismatch")
        if type(mac_hex) is not str or HEX64.fullmatch(mac_hex) is None:
            raise HighwaterHold("HMAC encoding invalid")
        expected_mac = hmac.new(self.peer_hmac_key, DOMAIN + raw,
                                hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, mac_hex):
            raise HighwaterHold("peer receipt HMAC invalid")
        try:
            with closing(self._db()) as db:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute("SELECT seq,head FROM floor WHERE id=1").fetchone()
                    if row is None:
                        raise HighwaterHold("local high-water floor missing")
                    current_seq, current_head = row
                    if (record["seq"] != current_seq + 1
                            or record["previous_head"] != current_head):
                        raise HighwaterHold("stale, skipped, or divergent high-water")
                    if db.execute("SELECT 1 FROM nonces WHERE nonce=?",
                                  (record["nonce"],)).fetchone():
                        raise HighwaterHold("replayed nonce")
                    db.execute("INSERT INTO nonces(nonce) VALUES (?)", (record["nonce"],))
                    db.execute("UPDATE floor SET seq=?, head=? WHERE id=1",
                               (record["seq"], record["head"]))
                return self._hold(record["seq"], record["head"])
        except sqlite3.Error as exc:
            raise HighwaterHold("local high-water write failed") from exc
