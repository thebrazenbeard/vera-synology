"""Python 3.8-compatible loopback NAS witness: authenticated CAS, always HOLD.

The host-owned Windows broker does not yet possess a qualified GPU lease or
source-use grant.  Neither an administrator password nor a signed-looking
caller request may turn this source-only service into training authorization.
"""

import argparse
from contextlib import closing
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

from .issuer_signer import HostOwnedSigner, IssuerKeyError, provision_signer


SCHEMA = "VERA_TRAININGDAY_NAS_WITNESS_REQUEST_V1"
RESPONSE_SCHEMA = "VERA_TRAININGDAY_NAS_WITNESS_HOLD_V1"
REQUEST_DOMAIN = b"VERA_TRAININGDAY_NAS_BROKER_V1\x00"
LEDGER_DOMAIN = b"VERA_TRAININGDAY_NAS_LEDGER_V1\x00"
RECEIPT_DOMAIN = b"VERA_TRAININGDAY_NAS_LOCAL_RECEIPT_V1\x00"
GENESIS = "0" * 64
MAX_BODY = 8192
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_FIELDS = frozenset({"schema", "nonce", "previous_head",
                            "request_sha256", "expires_unix", "event_kind"})
HOLD_FLAGS = {"rights_admitted": False, "gpu_lease_granted": False,
              "physical_training_authorized": False}
MAX_HTTP_CLIENTS = 16
CLIENT_TIMEOUT_SECONDS = 3


class StateError(ValueError):
    """The host state or request is invalid; do not grant an effect."""


class BrokerAuthError(StateError):
    """Caller did not authenticate to the independently provisioned key."""


class LedgerConflict(StateError):
    """Stale compare-and-append or previously consumed nonce."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _object_no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError("duplicate JSON object key")
        result[key] = value
    return result


def _decode_exact(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_BODY:
        raise StateError("noncanonical or oversized witness request")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_object_no_duplicate_keys,
                           parse_constant=lambda _: (_ for _ in ()).throw(StateError("constant")))
        if raw != canonical(value):
            raise StateError("witness request must be canonical JSON")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise StateError("witness request rejected") from exc


def _is_secure_owner_dir(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise StateError("witness state directory absent") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.geteuid()):
        raise StateError("witness state directory not host-owned and private")


def _secret(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid != os.geteuid() or info.st_size != 32):
                raise StateError("host-owned witness secret insecure")
            value = os.read(descriptor, 33)
            if len(value) != 32:
                raise StateError("host-owned witness secret invalid")
            return value
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise StateError("host-owned witness secret unavailable") from exc


def _secure_create(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                 0o600)
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, data) != len(data):
            raise StateError("short secret write")
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def provision(state_root):
    """One-time *local* admin provisioning. Never display secret bytes."""
    root = Path(state_root)
    try:
        root.mkdir(mode=0o700)
        os.chmod(str(root), 0o700)
        _is_secure_owner_dir(root)
        _secure_create(root / "broker.key", secrets.token_bytes(32))
        _secure_create(root / "issuer.key", secrets.token_bytes(32))
        _fsync_dir(root)
    except OSError as exc:
        raise StateError("one-time secure witness provisioning failed") from exc
    # A generated broker key is NOT proof of an enrolled Windows service.
    # Distribution needs a separately verified administrator ceremony.
    return {"state_root": str(root), "status": "PROVISIONED_NOT_ENROLLED_HOLD"}


class WitnessEngine:
    """Durable *local* append witness; no rights or GPU lease adjudicator."""

    def __init__(self, state_root, now=None, signer=None):
        self.root = Path(state_root)
        _is_secure_owner_dir(self.root)
        self._broker_key = _secret(self.root / "broker.key")
        self._issuer_key = _secret(self.root / "issuer.key")
        self._now = now or time.time
        if signer is not None and type(signer) is not HostOwnedSigner:
            raise StateError("untrusted issuer signer")
        self._signer = signer
        self.db_path = self.root / "witness.sqlite3"
        self._initialize_db()
        self._verify_chain()

    def _connect(self):
        try:
            if self.db_path.exists():
                info = self.db_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077):
                    raise StateError("witness database not host-owned and private")
            db = sqlite3.connect(str(self.db_path), timeout=3, isolation_level=None)
            db.execute("PRAGMA busy_timeout=3000")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            return db
        except sqlite3.Error as exc:
            raise StateError("witness durable state unavailable") from exc

    def _initialize_db(self):
        old_umask = os.umask(0o077)
        try:
            with closing(self._connect()) as db:
                db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1),"
                           " seq INTEGER NOT NULL, head TEXT NOT NULL, last_time INTEGER NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS events ("
                           "seq INTEGER PRIMARY KEY, nonce TEXT NOT NULL UNIQUE,"
                           "previous_head TEXT NOT NULL, head TEXT NOT NULL,"
                           "request_sha256 TEXT NOT NULL, event_kind TEXT NOT NULL,"
                           "created_unix INTEGER NOT NULL)")
                db.execute("INSERT OR IGNORE INTO state (id,seq,head,last_time)"
                           " VALUES (1,0,?,0)", (GENESIS,))
        except sqlite3.Error as exc:
            raise StateError("witness schema unavailable") from exc
        finally:
            os.umask(old_umask)

    def _verify_chain(self):
        try:
            with closing(self._connect()) as db:
                if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise StateError("witness database integrity check failed")
                row = db.execute("SELECT seq,head,last_time FROM state WHERE id=1").fetchone()
                if row is None:
                    raise StateError("missing witness head")
                seq, expected_head, last_time = row
                prior = GENESIS
                current_time = 0
                rows = db.execute("SELECT seq,nonce,previous_head,head,request_sha256,"
                                  "event_kind,created_unix FROM events ORDER BY seq")
                count = 0
                for count, event in enumerate(rows, 1):
                    e_seq, nonce, prev, head, request_sha, kind, created = event
                    if (e_seq != count or prev != prior or created < current_time
                            or type(created) is not int):
                        raise StateError("witness chain continuity invalid")
                    body = {"seq": e_seq, "nonce": nonce, "previous_head": prev,
                            "request_sha256": request_sha, "event_kind": kind,
                            "created_unix": created}
                    calculated = hashlib.sha256(LEDGER_DOMAIN + canonical(body)).hexdigest()
                    if calculated != head:
                        raise StateError("witness chain hash invalid")
                    prior, current_time = head, created
                if seq != count:
                    raise StateError("witness sequence invalid")
                final_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if (seq != final_count or expected_head != prior
                        or last_time != current_time):
                    raise StateError("witness head invalid")
        except sqlite3.Error as exc:
            raise StateError("witness database corrupt") from exc

    def health(self):
        self._verify_chain()
        with closing(self._connect()) as db:
            seq, head, _ = db.execute("SELECT seq,head,last_time FROM state WHERE id=1").fetchone()
        return {"schema": RESPONSE_SCHEMA, "seq": seq, "head": head,
                "status": "HOLD", "reason": "RIGHTS_AND_GPU_OWNER_NOT_QUALIFIED",
                **HOLD_FLAGS}

    def append(self, raw, mac_hex):
        if (type(raw) is not bytes or type(mac_hex) is not str
                or HEX64.fullmatch(mac_hex) is None
                or not hmac.compare_digest(mac_hex, hmac.new(
                    self._broker_key, REQUEST_DOMAIN + raw, hashlib.sha256).hexdigest())):
            raise BrokerAuthError("unauthenticated broker request")
        request = _decode_exact(raw)
        if (type(request) is not dict or set(request) != REQUEST_FIELDS
                or request["schema"] != SCHEMA
                or type(request["event_kind"]) is not str
                or request["event_kind"] not in ("PREFLIGHT", "ABORT")
                or type(request["nonce"]) is not str
                or HEX32.fullmatch(request["nonce"]) is None
                or type(request["previous_head"]) is not str
                or HEX64.fullmatch(request["previous_head"]) is None
                or type(request["request_sha256"]) is not str
                or HEX64.fullmatch(request["request_sha256"]) is None
                or type(request["expires_unix"]) is not int):
            raise StateError("unsupported or malformed witness declaration")
        now = int(self._now())
        if not now <= request["expires_unix"] <= now + 120:
            raise StateError("request expired or deadline too far")
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                seq, head, last_time = db.execute(
                    "SELECT seq,head,last_time FROM state WHERE id=1").fetchone()
                # Host time can advance while the SQLite writer lock is busy.
                # Recheck the deadline inside the acquired transaction.
                commit_now = int(self._now())
                if commit_now < now or commit_now < last_time:
                    raise StateError("trusted host clock regressed")
                if not commit_now <= request["expires_unix"] <= commit_now + 120:
                    raise StateError("request expired before durable append")
                if head != request["previous_head"]:
                    raise LedgerConflict("stale witness prior head")
                if db.execute("SELECT 1 FROM events WHERE nonce=?",
                              (request["nonce"],)).fetchone():
                    raise LedgerConflict("broker nonce already consumed")
                next_seq = seq + 1
                body = {"seq": next_seq, "nonce": request["nonce"],
                        "previous_head": head,
                        "request_sha256": request["request_sha256"],
                        "event_kind": request["event_kind"],
                        "created_unix": commit_now}
                new_head = hashlib.sha256(LEDGER_DOMAIN + canonical(body)).hexdigest()
                db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                           (next_seq, request["nonce"], head, new_head,
                            request["request_sha256"], request["event_kind"], commit_now))
                db.execute("UPDATE state SET seq=?,head=?,last_time=? WHERE id=1",
                           (next_seq, new_head, commit_now))
                receipt = {"schema": RESPONSE_SCHEMA, **body, "head": new_head,
                           "status": "HOLD", "reason": "RIGHTS_AND_GPU_OWNER_NOT_QUALIFIED",
                           **HOLD_FLAGS}
                receipt["local_receipt_mac"] = hmac.new(
                    self._issuer_key, RECEIPT_DOMAIN + canonical(receipt),
                    hashlib.sha256).hexdigest()
                if self._signer is not None:
                    # Sign the durable candidate BEFORE COMMIT; signing failure
                    # rolls back the pending CAS instead of consuming the nonce.
                    receipt.update(self._signer.sign_hold(canonical(receipt)))
                db.execute("COMMIT")
        except (StateError, LedgerConflict):
            raise
        except IssuerKeyError as exc:
            raise StateError("host issuer signer unavailable; witness HOLD") from exc
        except sqlite3.IntegrityError as exc:
            raise LedgerConflict("duplicate or conflicting witness append") from exc
        except sqlite3.Error as exc:
            raise StateError("witness append unavailable") from exc
        return receipt


class BoundedWitnessHTTPServer(ThreadingHTTPServer):
    """Limit tailnet-client concurrency on the memory-constrained ARM NAS."""

    daemon_threads = True
    request_queue_size = MAX_HTTP_CLIENTS

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(MAX_HTTP_CLIENTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(engine, port):
    """Construct the concrete loopback server; port 0 is for local tests only."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise StateError("invalid loopback port")
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(CLIENT_TIMEOUT_SECONDS)

        def _respond(self, code, payload):
            raw = canonical(payload)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != "/health":
                return self._respond(404, {"status": "HOLD"})
            try:
                result = engine.health()
                return self._respond(200, result)
            except StateError:
                return self._respond(503, {"status": "HOLD"})

        def do_POST(self):
            if self.path != "/v1/witness":
                return self._respond(404, {"status": "HOLD"})
            lengths = self.headers.get_all("Content-Length", [])
            signatures = self.headers.get_all("X-Vera-Broker-HMAC", [])
            try:
                if (len(lengths) != 1 or not lengths[0].isdigit()
                        or not 0 < int(lengths[0]) <= MAX_BODY
                        or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Type") != "application/json"
                        or len(signatures) != 1):
                    raise StateError("invalid witness transport")
                request_bytes = self.rfile.read(int(lengths[0]))
                if len(request_bytes) != int(lengths[0]):
                    raise StateError("truncated witness request body")
                result = engine.append(request_bytes, signatures[0])
                return self._respond(200, result)
            except BrokerAuthError:
                return self._respond(403, {"status": "HOLD"})
            except LedgerConflict:
                return self._respond(409, {"status": "HOLD"})
            except StateError:
                return self._respond(422, {"status": "HOLD"})
            except (TimeoutError, OSError):
                # A slow/incomplete request cannot consume workers forever.
                self.close_connection = True

        def log_message(self, format, *args):
            # Never log request body, hashes, secrets, or identifiers.
            pass

    server = BoundedWitnessHTTPServer(("127.0.0.1", port), Handler)
    return server


def serve(engine, port):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise StateError("invalid loopback service port")
    server = make_server(engine, port)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Vera TrainingDay NAS HOLD witness")
    parser.add_argument("action", choices=("provision", "provision-signer",
                                          "serve", "serve-signed", "health"))
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18718)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == "provision":
        print(canonical(provision(args.state_dir)).decode("utf-8"))
    elif args.action == "provision-signer":
        print(canonical(provision_signer(args.state_dir)).decode("utf-8"))
    else:
        signer = HostOwnedSigner(args.state_dir) if args.action == "serve-signed" else None
        engine = WitnessEngine(args.state_dir, signer=signer)
        if args.action == "health":
            print(canonical(engine.health()).decode("utf-8"))
        else:
            serve(engine, args.port)


if __name__ == "__main__":
    main()
