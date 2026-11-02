"""R18 NAS-side private DEV/exclusion *candidate*, never an authority.

Only an independently isolated future evaluator with its own private nonce,
actual frozen R16 and R18 OOD sources, and authenticated R185 TRAIN bytes may
invoke this. Public output contains aggregate hashes/counts but no examples.
Neither supplied data nor Python import establishes custody or use rights.

The synthetic arithmetic generator is a candidate only: it has NOT been
approved as a frozen R18 evaluator, and no real data or nonce ships here.
"""

import hashlib
import hmac
import json
import re
import unicodedata


SCHEMA = "VERA_R18_NAS_PRIVATE_DEV_CUSTODY_CANDIDATE_V1"
GENERATOR_SCHEMA = "VERA_R18_PRIVATE_DEV_GENERATOR_CANDIDATE_V1"
STATUS = "PRIVATE_CANDIDATE_UNAUTHENTICATED_HOLD"
SELECTED_ID_SCHEMA = "VERA_TRAININGDAY_SELECTED_ID_DIGEST_V2"
DEV_ROWS = 64
DOMAIN = GENERATOR_SCHEMA.encode("ascii") + b"\x00"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SUBJECT_FIELDS = frozenset({
    "corpus_id", "manifest_sha256", "train_sha256", "train_content_sha256",
    "selected_id_v2_sha256", "generator_source_sha256",
})
_TRAIN_FIELDS = frozenset({"id", "prompt_sha256", "answer_sha256"})
_PROTECTED_FIELDS = frozenset({"id", "prompt"})


class CandidateError(ValueError):
    """Fail closed without echoing any protected input or nonce."""


def _require(condition):
    if not condition:
        raise CandidateError("private custody candidate rejected")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 256
            and value.strip() == value
            and not any(unicodedata.category(c) in ("Cc", "Cf") for c in value))


def _prompt_hash(value):
    _require(type(value) is str and 1 <= len(value) <= 4096)
    normalized = " ".join(unicodedata.normalize("NFKC", value).split()).casefold()
    _require(bool(normalized))
    return _sha(normalized.encode("utf-8"))


def _unique(entries):
    ids = [row[0] for row in entries]
    prompt_hashes = [row[1] for row in entries]
    _require(len(ids) == len(set(ids)) and len(prompt_hashes) == len(set(prompt_hashes)))


def _validate_nonce(dev_nonce):
    # A source-only length/shape check does not prove OS-generated entropy or
    # separate custody from the existing sealed OOD bank.
    _require(type(dev_nonce) is bytes and len(dev_nonce) == 32
             and dev_nonce != b"\x00" * 32)


def _generate_private_dev_jsonl(dev_nonce):
    """Internal raw DEV material for a future private evaluator ONLY.

    Never call this in a trainer or expose its return on GitHub/Bus/Blotter.
    The public candidate API below returns only the exact-byte commitment.
    """
    _validate_nonce(dev_nonce)
    rows = []
    for index in range(DEV_ROWS):
        seed = hmac.new(dev_nonce, DOMAIN + index.to_bytes(4, "big"),
                        hashlib.sha256).digest()
        a = 10000 + int.from_bytes(seed[:4], "big") % 60000
        b = 100 + int.from_bytes(seed[4:8], "big") % 9000
        multiplier = 2 + int.from_bytes(seed[8:12], "big") % 400
        operation = seed[12] % 3
        if operation == 0:
            prompt, answer = "Compute {} plus {}.".format(a, b), a + b
        elif operation == 1:
            prompt, answer = "Compute {} minus {}.".format(a, b), a - b
        else:
            prompt, answer = "Compute {} times {}.".format(a, multiplier), a * multiplier
        rows.append({
            "id": "r18-dev-" + _sha(DOMAIN + seed)[:24],
            "prompt": prompt, "answer": str(answer), "split": "dev",
        })
    _unique([(row["id"], _prompt_hash(row["prompt"])) for row in rows])
    return b"\n".join(_canonical(row) for row in rows) + b"\n"


def _train_index(rows, subject):
    _require(type(rows) is list and len(rows) == 1024)
    entries = []
    for row in rows:
        _require(type(row) is dict and set(row) == _TRAIN_FIELDS)
        _require(_identifier(row["id"]))
        for field in ("prompt_sha256", "answer_sha256"):
            _require(type(row[field]) is str and HEX64.fullmatch(row[field]) is not None)
        entries.append((row["id"], row["prompt_sha256"], row["answer_sha256"]))
    _unique(entries)
    ids = [row[0] for row in entries]
    selected_digest = _sha(SELECTED_ID_SCHEMA.encode("ascii") + b"\x00"
                           + json.dumps(ids, ensure_ascii=False,
                                        separators=(",", ":")).encode("utf-8"))
    _require(selected_digest == subject["selected_id_v2_sha256"])
    full_digest = _sha(_canonical([
        {"id": row[0], "prompt_sha256": row[1], "answer_sha256": row[2]}
        for row in entries
    ]))
    _require(full_digest == subject["train_content_sha256"])
    return entries, selected_digest, full_digest


def _protected(rows, bank):
    _require(type(rows) is list and len(rows) == 64)
    result = []
    for row in rows:
        # Never ingest protected answers into this hash-only source seam.
        _require(type(row) is dict and set(row) == _PROTECTED_FIELDS
                 and _identifier(row["id"]))
        result.append({
            "id": row["id"], "prompt_sha256": _prompt_hash(row["prompt"]),
            "bank": bank,
        })
    _unique([(row["id"], row["prompt_sha256"]) for row in result])
    return result


def build_private_dev_candidate(*, subject, train_index, r16_protected,
                                r18_external_ood, dev_nonce):
    """Check disjoint inputs, then return aggregate commitments with HARD HOLD.

    Supplied subject, TRAIN index, protected bank rows, and secret nonce are
    untrusted until a separate NAS custodian enrolls their OS/source provenance.
    This module NEVER writes or authenticates private gold or issues grants.
    """
    _require(type(subject) is dict and set(subject) == _SUBJECT_FIELDS
             and subject["corpus_id"] == "R18_ARITHMETIC")
    for key in _SUBJECT_FIELDS - {"corpus_id"}:
        _require(type(subject[key]) is str and HEX64.fullmatch(subject[key]) is not None)
    _validate_nonce(dev_nonce)
    train, selected_digest, full_digest = _train_index(train_index, subject)
    r16 = _protected(r16_protected, "R16_PROTECTED")
    r18 = _protected(r18_external_ood, "R18_EXTERNAL_OOD")
    exclusions = r16 + r18
    dev_jsonl = _generate_private_dev_jsonl(dev_nonce)
    dev_rows = [json.loads(raw_line) for raw_line in dev_jsonl[:-1].split(b"\n")]
    dev_pairs = [(row["id"], _prompt_hash(row["prompt"])) for row in dev_rows]
    protected_pairs = [(row["id"], row["prompt_sha256"]) for row in exclusions]
    _unique([(row[0], row[1]) for row in train] + dev_pairs + protected_pairs)
    _require(all(type(row["answer"]) is str and len(row["answer"]) <= 8
                 and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", row["answer"]) is not None
                 for row in dev_rows))
    return {
        "schema": SCHEMA, "status": STATUS,
        "corpus_id": "R18_ARITHMETIC",
        "manifest_sha256": subject["manifest_sha256"],
        "train_sha256": subject["train_sha256"],
        "train_content_sha256": full_digest,
        "selected_id_v2_sha256": selected_digest,
        "generator_source_sha256": subject["generator_source_sha256"],
        "dev_generator_schema": GENERATOR_SCHEMA,
        "dev_count": len(dev_rows),
        "dev_sha256": _sha(dev_jsonl),
        "protected_exclusion_count": len(exclusions),
        "protected_exclusion_sha256": _sha(_canonical(exclusions)),
        "private_content_returned": False,
        "independent_custody_authenticated": False,
        "owner_identity_authenticated": False,
        "source_use_rights_verified": False,
        "host_ratification_authenticated": False,
        "authorizes_training": False,
        "authorizes_eval_unseal": False,
    }
