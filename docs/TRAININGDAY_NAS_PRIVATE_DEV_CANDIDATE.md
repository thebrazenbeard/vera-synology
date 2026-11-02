# R18 separate-private-DEV and protected-exclusion commitment candidate

Status: **SOURCE ONLY / UNFROZEN GENERATOR / NOT INSTALLED / HOLD**.

`trainingday_issuer.private_dev_candidate` is a deterministic *format and
disjointness* candidate for a future NAS-isolated evaluator. It has no HTTP
endpoint and does not alter the deployed `vera-trainingday-witness.service`.
Importing it or satisfying its predicates is not admission, training rights,
or proof that an evaluator exists.

## Input ownership required before real use

An independently administered custodian, not the model-training process, must
retrieve and authenticate all of these from its protected source inventory:

1. **R185 ordered TRAIN:** exactly 1,024 `{id,prompt_sha256,answer_sha256}`
   records derived from frozen original prompt and answer bytes. The subject's
   `train_content_sha256` and `selected_id_v2_sha256` must be enrolled and
   checked independently of the caller. The R185 owner-review packet SHA-256,
   selected-ID digest, and full TRAIN-content digest are *distinct* objects.
2. **R16 protected:** exactly 64 frozen R16 fresh-held-out `{id,prompt}`
   records, reconstructed under protected custody from source bytes. An
   ID-only exclusion record is insufficient to establish prompt disjointness.
3. **R18 external OOD:** exactly 64 independently authenticated existing
   sealed-bank `{id,prompt}` records, never substituted for private DEV.
   Private answers and source nonce do not cross this candidate API.
4. **Separate DEV:** a fresh 32-byte secret nonce generated and retained by
   the custodian for DEV alone, not reused from the R18 OOD bank or selected
   by a training caller. The current `VERA_R18_PRIVATE_DEV_GENERATOR_CANDIDATE_V1`
   produces 64 synthetic arithmetic cases; it is NOT a reviewed/frozen R18
   evaluation distribution and must be reviewed and frozen before any real
   independent evaluator uses it. Case rows and nonce stay in the private
   process. The public builder returns only aggregate SHA-256 and counts.

The synthetic generator derives each case from HMAC-SHA256 with a domain-
separated nonce and ordered counter. Its byte-exact canonical JSONL has
`id,prompt,answer,split:"dev"`; the protected exclusion JSON binds the
ordered 64 R16 plus 64 R18 records, each with `id,prompt_sha256,bank`.
Both commitments use canonical JSON with sorted keys, compact separators and
UTF-8, matching the source-only model-training Draft #206 bridge. Prompt
hashes use NFKC whitespace collapse and case-folding. Overlap checks reject
duplicate or cross-split IDs and normalized prompt hashes.

## Trust ceiling

- No real R16/OOD/DEV contents, nonce or private per-case hashes are included
  in the repository, tests, generated output, Bus or Blotter.
- This code makes no OS ACL, private material, signer, rights, replay, or
  immutable owner-enrollment assertion. A caller that co-forges TRAIN index
  and subject commitments remains unauthenticated even if input consistency
  checks pass; **all authorization flags are permanently false**.
- The existing R18 OOD bank is exclusion-only; using it as DEV would violate
  the required separation and is rejected on repeated IDs/prompts.
- The existing Lappy R185 packet is unsigned, and the private exclusion
  commitment/owner key are not yet enrolled. No source-only hash-only result
  may be promoted to a protected evaluator, rights admission or GPU lease.
- Future private implementation must store nonce, DEV bytes and protected
  source records under a separate NAS service identity and strict ACLs with
  atomic checkpoint/retention and independent source review. The candidate
  does not write files or expose a network route.

## Synthetic verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -q tests.test_private_dev_candidate
```

The tests use only invented prompts and a synthetic nonce. They exercise
determinism, 64+64 exclusion counts, exact-byte digest changes, TRAIN/DEV and
DEV/OOD overlap rejection, malformed provenance rejection and non-disclosure.
Passing tests do not qualify any physical private bank or real evaluator.

## R185 owner/custody cross-binding (source candidate)

`trainingday_issuer.owner_custody_join.join_owner_and_private_custody` now
cross-checks the canonical R185 host source-pin bytes against a hash-only
private DEV/exclusion candidate. It rejects mismatched manifest, TRAIN-content
or selected-ID V2 hashes, malformed or unauthorized private summaries,
unexpected private fields, and attempted positive rights/evaluation claims.
The resulting domain-separated join SHA-256 binds the owner-key fingerprint,
source-pin generation, ordered TRAIN declarations and aggregate DEV/exclusion
hashes without returning private cases, answers, or the DEV nonce.

**The join is consistency evidence only, not authenticated custody.** Even if a
caller co-forges both source pin and private candidate, it remains `HOLD` with
all rights, protected-evaluation, GPU-lease, and training flags false. It does
not verify an owner signature, OS-level root-owned source enrollment, original
source rights, independently sealed evaluator provenance, or host ratification.
The active HTTP witness does not import this module and remains unchanged.
Its purpose is to make a future separate NAS ratifier reject inconsistent
inputs before any protected cryptographic, OS-custody, or authorization step.

Synthetic tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -q tests.test_trainingday_owner_custody_join
```
