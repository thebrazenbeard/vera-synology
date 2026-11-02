# TrainingDay NAS local witness candidate

**State: source-only candidate, independently unaudited, never ADMIT.**

`trainingday_issuer.nas_witness` is a runnable **Python 3.8 standard-library**
HTTP service for Synology DSM. It is an authenticated *local append journal*,
not a data-rights issuer or Lappy GPU owner. Its sole dynamic endpoint writes
a durable compare-and-append record and returns `HOLD`, regardless of claims.

The service binds **only `127.0.0.1:18718`**. No TLS or WAN/LAN listener is
created. Remote transport would require an independently authenticated,
correct-hostname TLS tunnel and explicitly reviewed client identity. Do **not**
reuse or modify existing Tailscale Serve port 17445 or Executor ingress 9443.

## R185 source and owner-key enrollment extension (NOT INSTALLED)

`trainingday_issuer.owner_source_pin` is a **separate future integration
candidate** that checks a *root-owned*, non-symlink, canonical JSON enrollment
file outside the writable service state. It binds
the physically observed frozen R185 owner-review packet SHA, R18 manifest,
ordered 1,024-case TRAIN-content digest, and V2 selected-ID digest to one
administrator-enrolled owner public-key fingerprint and revocation generation.
It verifies that each parent directory and the file are root-owned and cannot
be replaced by the unprivileged `vera-witness` process. **The currently
deployed NAS witness does not import this module or accept an owner pin.** A
separate reviewed service-integration change is needed to bind the root pin to
requests, detect revocation/rollback, and fail closed on live replacement.
The pin module itself never accepts a public-key pin from a network request.

**No owner key has been enrolled by this source patch.** The R185 packet is
still unsigned and has a null protected-exclusion custody digest. An
administrator must separately verify Patrick's identity and the original
R185 bytes and enroll a genuine public key before installing a file. Do not
copy a synthetic test key into the NAS. A pinned public key or TRAIN digest
alone cannot prove actual owner consent, independent DEV/exclusion custody,
source-use rights, external antirollback, or physical GPU ownership. Every
service decision and every resulting authorization flag remains `HOLD/false`.
The HTTP listener bounds concurrent client connections to 16 and applies a
3-second socket deadline to limit slow-client resource exhaustion on ARMv7.

## Staged DSM deployment (administrative operator, not automatic)

1. Install source to a root-protected, immutable versioned location outside
   Git and ensure `/usr/bin/python3` is Python 3.8 or newer.
2. Provision a dedicated **unprivileged** service user with no access to
   private evaluator gold, GPU jobs, model files, NAS administrator secrets,
   or existing VeraMesh/Executor state.
3. As that service user, select a new exact service-owned directory outside
   all package or model trees. From the installed source root run once:

   ```sh
   /usr/bin/python3 -m trainingday_issuer.nas_witness provision \
     --state-dir /volume1/@apphome/vera-trainingday-witness/private
   ```

   Provisioning creates `broker.key` and a **distinct** `issuer.key` with
   mode 0600 and a private 0700 directory. It fails if the directory exists;
   it never prints secret bytes. **Generated keys are not enrolled identities**.
   Distribute `broker.key` only through a separately authenticated admin
   procedure to a verified Windows broker service; never put keys in Git,
   logs, command-line flags, service units, Bus, or model-training prompts.
   The current Windows training broker is deny-only and not yet enrolled.
4. Start under that restricted account with protected working directory and
   `umask 077`, using the exact installed Python module location:

   ```sh
   /usr/bin/python3 -m trainingday_issuer.nas_witness serve \
     --state-dir /volume1/@apphome/vera-trainingday-witness/private \
     --port 18718
   ```

5. Verify `curl --fail http://127.0.0.1:18718/health` returns only `HOLD`,
   and use a separately enrolled broker to prove HMAC-bound append, stale
   head rejection, nonce replay rejection, restart continuity, and storage
   permission checks. Stop the service before any package change. `systemd`
   219 supports a dedicated service unit; a cautious template is included at
   `trainingday_issuer/vera-trainingday-witness.service.example`. Review the
   precise user, paths, binaries and unit semantics against the live DSM host
   before copying it into `/etc/systemd/system/`. Never run under NAS root
   merely to make it start.

6. **Rollback:** stop and disable the new unit, remove only its exact installed
   unit file, reload `systemd`, and verify the listener on 18718 is gone.
   Retain the private ledger/keys untouched for forensic rollback and replay
   continuity. Do not erase prior state, VeraMesh, Tailscale or Executor.

## Exact API

`GET /health` reports a public `HOLD` and local ledger sequence/head.
`POST /v1/witness` has `Content-Type: application/json`, `Content-Length`,
and `X-Vera-Broker-HMAC` containing lowercase HMAC-SHA256 of
`b"VERA_TRAININGDAY_NAS_BROKER_V1\\x00" + exact canonical JSON request`,
using the privately provisioned broker key. Request exact fields:

- `schema`: `VERA_TRAININGDAY_NAS_WITNESS_REQUEST_V1`
- `nonce`: lowercase 32-hex, never reused
- `previous_head`: lowercase 64-hex, initial all zeroes
- `request_sha256`: lowercase 64-hex immutable declaration identifier
- `event_kind`: `PREFLIGHT` or `ABORT` only
- `expires_unix`: host-comparable integer deadline within 120 seconds

The SQLite journal uses WAL, FULL synchronous commits, a unique nonce index,
`BEGIN IMMEDIATE` CAS, sequence/head hash chain, clock-regression detection,
startup chain verification and restrictive directory/file modes. A reply is
`HOLD`, including `rights_admitted=false`, `gpu_lease_granted=false`, and
`physical_training_authorized=false`. A distinct server-only HMAC protects a
**local receipt**, but is **not independently verifiable asymmetric issuer
signing** and must never be treated as an authority root.

This does not authenticate R185 TRAIN/DEV/exclusion provenance, owner key
enrollment or actual source-use rights. It has no Windows broker token/Job
Object capability, GPU exclusivity, protected data, verified certificate,
external anti-rollback anchor, or durable cross-host physical lease. Complete
database rollback by a state-owning administrator is not detectable locally;
independent trusted monotonic anchoring is required before any lease grant.
NAS administration is already authorized by Patrick; that is a deployment
permission, **not** a substitute for these effect conditions. Never alter the
model-training unconditional physical launch guard to accept this service.

## Source tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_trainingday_nas_witness
```

Tests use synthetic state and synthetic HMAC keys only; no protected source
or physical training is accessed.
