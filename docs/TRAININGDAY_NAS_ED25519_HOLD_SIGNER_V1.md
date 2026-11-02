# TrainingDay NAS host-owned Ed25519 HOLD signer (source candidate)

**Status: NEW DRAFT SOURCE, NOT DEPLOYED, NOT AN ADMISSION OR GPU LEASE.**

This successor introduces genuine, locally generated Ed25519 signing keys for
the existing bounded NAS witness. The implementation uses OpenSSL's Ed25519
`pkeyutl -rawin` with private temporary files, supporting DSM's observed
OpenSSL 1.1.1u and Python 3.8 standard library without installing `cryptography`.

It does **not** modify the currently installed default `serve` behavior. No
private signing key is loaded from an HTTP request, returned to a client, or
stored in Git. The signer accepts only exact canonical
`VERA_TRAININGDAY_NAS_WITNESS_HOLD_V1` receipts with all three grants `false`.

## Offline-only provisioning and opt-in

Before an independent host change, the NAS administrator must verify the
installed version, dedicated non-admin service identity, live file hashes,
trusted OpenSSL path, and private state ownership. As the service identity,
one-time offline provisioning is:

```sh
/usr/bin/python3 -m trainingday_issuer.nas_witness provision-signer \
  --state-dir /volume1/@apphome/vera-trainingday-witness/private/state
```

This creates `issuer-ed25519-private.pem` and `issuer-ed25519-public.pem`
in the pre-existing 0700 service-private state directory, mode 0600. Existing
keys are never overwritten. Provisioning failure may leave an incomplete pair
that must be inspected offline; it is never silently repaired.

After exact-head review and operator-controlled rollback preparation, the
administrator **may separately choose** the new `serve-signed` action in the
installed service command, keeping the same loopback port and existing ledger:

```sh
/usr/bin/python3 -m trainingday_issuer.nas_witness serve-signed \
  --state-dir /volume1/@apphome/vera-trainingday-witness/private/state \
  --port 18718
```

It appends under SQLite `BEGIN IMMEDIATE`; the signer generates an Ed25519
signature over the exact canonical HOLD receipt while the transaction is still
open. If signing fails, SQLite rolls back the nonce/epoch transition; no
signed-looking positive receipt is returned. A successful response adds:

- `issuer_public_pem_sha256`: SHA-256 of the exact provisioned PEM public key;
- `issuer_ed25519_signature_hex`: 64-byte Ed25519 signature in lowercase hex.

Signing domain: `VERA_TRAININGDAY_NAS_ISSUER_ED25519_HOLD_V1` plus NUL byte.
The signed bytes exclude the signature/fingerprint attachment and remain exact
canonical JSON. A verifier MUST use a **separately trusted, pinned** public key
obtained through an authorized enrollment process. A key fingerprint or PEM
returned by the service cannot enroll itself as a trust root.

## What remains unresolved

- Existing broker HMAC is locally generated but **not physically enrolled**
  into a separately verified Windows LocalSystem broker. A valid HMAC would
  prove possession of the shared secret, not actual Windows token ownership.
- The key pair is host-owned but its *public identity is not yet independently
  enrolled* by a relying broker/owner; signing alone cannot issue rights.
- R185 owner's source packet is unsigned; protected DEV and exclusion custody
  is not independently authenticated. No source-rights ADMIT exists.
- The NAS ledger has no external anti-rollback anchor; a privileged rollback
  of the entire database remains detectable only if a separately held head is
  compared.
- WDDM Lappy's current broker is deny-only and does not enforce CUDA process
  exclusivity or own a real TrainingDay child. No GPU lease can be issued.
- The currently deployed NAS service and Tailscale route are untouched by
  these draft changes. The new signing mode is opt-in only.

## Synthetic verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  tests.test_trainingday_issuer_signer tests.test_trainingday_nas_witness
```

Negative coverage: forged/wrong public key, tampered signed bytes, positive or
extra grant fields, missing OpenSSL, unsafe key permissions, duplicate offline
provisioning, and signer failure before SQLite commit. None grants training.
