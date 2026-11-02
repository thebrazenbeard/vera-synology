# TrainingDay NAS host-owned RSA-PSS HOLD signer (source candidate)

**Status: DRAFT SOURCE, NOT DEPLOYED, NOT AN ADMISSION OR GPU LEASE.**

The initial Ed25519 draft wrongly claimed OpenSSL 1.1.1u CLI support.
An actual Synology ARMv7 OpenSSL 1.1.1u probe generated Ed25519 keys but
`openssl pkeyutl -sign -rawin` failed with `Option unknown option -rawin`.
OpenSSL's official 1.1.1 `pkeyutl` and `dgst` documentation explicitly
excludes Ed25519/Ed448 signing with those utilities. Merely dropping
`-rawin` is **not** a repair.

This replacement uses host-generated **3072-bit RSA-PSS/SHA-256**, with
MGF1-SHA-256 and a fixed 32-byte salt, through OpenSSL `dgst`. Its supported
command shape exists in OpenSSL 1.1.1 as well as 3.x. The source also runs a
real sign/verify self-test using the exact configured OpenSSL binary **before
publishing the key pair and on every signed-service startup**. A failure
prevents signing, cannot consume a pending CAS nonce, and does not fall back
to unsigned or weaker signature formats.

The currently deployed unsigned `serve` mode remains unchanged. No signing
key is accepted from HTTP, returned to a client, or stored in Git. The signer
accepts only canonical `VERA_TRAININGDAY_NAS_WITNESS_HOLD_V1` receipts with
all three grant flags exactly false. The RSA key pair is a **new identity**;
no Ed25519 draft key or fingerprint is silently migrated.

## Offline-only provisioning and opt-in

Before changing the actual NAS service, independently review the exact source,
service UID, installed version, trust anchor, rollback procedure and live
OpenSSL operation. As the restricted service account, one-time provisioning:

```sh
/usr/bin/python3 -m trainingday_issuer.nas_witness provision-signer \
  --state-dir /volume1/@apphome/vera-trainingday-witness/private/state
```

This creates `issuer-rsapss-private.pem` and `issuer-rsapss-public.pem`
with mode 0600 inside an existing 0700 service-private directory. A partial
pair requires explicit offline inspection; a second provision operation
refuses replacement. The signer does **not** silently rotate or overwrite.

After separate rollout/rollback qualification, the administrator may opt in:

```sh
/usr/bin/python3 -m trainingday_issuer.nas_witness serve-signed \
  --state-dir /volume1/@apphome/vera-trainingday-witness/private/state \
  --port 18718
```

Within SQLite `BEGIN IMMEDIATE`, it signs the exact canonical HOLD receipt
before COMMIT. A successful response adds these attachments:

- `issuer_public_pem_sha256`: SHA-256 of protected public PEM bytes;
- `issuer_signature_algorithm`: fixed `RSA_PSS_SHA256_MGF1_SHA256_SALT32`;
- `issuer_rsapss_signature_hex`: exactly 384 signature bytes, lowercase hex.

Signing domain: `VERA_TRAININGDAY_NAS_ISSUER_RSA_PSS_SHA256_HOLD_V1` + NUL.
The signed bytes exclude the attachments. Verification requires an independently
trusted, pinned public PEM and fixed expected algorithm; an HTTP-supplied
fingerprint cannot self-enroll as a trust root. Do not accept an algorithm
claimed solely by the untrusted response to select a verifier dynamically.

## Still unresolved

- NAS key-public-identity enrollment into an independent relying party.
- Owner identity/source rights, protected DEV and exclusion custody, and an
  externally anchored monotonic ledger head.
- An enforceable physical GPU lease. Lappy WSL2 can see its RTX 3050, but
  Windows WDDM remains in Default compute mode; the current broker is deny-only.
- On-device NAS ARMv7 RSA-PSS sign/verify and controlled rollback qualification.
  Until those pass, **keep the current unsigned HOLD service installed**.

## Source test

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  tests.test_trainingday_issuer_signer tests.test_trainingday_nas_witness
```

Negative cases cover tampering, mismatched keys, forgery, positive grants,
permission failures, self-test failure, missing OpenSSL, and rollback on
signing failure. The implementation does not grant training.
