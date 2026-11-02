# TrainingDay cross-host high-water candidate — STRUCTURAL HOLD

This is a source-only Python 3.8-compatible comparison primitive, **not** a
deployed second witness, a rights issuer, or a training lease. It does not
change the installed NAS service, its API, keys, or the Windows broker.

`trainingday_issuer.cross_host_highwater_candidate.PeerHighwaterCandidate`
records consecutive, canonical, HMAC-bound receipts in a private SQLite
WAL/FULL local floor. The receipt carries a peer label, protocol epoch,
sequence, previous head, new head and nonce. Every result, including a
successful append, is `PEER_HWM_STRUCTURAL_HOLD` with the peer identity,
external rollback anchor, rights, GPU and physical-training grants **false**.

If an independently administered Lappy host retains sequence `N`, it can
reject a reverted NAS that replays `< N` or changes the chain head. For this
comparison to be meaningful, both hosts must run independently authenticated
services with separate durable state, retained history and a trustworthy
channel. No such owner-controlled enrollment is implemented here. The
32-byte HMAC key, `expected_peer`, epoch and local directory are **all
caller-supplied**, so matching MACs and test-local source checks do *not*
establish independent Lappy identity or high-water custody.

## Deliberate limits

- **Whole-state rollback on both hosts:** can replay an older valid history.
  Even rollback of this one local database is undetectable until an actually
  independent host presents its retained newer evidence; the test suite
  demonstrates that failure mode explicitly.
- **Privileged compromise or collusion:** either host can tamper with its
  persisted history. Symmetric HMAC requires both signing and verifying
  parties to know shared material; it cannot prove a separate asymmetric
  issuer identity, particularly after compromise of a recipient host.
- **False history/fork:** a valid MAC on an arbitrary head proves only use
  of the supplied HMAC key, not that the true NAS ledger or GPU job produced
  it. The candidate does not connect receipts to the #15 event transcript.
- **ACL and process security:** private-directory checks are portable source
  checks, not audited host isolation; a privileged actor or symlink race can
  still replace SQLite or keys. Do not place this in an installed service.
- **Availability/epoch:** sequential receipts require replay of every
  intervening event after an outage. No catch-up/snapshot, clock guarantee,
  key rotation, local identity, revocation or enrollment ceremony exists.

An actual cross-host anchor requires an independently enrolled Lappy process
identity, separate protected Lappy and NAS state, an authenticated transport,
verified exact event transcript and a rollback/revocation policy. No positive
rights or training transition is proposed until those and the owner-controlled
corpus/evaluator/GPU grants are independently qualified.

Run synthetic validation with `python -m unittest -q
tests.test_trainingday_cross_host_highwater_candidate`. All fabricated keys
and packets are test-only. This candidate preserves NAS Draft #15's
unconditional HOLD and does not alter `trainingday_issuer.nas_witness`.
