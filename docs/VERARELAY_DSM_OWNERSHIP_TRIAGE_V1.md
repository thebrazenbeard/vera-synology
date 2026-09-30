# VeraRelay DSM ownership incident — investigation V1

Status: read-only diagnostic source. NOT installed, deployed, or production-qualified.

## Purpose

The standalone VeraRelay package can reject DSM prestart with the marker
port_17443_healthy_but_not_owned even while the port returns healthy metadata.
A health response alone is not authority to stop, kill, adopt, or restart a
process. The frozen predecessor package checks a PID file and runtime argv;
a missing, stale, reused, or foreign PID can disagree with a healthy socket.

## Read-only probe

tools/diagnose_verarelay_owner.py is a Python 3.11-compatible source-level
inspection helper for an already authenticated, host-key-verified DSM shell.
Invoke as: python3 /trusted/path/diagnose_verarelay_owner.py

It inspects the installed VeraRelay state runtime.json/runtime.pid, exact
Node runtime/server argv, DSM package UID, parent-child PID relationship,
localhost TCP listener inode and server process FDs, and localhost health.
It does not read private keys, tokens, messages, full environments or config
secrets. It never edits durable state or signals a process.

Diagnostic classifications:
- PROCESS_CHAIN_MATCHES_PIDFILE: matching recorded process chain and listener,
  not proof of DSM package manager lifecycle ownership.
- STALE_OR_MISSING_PIDFILE_CANDIDATE: matching process chain but no matching
  PID file. Manual review is mandatory; nothing is repaired automatically.
- UNVERIFIED_OR_FOREIGN_LISTENER: at least one required check did not match.
- NO_LOCAL_LISTENER_OR_PROC_VISIBILITY: no matching loopback listener visible.

## Operator boundary

Verify DSM SSH host key independently before accepting a new host key.
Tailscale SSH is not available on Synology; use Synology's SSH daemon
through an approved network route, without weakening SSH trust settings.
Collect package status and version, probe report, installed source bindings,
and nonsecret lifecycle logs before choosing an effect. Do not attempt
blind PID-file rewrites, process kills, package restart, or unverified cutover.
Any runtime change requires exact operator authority and readback.

## Intended architecture and research findings

VeraRelay is an authenticated, durable sealed-mailbox courier for Vera Mobile
and the Vera Host Adapter. It is not an inference runtime, identity source,
canonical memory, or remote computer execution service. WorkBridge remains
the governed execution surface. Tailnet-private transport does not substitute
for application-layer sender, role, scope, recipient, or operation checks.

The documented VeraMesh V1/Relay 0.4 target requires RFC 9421 signatures
with strict P-256/ES256 key checks, signed body digests, transactional nonce
replay handling, explicit roles/scopes, opaque endpoint-encrypted envelopes,
content-bound idempotency, append-only signed receipts, SQLite transactions,
migration/rollback safety, corruption quarantine, external audit checkpoints,
structured health, DSM package-user privilege, and localhost-only binding.

The live 0.3 predecessor is specifically frozen with documented known
authorization, receipt, audit, and idempotency defects. The preserved 0.4
snapshot still has unintegrated executable server and SQLite paths; passing
isolated tests is not SPK, deployment, production-route, or E2E evidence.

## Qualification and hostile review

Internal fixtures cover valid process chain, stale/malformed/missing PID file,
UID and parent mismatch, unowned socket, failed audit, stale runtime state,
malformed health data, absent listener, and argv spoof attempts. Fixtures
are not live NAS process evidence and not independent review.

HOSTILE OBJECTION (ACCEPTED): A same-UID process with access to writable
package state may reproduce much of this apparent ownership chain. Therefore
the tool reports corroboration, not attestation, and never auto-adopts.
Package manager lifecycle, installed source, and external authenticated
behavior require separate evidence.

Next gate: collect read-only NAS ownership evidence after independently
verifying host key and authenticating; assess exact repair versus a guarded
migration to a release-qualified 0.4 successor. Do not activate 0.4 solely
because a 0.4 archive exists.
