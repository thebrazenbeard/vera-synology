# VeraMesh DS216 target-first repair

This branch intentionally discards the failed Python readiness scaffold as an implementation constraint.

## Runtime decision

The first repair generation uses **Node.js v22** because the user-supplied historical
`VeraRelay-0.2.2-armada38x-with-VERA-icon(3).spk` has SHA-256 `57c85e31cafc9f357818494db914482dc14aff61286f6469587e5b55d2fcb7d6` and declares
`install_dep_packages="Node.js_v22"`. That historical package installed and ran on the same DS216 target.
The current DS216 also reports Node.js v22 installed.

This is a bounded target-first choice, not a permanent Mesh runtime decision. Python 3.11 is also
installed, but the failed VeraMesh scaffold was never allowed to start because its runtime target policy
was intentionally unbound. No current same-device resource benchmark proves Node or Python cheaper.
After this repair survives ordinary Package Center install/start/status/open/stop, measure the actual
Node process RSS/CPU/start latency before freezing a release runtime.

## Acceptance ceiling

This source can produce a **device-validation candidate**. It is not handoff-ready or testable by project
policy until the ordinary DS216 Package Center install + start + status + open + stop flow succeeds on the
target device.

## Repair behavior

- package identity `VeraMesh`, target `armada38x`, DSM >= 7.2-72806
- lower-privilege package user `veramesh`
- Node.js v22 dependency, `/usr/local/bin/node`
- one process, no custom watchdog, no systemd-user-unit worker
- safe `SAFE_IDLE_UNPAIRED` state
- no TCP/UDP/UNIX listener, no pairing, no transport
- Package Center Start/Stop/Status semantics
- DSM Open launches a static diagnostic surface
- VERA package and application icons are derived from the verified historical VERA icon
- no periodic state writes; state updates only on lifecycle transitions

## Historical baseline defect deliberately not copied

The VeraRelay 0.2.2 `package.tgz` contained duplicate payload members. This branch reuses the proven
package/lifecycle shape and icon, not those duplicate archive defects.
