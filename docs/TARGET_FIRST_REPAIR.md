# Target-first repair evidence

Historical user-supplied baseline:
- file: `VeraRelay-0.2.2-armada38x-with-VERA-icon(3).spk`
- SHA-256: `57c85e31cafc9f357818494db914482dc14aff61286f6469587e5b55d2fcb7d6`
- package: `VeraRelay`
- version: `0.2.2-0001`
- arch: `armada38x`
- dependency: `Node.js_v22`
- package icon SHA-256 (64): `7a7e58574f82b16f9522c2b61456ac84b46f33b8a7c75c24e02f3db7e897b59a`
- package icon SHA-256 (256): `0bbab931e7ed5836917dee72b80fe68295ee8182aa08bc0a00250bcb11f442d5`

Repair target:
- Synology DS216
- DSM 7.2.2-72806 Update 9 (prior live device evidence)
- Armada38x / ARMv7, 512 MB RAM
- Node.js v22 currently installed (user Package Center evidence)
- Python 3.11 currently installed (user Package Center evidence)

Decision:
Use Node.js v22 for the first target repair because it has the strongest same-device packaging/lifecycle
evidence. Do not infer superior memory/CPU cost. Target measurement remains required before final runtime freeze.
