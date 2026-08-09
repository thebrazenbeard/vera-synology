# Synology toolkit and Package Center qualification boundary

This repository can locally prove deterministic archive structure and source invariants. It cannot prove DSM accepts or executes the package.

Later separately authorized target/toolkit checks must bind the exact commit and built SPK digest, then verify:

1. Synology DSM 7.2 toolkit can deploy the intended target platform environment and parse the project/package inputs without structural errors.
2. The generated SPK contains exactly one `INFO`, `package.tgz`, required `scripts/`, `conf/privilege`, package icons, and no duplicate archive member names.
3. Package Center on the exact DS216/DSM build accepts the lower-privilege package and its `python311` dependency policy.
4. `dsmuidir=ui` and `dsmappname=com.vera.MeshScaffold` produce an Open action and admin-visible DSM desktop entry as intended.
5. The `systemd-user-unit` resource copies the package user unit, DSM start/stop effects operate as expected, and the package-owned lifecycle oracle returns truthful stable RUNNING/STOPPED/UNKNOWN semantics with exact responder binding.
6. Fresh install creates restrictive durable scaffold state once. Restart preserves it. Upgrade refuses missing/corrupt predecessor state and never silently regenerates identity/trust material.
7. Package process status and Mesh semantic state remain separate. A running scaffold must still show `BLOCKED_MESH_NOT_IMPLEMENTED`.
8. No TCP listener, anonymous LAN admin service, WebStation, Node, React, Chat/Contacts, trust identity generation, pairing, or Mesh delivery exists in this candidate.

Until those device/toolkit checks run under separate authority, status remains `STRUCTURALLY_QUALIFIED_LOCALLY / DEVICE_TOOLKIT_EXECUTION_NOT_RUN`.
