# VeraMesh unified runtime host

Single DSM package; separate internal Edge, Relay, Gateway, and DSM-control roles. Exact component bindings are in component-bindings.json. Gateway and Relay are bundled but disabled by default. WorkBridge remains external on Lappy.

Version 0.2.0-0002 adds a guarded standalone-VeraRelay adoption tool with exact state-copy verification and rollback.

Version 0.2.0-0003 accepts Synology's package-managed VeraRelay var symlink after canonical resolution, preserves module-config ownership, and avoids restarting VeraMesh on pre-cutover failures.

Version 0.2.0-0004 fixes fresh-install lifecycle bootstrap by passing DSM's real SYNOPKG_PKG_STATUS to veramesh_lifecycle.py instead of a literal shell expression. This is required when VeraMesh has been removed and no prior lifecycle state exists.


Version 0.2.0-0005 hardens reinstall recovery for DSM's persistent package var: INSTALL quarantines any prior modules.json without reading it and recreates safe edge-only activation state; UPGRADE remains fail-closed and preserves valid activation state.

Version 0.2.0-0006 repairs the DSM broken-package upgrade path: UPGRADE can quarantine an unreadable persisted modules.json without reading it, recreate safe edge-only activation, and establish a fresh lifecycle incarnation when persistent lifecycle authority is validly RETIRED and the semantic control socket is absent. Corrupt-but-readable activation and non-retired lifecycle states remain fail-closed/preserved.

Version 0.2.0-0007 adds supervisor-owned hot module reload. SIGHUP re-reads modules.json and starts/stops optional Relay/Gateway processes without stopping the VeraMesh package or Edge. VeraRelay adoption now uses this reload path for cutover and rollback.

Version 0.2.0-0008 hardens Relay adoption qualification: fixes the missing signal import, binds SIGHUP completion to a monotonic supervisor reload generation, validates the exact supervisor process identity, requires pre/post Relay health and audit-chain continuity, and re-hashes the stopped standalone source state before declaring adoption safe for uninstall review.
