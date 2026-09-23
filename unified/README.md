# VeraMesh unified runtime host

Single DSM package; separate internal Edge, Relay, Gateway, and DSM-control roles. Exact component bindings are in component-bindings.json. Gateway and Relay are bundled but disabled by default. WorkBridge remains external on Lappy.

Version 0.2.0-0002 adds a guarded standalone-VeraRelay adoption tool with exact state-copy verification and rollback.

Version 0.2.0-0003 accepts Synology's package-managed VeraRelay var symlink after canonical resolution, preserves module-config ownership, and avoids restarting VeraMesh on pre-cutover failures.

Version 0.2.0-0004 fixes fresh-install lifecycle bootstrap by passing DSM's real SYNOPKG_PKG_STATUS to veramesh_lifecycle.py instead of a literal shell expression. This is required when VeraMesh has been removed and no prior lifecycle state exists.

Version 0.2.0-0005 removes the unsupported system-unit ordering dependency from the DSM systemd user unit and expresses network ordering through DSM INFO start_dep_services instead.
