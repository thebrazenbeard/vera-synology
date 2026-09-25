> **License:** Source-visible, not open source. Original material is proprietary. Commercial use, redistribution, hosted-service use, and commercial derivative products require written permission. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Separately identified third-party components retain their own licenses.

# Vera Synology runtime host

This repository contains the Synology/DSM packaging and runtime-host source for VeraMesh on the DS216-class target. It now carries two related source surfaces on `main`:

- the hardened **VeraPort live edge** package, which runs as the DSM package user and exposes only a loopback TCP edge intended for tailnet-only ingress through separately configured Tailscale Serve;
- the **unified VeraMesh runtime host** under `unified/`, which packages separate Edge, Relay, Gateway, and DSM-control roles in one DSM package. Relay and Gateway are bundled but disabled by default, and WorkBridge remains external on Lappy.

## Safety and authority boundary

The NAS does not become Vera's workstation authority merely because this source is present. VeraPort TLS/authentication remains end-to-end, controller credentials are not terminated by the edge package, and public/LAN exposure or autonomous pairing is not implied.

Repository source, green package tests, an installed SPK, an active DSM service, and a qualified live route are separate states. This repository establishes source/package behavior only unless runtime evidence says otherwise.

## Implemented source surfaces

The current tree includes:

- DSM-native lower-privilege Package Center lifecycle;
- bounded DS216 readiness policy;
- loopback-only VeraPort edge proxy;
- lifecycle and state-recovery tests;
- SPK build and verification tooling;
- the unified runtime-host package and component bindings;
- guarded standalone-VeraRelay adoption support with rollback and reload-generation checks.

See `unified/README.md` for the unified package revision history and `docs/TOOLKIT_QUALIFICATION.md` for source/toolkit qualification notes.

## Currentness

Treat `main` as the canonical repository source. Do not infer NAS installation, service activation, durable relay operation, credentials, or network exposure from repository state alone.
