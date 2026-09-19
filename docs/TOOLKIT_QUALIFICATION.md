# DS216 V16 live-edge qualification boundary

V16 is a live-edge successor to the earlier scaffold.

Local/source qualification must prove deterministic packaging, closed metadata, loopback-only listener policy, transparent byte forwarding, end-to-end VeraPort authentication preservation, and truthful non-claim of durable relay.

Target qualification on the exact DS216/DSM 7.2.2 build must then prove:
1. Package Center accepts the exact SPK and python311 dependency.
2. Package starts/stops through DSM lifecycle with bounded readiness and exact responder binding.
3. Edge configuration is private package-owned mode 0600.
4. Data listener binds only to 127.0.0.1.
5. Tailscale Serve exposes the edge tailnet-only, with Funnel/public exposure absent.
6. A VeraPort controller can connect through DS216 edge to Lappy and complete an authenticated file round-trip.
7. Direct Lappy path remains independent of the edge.
8. Durable relay remains explicitly NOT_IMPLEMENTED.

Installation/deployment evidence is separate from source/build evidence.
