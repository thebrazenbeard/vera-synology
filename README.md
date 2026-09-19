# VeraMesh Synology DS216 Live Edge V16

V16 turns the prior DSM scaffold into a real, deliberately narrow VeraPort edge.

The package runs as the DSM package user and binds a transparent TCP proxy only to loopback. Tailscale Serve is configured separately at deployment to provide tailnet-only ingress. The NAS does not terminate VeraPort TLS, does not hold VeraPort controller credentials, and does not authorize workstation operations.

Current semantic state: LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED.

Implemented:
- DSM-native lower-privilege Package Center lifecycle;
- bounded DS216 readiness policy;
- loopback-only live TCP edge proxy;
- end-to-end VeraPort TLS/authentication preservation;
- lifecycle-bound private Unix status socket.

Not implemented:
- durable store-and-forward relay;
- NAS-side VeraPort credential termination;
- public/LAN edge exposure;
- autonomous pairing or authorization.
