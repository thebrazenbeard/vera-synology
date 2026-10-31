# Vera Synology — VeraMesh packages for Synology DSM

**A source-visible DSM package toolkit for a bounded VeraMesh network edge and an optional multi-component runtime host.**

Vera Synology contains package metadata, lower-privilege lifecycle scripts, Python edge/runtime code, deterministic SPK build and verification tools, and source-level regression tests. The package sources target **Synology DSM 7.2 or later (minimum build 72806)** on the declared **`armada38x`** architecture. They are reusable as a packaging reference and for private evaluation under the repository's license; they are **not** a generic DSM package for every architecture or evidence of installation on a particular NAS.

There are two related products in this repository:

| Source | Version / intended role | Status in `main` |
| --- | --- | --- |
| [Live edge package](spk/INFO) | `0.1.0-0017` — bounded, loopback-only VeraPort TCP forwarding | Package source, deterministic builder/verifier and lifecycle tests present |
| [Unified runtime host](unified/spk/INFO) | `0.2.0-0008` — Edge, Relay, Gateway and DSM-control roles in one package | Component bindings, supervisor, package builder/verifier and guarded adoption source present; additional qualified external artifacts required to build |

The unified design starts with Edge required and enabled; **Relay and Gateway are disabled by default**. The DSM-control utility is bundled as a utility, not treated as an independently authenticated management authority.

## What the source implements

- A Synology Package Center lifecycle with a dedicated package user, fail-closed state checks, bounded startup readiness, and controlled recovery paths.
- A VeraPort edge that validates a private configuration file, requires its listener host to be `127.0.0.1`, and forwards bounded TCP bytes without terminating the controller's end-to-end VeraPort authentication.
- Deterministic legacy SPK construction from an exact Git source snapshot, source-manifest checking, and verification of the resulting package structure.
- A unified supervisor with per-module enablement, status records, SIGHUP reload generation, and recovery and rollback handling for optional Relay adoption.
- Tests for metadata, proxy behavior, framing, lifecycle, state recovery, source custody and package qualification contracts.

The [legacy edge implementation](payload/bin/veramesh_edge.py) is **not** a durable store-and-forward relay. The [unified module defaults](unified/payload/bin/veramesh_runtime_init.py) preserve Edge-only activation until a separately authorized operator changes configuration. An enabled component in a local configuration file is not proof of a healthy remote route.

## Build and inspect the edge SPK

From a clean checkout with **Git and Python 3.11+**:

```sh
python3 -B -m unittest discover -s tests -q
python3 -B tools/build_spk.py
python3 -B tools/verify_spk.py dist/VeraMesh-0.1.0-0017-live-edge.spk
```

The builder writes `dist/VeraMesh-0.1.0-0017-live-edge.spk`. It rejects unexpected source paths, symlinks and changes that do not match exact Git `HEAD`; run it on a clean committed tree. The verifier checks package structure, provenance and metadata. **Passing either command qualifies a source/package artifact, not a DSM install, running service, reachable tunnel or authenticated controller connection.**

Some socket-based regression tests need permission to bind temporary local Unix sockets. The test suite is intended for a normal isolated development environment; environment restrictions can prevent those tests from exercising their fixtures.

## Unified package — externally qualified components

The [unified source](unified/) supplies `build_unified_spk.py` and `verify_unified_spk.py`, but the build requires separately obtained, compatible **Gateway and DSM-control executable artifacts** and a **Relay source tree**. Their identities and the component revisions are constrained by [component bindings](unified/component-bindings.json), not selected by an arbitrary machine name.

With those qualified artifacts available, the command shape is:

```sh
python3 unified/tools/build_unified_spk.py \
  --gateway-bin /path/to/qualified-gateway \
  --dsmctl-bin /path/to/qualified-dsmctl \
  --relay-dir /path/to/qualified-relay-tree \
  --source-head YOUR_VERIFIED_SOURCE_COMMIT
python3 unified/tools/verify_unified_spk.py \
  dist/VeraMesh-0.2.0-0008-unified-runtime.spk
```

Those paths are placeholders, not shipped binaries. The unified verifier checks expected package members, executable architecture and exact component/provenance bindings. See the [unified revision record](unified/README.md) for lifecycle and adoption changes. A locally built unified SPK does not imply that Relay, Gateway, or any workstation integration has been activated.

## Deployment and authority boundaries

**Installation is a separate, operator-controlled step.** The repository does not install packages, enroll devices, provision credentials, configure Tailscale, or modify a NAS when its tests or build commands run. Actual DSM version/CPU compatibility, package-user permissions, Package Center lifecycle, socket binding, and end-to-end authenticated traffic must be checked on the exact target before a deployment can be called qualified.

The edge listener is loopback-only by design. Tailnet-only exposure would require a separately configured and verified ingress mechanism; no Funnel/public internet exposure is authorized or implied by this repository. Opaque byte forwarding preserves the protocol's location of authentication, but does **not** independently authenticate a provider, authorize an external effect, or grant host-owned immutable authority to an AI model.

The [toolkit qualification boundary](docs/TOOLKIT_QUALIFICATION.md) records a historical device-class acceptance plan. Treat named hardware and workstation examples there as **test provenance**, not generic installation requirements or proof that this `main` commit is installed anywhere.

## Licensing and contributions

This is **source-visible proprietary software, not open source**. [LICENSE](LICENSE) permits limited private, noncommercial evaluation and reserves redistribution, commercial deployment and hosted-use rights; [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) describes separate permissions. Third-party material retains its own terms (see [NOTICE](NOTICE) and the [bundled DSM-control license notice](unified/third_party/dsmctl-LICENSE)).

Contributors should read [CONTRIBUTING.md](CONTRIBUTING.md) and [CLA.md](CLA.md). Publication, modified distribution or use of contributed material requires respecting those terms; repository access alone does not grant permission to redistribute the SPKs.
