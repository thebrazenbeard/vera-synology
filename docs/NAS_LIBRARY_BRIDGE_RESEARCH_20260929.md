# NAS Library Bridge and SSH Operator Plane Research — 2026-09-29

Status: RESEARCHED / DESIGN CANDIDATE / NO PACKAGE OR RUNTIME EFFECT

## Problem

The user wants:
1. direct, governed access to the media library physically hosted on the DS216;
2. eventual safe filename normalization and Mediaphile ingestion;
3. clean SSH administration paths to both Lappy and the DS216;
4. reuse of VeraMesh, VeraRelay, and WorkBridgeMCP where they already fit.

The current Windows Z:\Library path is a mapped-drive view and is not a good canonical execution target for a Windows service. The DS216 is the storage authority.

## Exact source subjects inspected

- vera-synology main: d13cdefbf817aeba60c673fa4a517575c311da2c
- WorkBridgeMCP main: 8707a2e1eaf7de5ce2316567b5e6f1e805c0537b
- vera-mesh current inspected main: 98b74ff77981a5478e20a748bbb94565ad9140c8

The unified VeraMesh package already separates Edge, Relay, Gateway, and DSM control.
The VeraMesh Gateway already has a first-class WorkBridge upstream client and preserves the outer VeraMesh capability ceiling.

## Findings

### 1. Do not invent a new filesystem engine inside VeraMesh

Bounded WorkBridgeMCP already provides the right primitive:
- explicit read_roots and write_roots;
- Go os.Root-based rooted filesystem operations;
- bounded directory listings and file reads;
- write/process tools absent unless configured;
- loopback-only HTTP with bearer authentication;
- no shell insertion in bounded process mode.

The DesktopCommander duplicate mode is intentionally unrestricted and should not be the NAS library engine.

### 2. ARMv7 is technically viable

The DS216 evidence identifies Linux armv7l with kernel 3.10.108.
WorkBridgeMCP is Go 1.25.12 source.
Go supports linux/arm GOARM=7, and current Go Linux minimum kernel requirements are below 3.10 for ARM.
A candidate build should therefore use CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 and must still receive native-DS216 runtime qualification before installation is called successful.

### 3. DSM share access should remain lower privilege

DSM 7 requires packages to run as package users rather than system/root and provides resource workers for privileged resource grants.
The data-share resource can give a package user read-only or read/write permission to a named shared folder.
On DSM 7.0-41201+, Package Center creates /var/packages/<package>/shares/<share> symlinks to admitted shares.

Important limitation: data-share creates the named shared folder if it does not already exist and is not an updatable resource.
Therefore we must not hard-code a share named Library until the actual Z: mapping is established. Z:\Library may be a subdirectory of another share.

### 4. VeraMesh Gateway already composes with WorkBridge

vera-mesh gateway code already supports an optional VERAMESH_WORKBRIDGE_UPSTREAM_V1 configuration.
It maps WorkBridge workspace list/stat/read/write/mkdir into VeraMesh public tools while preserving VeraMesh's existing public policy ceiling.
WorkBridge is therefore an implementation backend, not a second authority layer.

This makes the strongest candidate composition:

ChatGPT / authorized MCP client
    -> VeraMesh authenticated Gateway
    -> loopback WorkBridgeMCP
    -> DSM package-user read root
    -> exact admitted media share/subdirectory

Lappy VeraPort remains a separate workstation backend.

### 5. Read and rename authority should be separate

Initial NAS WorkBridge profile:
- read_roots: exact library root only;
- write_roots: empty;
- process.enabled: false.

Inventory and identity resolution happen under this read-only profile.

Renaming should not be enabled by merely populating write_roots. The media workflow needs a narrower move/rename operation that can enforce:
- prevalidated source and destination;
- collision detection;
- plan/item identity;
- optional source version/stat precondition;
- append-only rename receipt;
- no cross-root movement.

That operation should be added to bounded WorkBridge only after the Mediaphile rename-plan contract is finalized.

## SSH operator plane

SSH is not an MCP transport replacement and should not be hidden inside VeraMesh.

### Lappy

Use Microsoft's in-box OpenSSH Server.
Candidate hardened profile:
- public-key authentication;
- explicit allowed user/group;
- PowerShell as default shell if desired;
- password authentication disabled only after key login is proven;
- Windows Firewall limited to the intended LAN/tailnet source range rather than broad Internet exposure.

### DS216

Use DSM's supported SSH service.
DSM SSH login is for local administrators; root escalation should remain sudo -i when needed.
Public-key login is supported.

Tailscale SSH itself is not supported on Synology, but ordinary DSM SSH can be reached over the NAS's Tailscale address when normal network/firewall policy permits it.

The SPK should not modify DSM sshd, install another SSH daemon, or own SSH keys.

## Alternatives rejected or held

### Dedicated library SPK

Pros: separate failure domain and package identity.
Cons: duplicates WorkBridge runtime/transport mechanics and creates an additional secret/config lifecycle.
Held unless unified VeraMesh integration proves operationally awkward.

### Native Python library server inside VeraMesh

Rejected as first choice because it would duplicate WorkBridge confinement, limits, and MCP semantics.

### DesktopCommander on NAS

Rejected for this use because its intentionally unrestricted shell surface is wider than the library task requires.

### Direct root-level /volume1 crawler

Rejected. It violates DSM 7 lower-privilege design and grants materially broader authority than required.

## Hostile review

> Packaging WorkBridge inside VeraMesh does not itself solve access. The actual shared-folder identity and DSM package-user permission must be established first. A technically correct ARM binary pointed at the wrong share is still the wrong system.

> The existing WorkBridge write surface is not yet adequate for bulk media renaming. Atomic text write and mkdir do not provide a governed rename transaction. Adding generic process execution merely to call mv would widen authority unnecessarily.

> VeraMesh Gateway integration is source-supported, but deployed Gateway/OAuth/reverse-proxy configuration is a separate runtime subject. Do not infer a usable ChatGPT NAS connector merely from bundling the binary.

## Recommended sequence

R0 — Establish Z: mapping using standard SSH/operator inspection or another authoritative Windows/NAS readback.

R1 — Prove WorkBridgeMCP cross-build for linux/arm GOARM=7 and run its unit tests plus an ARM artifact inspection.

R2 — Add a read-only WorkBridge module/profile to the unified VeraMesh SPK, bound only to the established DSM shared-folder resource or package-local share symlink.

R3 — Qualify the package on the DS216: package user identity, share traversal, symlink/root confinement, list/stat/read behavior, restart persistence, and Gateway->WorkBridge loopback composition.

R4 — Connect the NAS-side MCP route through the reviewed VeraMesh Gateway/auth surface.

R5 — Run Mediaphile read-only inventory.

R6 — Design and hostile-review a dedicated governed rename operation before enabling any filesystem mutation.

## Claim ceiling

This document establishes a preferred design from source inspection and official platform documentation.
It does not establish the actual Z: mapping, a successful ARMv7 WorkBridge build, an installed SPK, DSM share permission, an active Gateway, SSH configuration, or live media-library access.
