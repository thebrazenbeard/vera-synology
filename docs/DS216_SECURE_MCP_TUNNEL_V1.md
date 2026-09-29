# DS216 Secure MCP Tunnel V1

Status: ARMV7 DERIVATIVE QUALIFIED / STANDALONE SPK QUALIFIED / NOT INSTALLED

Goal: connect ChatGPT directly to a bounded WorkBridge MCP server on the DS216 without QuickConnect automation, an inbound NAS port, or the Windows Z: mapping.

Target path:

```text
ChatGPT
  -> OpenAI Secure MCP Tunnel
  -> tunnel-client-runtime on DS216
  -> loopback WorkBridge MCP
  -> /Media/Library
```

## Exact OpenAI tunnel subject

- repository: `openai/tunnel-client`
- release: `v0.0.15`
- source commit: `a390c168ff1b2d14e73a95991c186c6aba3ff5a0`
- license: Apache-2.0

OpenAI publishes amd64/arm64 release binaries but no ARMv7 release artifact. The DS216 path therefore requires an explicit source-build qualification rather than treating ARM64 availability as ARMv7 support.

## Current qualification

The workflow `ds216-secure-mcp-tunnel-armv7.yml`:

1. checks out the exact v0.0.15 source commit;
2. runs `go mod verify` and the native upstream test suite;
3. applies the exact six-line word-size portability transformation and reruns upstream tests;
4. cross-builds `./cmd/client-runtime` with `CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7`;
5. requires a 32-bit ARM statically linked ELF;
6. records Go build metadata and SHA-256;
7. uploads the ARMv7 runtime binary only after those checks pass.

## Standalone package qualification

ARMv7 qualification passed. The successor `WorkBridgeMedia` package is implemented on PR #11 and:

- requests DSM package-user read/write access only to the existing `Media` share;
- exposes only `/var/packages/WorkBridgeMedia/shares/Media/Library` to WorkBridge;
- disables WorkBridge process execution;
- runs WorkBridge as a stdio child of the outbound Secure MCP Tunnel runtime;
- collects tunnel ID/runtime key through the DSM install wizard and stores them mode-0600;
- preserves existing credentials on upgrade when wizard fields are empty;
- uses complete DSM lifecycle scripts and package icons;
- creates no inbound NAS firewall/public reverse-proxy requirement.

Exact PR #11 head at qualification: `532baa103d360dd14caca7394bf0e416f3b29b23`.

All three exact-head workflows passed:
- WorkBridge Media SPK validation — PASS;
- Scaffold validation — PASS;
- Unified Vera Runtime SPK — PASS.

Qualified SPK:
- `WorkBridgeMedia-0.1.0-0001-armada38x.spk`
- size: `13189120` bytes
- SPK SHA-256: `72da8543c8d22fe86b19610d841b8e8c7e9337293dc6ea434ec2ec3b966230a0`
- GitHub Actions artifact ID: `11055795215`
- artifact ZIP digest: `sha256:14df3b89e4367acac97ae3731db4103ce7cc60db89764f50c9c1600ec9b7f58a`.

## Current media evidence

Read-only DSM/File Station inspection established that the Windows media mapping corresponds to the DSM `Media` share and the library is under `/Media/Library`. A nested `/Media/Library/Library` folder also exists and still requires a direct filesystem inventory to determine whether it is intentional or part of the naming/layout problem.

## Claim ceiling

Source/build/package qualification is green. It does not prove `WorkBridgeMedia` is installed or running on the DS216, that tunnel credentials have been provisioned, that ChatGPT is connected to the NAS package, or that any media rename has occurred.

The immediate Mediaphile job can continue through WorkBridge Commander direct UNC access without waiting for this package.

## Reviewed ARMv7 source patch

The unmodified v0.0.15 source passes its native test suite but fails to compile
for 32-bit ARM because six compile-time nonnegative assertions cast
`time.Duration`-sized constants through machine-word `uint`.

The derivative transformation
`tools/patch_openai_tunnel_client_armv7.py` changes only those six assertion
casts from `uint` to `uint64`, and refuses to run if the exact pinned source
does not contain the expected six-line subject.

This preserves the original fail-at-compile-time behavior for negative
relationships while removing an accidental 32-bit word-size ceiling. CI requires the transformation to touch exactly one file with exactly six
additions and six deletions, then reruns the complete upstream Go test suite
before attempting the ARMv7 build.

This is a local portability derivative. It is not a claim that OpenAI
officially supports ARMv7.
