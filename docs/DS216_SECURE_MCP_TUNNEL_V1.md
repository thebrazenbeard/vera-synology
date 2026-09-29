# DS216 Secure MCP Tunnel V1

Status: ARMV7 QUALIFICATION FRONTIER / NOT INSTALLED

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
3. cross-builds `./cmd/runtime` with `CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7`;
4. requires a 32-bit ARM statically linked ELF;
5. records Go build metadata and SHA-256;
6. uploads the ARMv7 runtime binary only after those checks pass.

## Package integration only after ARMv7 PASS

If qualification passes, the successor SPK should:

- request DSM package-user access to the existing `Media` share;
- expose only the known library root `/Media/Library` to WorkBridge;
- configure WorkBridge in write-capable mode for governed rename operations;
- keep WorkBridge loopback-only;
- run the official tunnel client runtime as an outbound-only daemon;
- keep tunnel ID and runtime API key in protected DSM package state, never source or the SPK;
- verify WorkBridge readiness before declaring tunnel readiness;
- create no inbound NAS firewall/public reverse-proxy requirement.

## Current media evidence

Read-only DSM/File Station inspection established that the Windows media mapping corresponds to the DSM `Media` share and the library is under `/Media/Library`. A nested `/Media/Library/Library` folder also exists and still requires a direct filesystem inventory to determine whether it is intentional or part of the naming/layout problem.

## Claim ceiling

A green ARMv7 workflow proves source/build compatibility for the exact tunnel-client subject only. It does not prove installation on DSM, tunnel credentials, ChatGPT connector binding, WorkBridge share permissions, media inventory, or any file rename effect.
