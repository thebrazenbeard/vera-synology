#!/bin/sh
set -eu

ROOT=/var/packages/WorkBridgeMedia
VAR="$ROOT/var"
TUNNEL="$ROOT/target/bin/tunnel-client-runtime"
WORKBRIDGE="$ROOT/target/bin/workbridge-mcp"
CONFIG="$VAR/workbridge-media.json"
TUNNEL_ID_FILE="$VAR/tunnel-id"
API_KEY_FILE="$VAR/runtime-api-key"
MEDIA_ROOT="$ROOT/shares/Media/Library"

fail() {
    printf '%s\n' "WorkBridgeMedia runtime: $*" >&2
    exit 78
}

[ -x "$TUNNEL" ] || fail "tunnel-client-runtime missing"
[ -x "$WORKBRIDGE" ] || fail "workbridge-mcp missing"
[ -r "$CONFIG" ] || fail "WorkBridge config missing"
[ -r "$TUNNEL_ID_FILE" ] || fail "tunnel ID file missing"
[ -r "$API_KEY_FILE" ] || fail "runtime API key file missing"
[ -d "$MEDIA_ROOT" ] || fail "Media Library share unavailable"

TUNNEL_ID=$(cat "$TUNNEL_ID_FILE")
printf '%s' "$TUNNEL_ID" | grep -Eq '^tunnel_[a-z0-9]{32}$' || fail "invalid tunnel ID file"

MCP_COMMAND="command=$WORKBRIDGE --config $CONFIG,channel=main"

exec "$TUNNEL" run \
    --control-plane.tunnel-id "$TUNNEL_ID" \
    --control-plane.api-key "file:$API_KEY_FILE" \
    --mcp.command "$MCP_COMMAND" \
    --health.listen-addr "127.0.0.1:17448"
