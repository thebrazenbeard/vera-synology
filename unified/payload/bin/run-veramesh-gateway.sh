#!/bin/sh
set -eu
R=/var/packages/VeraMesh
V="$R/var/gateway"
B="$R/target/bin/veramesh-gateway"
W="$R/var/workbridge"
WB="$R/target/bin/workbridge-mcp"
P=/var/packages/python311/target/bin/python3.11
fail(){ echo "VeraMesh gateway: $*" >&2; exit 78; }

[ -x "$B" ]||fail "gateway binary missing"
[ -r "$V/controller.json" ]||fail "controller config missing"
[ -r "$V/oauth.json" ]||fail "oauth config missing"
[ -r "$V/oauth-client-secret" ]||fail "oauth secret missing"
VERAMESH_OAUTH_CLIENT_SECRET=$(cat "$V/oauth-client-secret")
[ -n "$VERAMESH_OAUTH_CLIENT_SECRET" ]||fail "oauth secret empty"
export VERAMESH_OAUTH_CLIENT_SECRET

if [ ! -e "$W/config.json" ] && [ ! -e "$V/workbridge.json" ] && [ ! -e "$W/bearer-token" ]; then
  exec "$B" -listen 127.0.0.1:17446 -controller-config "$V/controller.json" -oauth-config "$V/oauth.json"
fi

[ -x "$WB" ]||fail "WorkBridge binary missing"
[ -r "$W/config.json" ]||fail "partial WorkBridge configuration: config missing"
[ -r "$V/workbridge.json" ]||fail "partial WorkBridge configuration: gateway upstream missing"
[ -r "$W/bearer-token" ]||fail "partial WorkBridge configuration: bearer token missing"
VERAMESH_WORKBRIDGE_TOKEN=$(cat "$W/bearer-token")
[ -n "$VERAMESH_WORKBRIDGE_TOKEN" ]||fail "WorkBridge bearer token empty"
export VERAMESH_WORKBRIDGE_TOKEN

"$WB" --transport http --config "$W/config.json" &
WB_PID=$!
GW_PID=""
cleanup(){
  if [ -n "$GW_PID" ]; then kill "$GW_PID" 2>/dev/null || true; fi
  kill "$WB_PID" 2>/dev/null || true
  if [ -n "$GW_PID" ]; then wait "$GW_PID" 2>/dev/null || true; fi
  wait "$WB_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

READY=0;i=0
while [ "$i" -lt 50 ]; do
  if ! kill -0 "$WB_PID" 2>/dev/null; then fail "WorkBridge exited during startup"; fi
  if "$P" -c 'import socket; s=socket.socket(); s.settimeout(.2); r=s.connect_ex(("127.0.0.1",17447)); s.close(); raise SystemExit(0 if r==0 else 1)' >/dev/null 2>&1; then READY=1;break; fi
  i=$((i+1));sleep 0.1
done
[ "$READY" -eq 1 ]||fail "WorkBridge loopback listener did not become ready"

"$B" -listen 127.0.0.1:17446 -controller-config "$V/controller.json" -oauth-config "$V/oauth.json" -workbridge-config "$V/workbridge.json" &
GW_PID=$!
set +e
wait "$GW_PID";RC=$?
set -e
GW_PID=""
exit "$RC"
