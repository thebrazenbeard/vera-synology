#!/bin/sh
set -eu
R=/var/packages/VeraMesh; V="$R/var/gateway"; B="$R/target/bin/veramesh-gateway"
fail(){ echo "VeraMesh gateway: $*" >&2; exit 78; }
[ -x "$B" ]||fail "binary missing"; [ -r "$V/controller.json" ]||fail "controller config missing"; [ -r "$V/oauth.json" ]||fail "oauth config missing"; [ -r "$V/oauth-client-secret" ]||fail "oauth secret missing"
VERAMESH_OAUTH_CLIENT_SECRET=$(cat "$V/oauth-client-secret"); [ -n "$VERAMESH_OAUTH_CLIENT_SECRET" ]||fail "oauth secret empty"; export VERAMESH_OAUTH_CLIENT_SECRET
exec "$B" -listen 127.0.0.1:17446 -controller-config "$V/controller.json" -oauth-config "$V/oauth.json"
