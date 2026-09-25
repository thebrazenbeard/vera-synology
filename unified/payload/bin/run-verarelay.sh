#!/bin/sh
set -eu
RELAY=/var/packages/VeraMesh/target/relay
VERA_RELAY_VAR=/var/packages/VeraMesh/var/relay
export VERA_RELAY_VAR

for NODE in \
  /var/packages/Node.js_v22/target/usr/local/bin/node \
  /var/packages/Node.js_v22/target/bin/node \
  /usr/local/bin/node \
  /usr/bin/node
do
  if [ -x "$NODE" ]; then
    break
  fi
  NODE=""
done

[ -n "$NODE" ] || { echo "VeraRelay: Node.js 22 missing" >&2; exit 78; }
[ -f "$RELAY/src/runtime.js" ] || { echo "VeraRelay: source-bound runtime entrypoint missing" >&2; exit 78; }
mkdir -p "$VERA_RELAY_VAR"
chmod 700 "$VERA_RELAY_VAR"
cd "$RELAY"
exec "$NODE" src/runtime.js
