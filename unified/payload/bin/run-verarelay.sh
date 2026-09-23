#!/bin/sh
set -eu
R=/var/packages/VeraMesh/target/relay
for N in /var/packages/Node.js_v22/target/usr/local/bin/node /var/packages/Node.js_v22/target/bin/node /usr/local/bin/node /usr/bin/node;do [ -x "$N" ]&&break;N="";done
[ -n "$N" ]||{ echo "VeraRelay: Node.js 22 missing" >&2;exit 78;};cd "$R";[ -f package.json ]||exit 78
M=$("$N" -e 'const p=require("./package.json");process.stdout.write(typeof p.main==="string"?p.main:"")')
if [ -n "$M" ]&&[ -f "$M" ];then exec "$N" "$M";fi
for M in server.js index.js src/server.js src/index.js;do [ -f "$M" ]&&exec "$N" "$M";done
echo "VeraRelay: no qualified runtime entrypoint; keep module disabled" >&2;exit 78
