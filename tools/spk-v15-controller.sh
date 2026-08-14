#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  qualify|publish) ;;
  *) printf '%s\n' "usage: $0 qualify|publish" >&2; exit 2 ;;
esac

REPO="thebrazenbeard/vera-synology"
QUALIFY_REF="refs/heads/controller/spk-v15-qualify-v1"
ACTIVATION_PREFIX="refs/heads/controller/spk-v15-publish-activation-"
ACTIVATION_REPO_PATH="spk-v15-activation.json"
ACTIVATION_PATH="controller/$ACTIVATION_REPO_PATH"
CONSUMED_PREFIX="refs/heads/controller/spk-v15-consumed-"
CONSUMED_REPO_PATH="spk-v15-consumed.json"
CONSUMED_PATH="controller/$CONSUMED_REPO_PATH"
GITHUB_API_VERSION="2026-03-10"
PUBLISH_ENVIRONMENT="bt2-synology-v15-publish"
PUBLISH_REVIEWER_LOGIN="thebrazenbeard"
PUBLISH_REVIEWER_ID="234958733"
MARKER_EPOCH="1786579200"
REPAIR_REF="refs/heads/repair/ds216-target-first-spk-v2"
REPAIR_BASE="c5935b4de032dbe0d02737ee03d1f36216a6d1c5"
REPAIR_BASE_TREE="4daa35d603296378d38beb0b358313370e3da62b"
CUSTODY_HEAD="5e8dd4aa41f6d4b8b5d3abd0aa090b0eab223a19"
CUSTODY_TREE="bb807c9cc154f59a868b2ae05b7c110b8c6b329f"
DONOR_BYTES="62827"
DONOR_SHA256="0bbab931e7ed5836917dee72b80fe68295ee8182aa08bc0a00250bcb11f442d5"
DONOR_BLOB="1640a4c4ab46f8933d0e3530921193897af8b31c"
MANIFEST_BYTES="4403"
MANIFEST_SHA256="f07ba02bb67b64e2b07ae741943ec50324261a022c5e54c9a73d2547b49db81d"
MANIFEST_BLOB="c9305e83b1b0feb89a390bf48c5a26529d870043"
EXPECTED_TREE="88a03ab666e7b9e0e7f09bb914a8b48549788694"
EXPECTED_COMMIT="37d1437f293537efe6bdbe8029da6e6888dccdba"
COMMIT_EPOCH="1786579200"
COMMIT_MESSAGE="Publish exact V15 Synology icon candidate"
EXPECTED_SPK_SHA256="8c633875d0ad6c462d17f90c9d33991fec65229eab52930a7c01a1eb97450b7d"
SPK_PATH="dist/VeraMesh-0.0.1-0002-reconstructed-scaffold.spk"

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

http_failure_rc() {
  local code="$1" headers="$2"
  case "$code" in
    408|425|429|5??)
      printf '%s\n' 2
      return 0
      ;;
    403)
      if python3 - "$headers" <<'PYHTTP'
import re, sys
from pathlib import Path
raw=Path(sys.argv[1]).read_text(encoding="iso-8859-1", errors="replace")
blocks=[b for b in re.split(r"\r?\n\r?\n", raw) if b.lstrip().startswith("HTTP/")]
if not blocks:
    raise SystemExit(1)
last=blocks[-1]
headers={}
for line in last.splitlines()[1:]:
    if ":" not in line:
        continue
    k,v=line.split(":",1)
    headers[k.strip().lower()]=v.strip()
retry_after=headers.get("retry-after", "")
remaining=headers.get("x-ratelimit-remaining", "")
if retry_after or remaining == "0":
    raise SystemExit(0)
raise SystemExit(1)
PYHTTP
      then
        printf '%s\n' 2
      else
        printf '%s\n' 1
      fi
      return 0
      ;;
    *)
      printf '%s\n' 1
      return 0
      ;;
  esac
}

remote_state_git() {
  local dir="$1" ref="$2" out rc lines sha
  if out="$(git -C "$dir" ls-remote --refs origin "$ref" 2>/dev/null)"; then
    rc=0
  else
    rc=$?
  fi
  test "$rc" -eq 0 || return 2
  if test -z "$out"; then
    printf '%s\n' "ABSENT"
    return 0
  fi
  lines="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  test "$lines" = "1" || return 2
  sha="$(printf '%s\n' "$out" | awk 'NR==1 {print $1}')"
  printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{40}$' || return 2
  printf 'SHA:%s\n' "$sha"
}

remote_state_rest() {
  local ref="$1" api_ref body http_code state rc
  api_ref="$(
    python3 - "$ref" <<'PY'
from urllib.parse import quote
import sys
ref = sys.argv[1]
if not ref.startswith("refs/"):
    raise SystemExit(1)
print(quote(ref[5:], safe="/-._"))
PY
  )" || return 2
  body="$(mktemp)"
  if http_code="$(
    curl --silent --show-error --location \
      --output "$body" \
      --write-out '%{http_code}' \
      --header 'Accept: application/vnd.github+json' \
      --header "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
      "https://api.github.com/repos/$REPO/git/ref/$api_ref"
  )"; then
    rc=0
  else
    rc=$?
  fi
  if test "$rc" -ne 0; then
    rm -f "$body"
    return 2
  fi
  if test "$http_code" = "404"; then
    rm -f "$body"
    printf '%s\n' "ABSENT"
    return 0
  fi
  if test "$http_code" != "200"; then
    rm -f "$body"
    return 2
  fi
  state="$(python3 - "$body" <<'PY'
import json, re, sys
from pathlib import Path
obj=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sha=((obj.get("object") or {}).get("sha"))
if not isinstance(sha,str) or not re.fullmatch(r"[0-9a-f]{40}",sha):
    raise SystemExit(1)
print("SHA:"+sha)
PY
  )" || { rm -f "$body"; return 2; }
  rm -f "$body"
  printf '%s\n' "$state"
}

environment_identity_from_json() {
  local input="$1"
  python3 - "$input" "$PUBLISH_ENVIRONMENT" "$PUBLISH_REVIEWER_LOGIN" "$PUBLISH_REVIEWER_ID" <<'PYENV'
import hashlib, json, sys
from pathlib import Path
path, expected_name, expected_login, expected_id = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
obj=json.loads(Path(path).read_text(encoding="utf-8"))
if obj.get("name") != expected_name:
    raise SystemExit(1)
rules=obj.get("protection_rules")
if not isinstance(rules,list):
    raise SystemExit(1)
required=[r for r in rules if isinstance(r,dict) and r.get("type")=="required_reviewers"]
if len(required)!=1:
    raise SystemExit(1)
rule=required[0]
reviewers=rule.get("reviewers")
if not isinstance(reviewers,list) or len(reviewers)!=1:
    raise SystemExit(1)
entry=reviewers[0]
reviewer=(entry or {}).get("reviewer") or {}
if entry.get("type") != "User" or reviewer.get("login") != expected_login or reviewer.get("id") != expected_id:
    raise SystemExit(1)
if rule.get("prevent_self_review") is not False:
    raise SystemExit(1)
projection={k:obj.get(k) for k in ("id","node_id","name","url","html_url","created_at","updated_at")}
if not isinstance(projection["id"],int) or projection["id"] <= 0:
    raise SystemExit(1)
for key in ("node_id","name","url","html_url","created_at","updated_at"):
    if not isinstance(projection[key],str) or not projection[key]:
        raise SystemExit(1)
canon=json.dumps(projection,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
envelope={
    "sha256": hashlib.sha256(canon).hexdigest(),
    "id": projection["id"],
    "node_id": projection["node_id"],
    "name": projection["name"],
}
print(json.dumps(envelope,sort_keys=True,separators=(",",":"),ensure_ascii=False))
PYENV
}

environment_specific_read() {
  local body headers code identity http_rc
  body="$(mktemp)"; headers="$(mktemp)"
  if ! code="$(curl --silent --show-error --location --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
    "https://api.github.com/repos/$REPO/environments/$PUBLISH_ENVIRONMENT")"; then
    rm -f "$body" "$headers"
    return 2
  fi
  if test "$code" != "200"; then
    http_rc="$(http_failure_rc "$code" "$headers")" || { rm -f "$body" "$headers"; return 1; }
    rm -f "$body" "$headers"
    return "$http_rc"
  fi
  if ! identity="$(environment_identity_from_json "$body")"; then
    rm -f "$body" "$headers"
    return 1
  fi
  rm -f "$body" "$headers"
  printf '%s\n' "$identity"
}

environment_list_read() {
  local body headers code extracted identity http_rc
  body="$(mktemp)"; headers="$(mktemp)"; extracted="$(mktemp)"
  if ! code="$(curl --silent --show-error --location --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
    "https://api.github.com/repos/$REPO/environments?per_page=100")"; then
    rm -f "$body" "$headers" "$extracted"
    return 2
  fi
  if test "$code" != "200"; then
    http_rc="$(http_failure_rc "$code" "$headers")" || { rm -f "$body" "$headers" "$extracted"; return 1; }
    rm -f "$body" "$headers" "$extracted"
    return "$http_rc"
  fi
  if ! python3 - "$body" "$extracted" "$PUBLISH_ENVIRONMENT" <<'PYLIST'
import json, sys
from pathlib import Path
source,out,name=sys.argv[1:]
obj=json.loads(Path(source).read_text(encoding="utf-8"))
matches=[x for x in obj.get("environments",[]) if isinstance(x,dict) and x.get("name")==name]
if len(matches)!=1:
    raise SystemExit(1)
Path(out).write_text(json.dumps(matches[0],sort_keys=True,separators=(",",":")),encoding="utf-8")
PYLIST
  then
    rm -f "$body" "$headers" "$extracted"
    return 1
  fi
  if ! identity="$(environment_identity_from_json "$extracted")"; then
    rm -f "$body" "$headers" "$extracted"
    return 1
  fi
  rm -f "$body" "$headers" "$extracted"
  printf '%s\n' "$identity"
}

verify_environment_gate() {
  local first second alternate first_rc second_rc alternate_rc
  if first="$(environment_specific_read)"; then
    printf '%s\n' "$first"
    return 0
  else
    first_rc=$?
  fi
  test "$first_rc" -eq 2 || die "publication environment exists but required reviewer profile is invalid"

  if second="$(environment_specific_read)"; then
    second_rc=0
  else
    second_rc=$?
  fi
  if test "$second_rc" -eq 1; then
    die "publication environment retry returned deterministic invalid reviewer profile"
  fi

  if alternate="$(environment_list_read)"; then
    alternate_rc=0
  else
    alternate_rc=$?
  fi
  test "$alternate_rc" -eq 0 || die "publication environment alternate read unavailable or invalid"
  if test "$second_rc" -eq 0; then
    test "$second" = "$alternate" || die "publication environment identity disagrees across same-route retry and alternate read"
    printf '%s\n' "$second"
    return 0
  fi
  test "$second_rc" -eq 2 || die "publication environment retry returned unknown state"
  printf '%s\n' "$alternate"
}

approval_history_from_json() {
  local input="$1" expected_environment_identity="$2"
  python3 - "$input" "$PUBLISH_ENVIRONMENT" "$PUBLISH_REVIEWER_LOGIN" "$PUBLISH_REVIEWER_ID" "$expected_environment_identity" <<'PYAPPROVAL'
import hashlib, json, re, sys
from pathlib import Path
path, expected_environment, expected_login, expected_id, expected_environment_envelope = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
expected=json.loads(expected_environment_envelope)
if set(expected) != {"sha256","id","node_id","name"}:
    raise SystemExit(1)
if not isinstance(expected["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",expected["sha256"]):
    raise SystemExit(1)
if not isinstance(expected["id"],int) or expected["id"] <= 0:
    raise SystemExit(1)
if not isinstance(expected["node_id"],str) or not expected["node_id"]:
    raise SystemExit(1)
if expected["name"] != expected_environment:
    raise SystemExit(1)
obj=json.loads(Path(path).read_text(encoding="utf-8"))
if not isinstance(obj,list) or len(obj) != 1:
    raise SystemExit(1)
review=obj[0]
if not isinstance(review,dict) or review.get("state") != "approved":
    raise SystemExit(1)
user=review.get("user") or {}
if user.get("login") != expected_login or user.get("id") != expected_id:
    raise SystemExit(1)
environments=review.get("environments")
if not isinstance(environments,list) or len(environments) != 1:
    raise SystemExit(1)
environment=environments[0]
if not isinstance(environment,dict) or environment.get("name") != expected_environment:
    raise SystemExit(1)
if environment.get("id") != expected["id"] or environment.get("node_id") != expected["node_id"]:
    raise SystemExit(1)
projection={k:environment.get(k) for k in ("id","node_id","name","url","html_url","created_at","updated_at")}
if not isinstance(projection["id"],int) or projection["id"] <= 0:
    raise SystemExit(1)
for key in ("node_id","name","url","html_url","created_at","updated_at"):
    if not isinstance(projection[key],str) or not projection[key]:
        raise SystemExit(1)
canon=json.dumps(projection,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
actual=hashlib.sha256(canon).hexdigest()
if actual != expected["sha256"]:
    raise SystemExit(1)
print("VALID")
PYAPPROVAL
}

approval_history_read() {
  local expected_environment_identity="$1" body headers code http_rc
  test -n "${GITHUB_RUN_ID:-}" || return 1
  printf '%s\n' "$GITHUB_RUN_ID" | grep -Eq '^[1-9][0-9]*$' || return 1
  body="$(mktemp)"; headers="$(mktemp)"
  if ! code="$(curl --silent --show-error --location --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
    --header 'Accept: application/vnd.github+json' \
    --header "X-GitHub-Api-Version: $GITHUB_API_VERSION" \
    "https://api.github.com/repos/$REPO/actions/runs/$GITHUB_RUN_ID/approvals")"; then
    rm -f "$body" "$headers"
    return 2
  fi
  if test "$code" != "200"; then
    http_rc="$(http_failure_rc "$code" "$headers")" || { rm -f "$body" "$headers"; return 1; }
    rm -f "$body" "$headers"
    return "$http_rc"
  fi
  if ! approval_history_from_json "$body" "$expected_environment_identity" >/dev/null; then
    rm -f "$body" "$headers"
    return 1
  fi
  rm -f "$body" "$headers"
  return 0
}

approval_history_graphql_from_json() {
  local input="$1" expected_environment_envelope="$2"
  python3 - "$input" "$PUBLISH_ENVIRONMENT" "$PUBLISH_REVIEWER_LOGIN" "$PUBLISH_REVIEWER_ID" "$GITHUB_RUN_ID" "$expected_environment_envelope" <<'PYGQLAPPROVAL'
import json, sys
from pathlib import Path
path, expected_environment, expected_login, expected_id, expected_run_id, expected_environment_envelope = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
expected=json.loads(expected_environment_envelope)
if set(expected) != {"sha256","id","node_id","name"}:
    raise SystemExit(1)
if expected["name"] != expected_environment:
    raise SystemExit(1)
obj=json.loads(Path(path).read_text(encoding="utf-8"))
if obj.get("errors"):
    raise SystemExit(1)
resource=((obj.get("data") or {}).get("resource"))
if not isinstance(resource,dict) or resource.get("__typename") != "WorkflowRun":
    raise SystemExit(1)
if resource.get("databaseId") != expected_run_id or resource.get("runAttempt") != 1:
    raise SystemExit(1)
reviews=resource.get("deploymentReviews") or {}
if reviews.get("totalCount") != 1:
    raise SystemExit(1)
nodes=reviews.get("nodes")
if not isinstance(nodes,list) or len(nodes) != 1:
    raise SystemExit(1)
review=nodes[0]
if not isinstance(review,dict) or review.get("state") != "APPROVED":
    raise SystemExit(1)
user=review.get("user") or {}
if user.get("login") != expected_login or user.get("databaseId") != expected_id:
    raise SystemExit(1)
environments=review.get("environments") or {}
if environments.get("totalCount") != 1:
    raise SystemExit(1)
enodes=environments.get("nodes")
if not isinstance(enodes,list) or len(enodes) != 1:
    raise SystemExit(1)
environment=enodes[0]
if not isinstance(environment,dict):
    raise SystemExit(1)
if environment.get("name") != expected_environment:
    raise SystemExit(1)
if environment.get("databaseId") != expected["id"] or environment.get("id") != expected["node_id"]:
    raise SystemExit(1)
print("VALID")
PYGQLAPPROVAL
}

approval_history_graphql_read() {
  local expected_environment_envelope="$1" body headers payload code run_url http_rc current_rc
  test -n "${GITHUB_RUN_ID:-}" || return 1
  printf '%s\n' "$GITHUB_RUN_ID" | grep -Eq '^[1-9][0-9]*$' || return 1
  test -n "${GH_PUSH_TOKEN:-}" || return 1
  run_url="https://github.com/$REPO/actions/runs/$GITHUB_RUN_ID"
  if ! payload="$(python3 - "$run_url" <<'PYGQLPAYLOAD'
import json,sys
query="query($url:URI!){resource(url:$url){__typename ... on WorkflowRun{databaseId runAttempt deploymentReviews(first:2){totalCount nodes{state user{login databaseId} environments(first:2){totalCount nodes{id databaseId name}}}}}}}"
print(json.dumps({"query":query,"variables":{"url":sys.argv[1]}},separators=(",",":")))
PYGQLPAYLOAD
  )"; then
    return 1
  fi
  body="$(mktemp)"; headers="$(mktemp)"
  if ! code="$(curl --silent --show-error --location --request POST --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $GH_PUSH_TOKEN" \
    --data "$payload" \
    'https://api.github.com/graphql')"; then
    rm -f "$body" "$headers"
    return 2
  fi
  if test "$code" != "200"; then
    http_rc="$(http_failure_rc "$code" "$headers")" || { rm -f "$body" "$headers"; return 1; }
    rm -f "$body" "$headers"
    return "$http_rc"
  fi
  if ! approval_history_graphql_from_json "$body" "$expected_environment_envelope" >/dev/null; then
    rm -f "$body" "$headers"
    return 1
  fi
  local current_environment_identity
  if current_environment_identity="$(environment_specific_read)"; then
    current_rc=0
  else
    current_rc=$?
    rm -f "$body" "$headers"
    return "$current_rc"
  fi
  if test "$current_environment_identity" != "$expected_environment_envelope"; then
    rm -f "$body" "$headers"
    return 1
  fi
  rm -f "$body" "$headers"
  # Independent GraphQL evidence binds run/reviewer/environment node and the
  # current REST environment, but cannot prove the full environment incarnation
  # under which approval was issued. It is PARTIAL and never authorizing.
  return 3
}

verify_run_approval() {
  local expected_environment_identity="$1" first_rc second_rc alternate_rc
  if approval_history_read "$expected_environment_identity"; then
    return 0
  else
    first_rc=$?
  fi
  test "$first_rc" -eq 2 || die "workflow run lacks exact approval history bound to the current environment identity; stale environment incarnation, admin bypass, or wrong review is non-authorizing"

  if approval_history_read "$expected_environment_identity"; then
    return 0
  else
    second_rc=$?
  fi
  test "$second_rc" -eq 2 || die "workflow run approval retry returned deterministic invalid or stale environment-bound review history"

  if approval_history_graphql_read "$expected_environment_identity"; then
    die "workflow run GraphQL alternate unexpectedly claimed full publication authority"
  else
    alternate_rc=$?
  fi
  case "$alternate_rc" in
    1) die "workflow run GraphQL approval-history alternate returned deterministic invalid or stale environment-bound review history" ;;
    2) die "workflow run approval history unavailable after same-route retry and independent GraphQL read; publication authority not established" ;;
    3) die "workflow run GraphQL approval-history alternate is partial evidence only; full approval-time environment incarnation is UNKNOWN" ;;
    *) die "workflow run GraphQL approval-history alternate returned unknown state" ;;
  esac
}

remote_state() {
  local dir="$1" ref="$2" first second alternate
  first="$(remote_state_git "$dir" "$ref")" && {
    case "$first" in
      SHA:*) printf '%s\n' "$first"; return 0 ;;
      ABSENT) ;;
      *) return 1 ;;
    esac
  }
  second="$(remote_state_git "$dir" "$ref")" || second="ERROR"
  alternate="$(remote_state_rest "$ref")" || alternate="ERROR"
  if test "$second" = "ERROR"; then
    test "$alternate" != "ERROR" || return 1
    printf '%s\n' "$alternate"
    return 0
  fi
  test "$alternate" != "ERROR" || return 1
  test "$second" = "$alternate" || return 1
  printf '%s\n' "$second"
}

remote_sha() {
  local state
  state="$(remote_state "$1" "$2")" || return 1
  case "$state" in
    SHA:*) printf '%s\n' "${state#SHA:}" ;;
    *) return 1 ;;
  esac
}

require_ref_absent() {
  local state
  state="$(remote_state "$1" "$2")" || return 1
  test "$state" = "ABSENT"
}

require_common_event() {
  test "${GITHUB_EVENT_NAME:-}" = "create" || die "event mismatch"
  test "${GITHUB_REPOSITORY:-}" = "$REPO" || die "repository mismatch"
  test "${GITHUB_RUN_ATTEMPT:-}" = "1" || die "run attempt must equal 1"
  test "$(git -C controller rev-parse HEAD)" = "${GITHUB_SHA:-}" || die "controller checkout mismatch"
}

construct_candidate() {
  test "$(git -C custody rev-parse HEAD)" = "$CUSTODY_HEAD" || die "custody witness mismatch"
  test "$(git -C custody rev-parse HEAD^{tree})" = "$CUSTODY_TREE" || die "custody tree mismatch"
  test "$(git -C custody ls-tree --name-only HEAD)" = "carrier-v4" || die "custody root path-set mismatch"
  test "$(git -C repair rev-parse HEAD)" = "$REPAIR_BASE" || die "repair checkout mismatch"
  test "$(git -C repair rev-parse HEAD^{tree})" = "$REPAIR_BASE_TREE" || die "repair base tree mismatch"
  test "$(remote_sha repair "$REPAIR_REF")" = "$REPAIR_BASE" || die "repair remote moved before construction"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  donor="$tmp/v15.png"

  python3 - "$donor" <<'PY'
from pathlib import Path
import re
import sys

root = Path("custody/carrier-v4")
out = Path(sys.argv[1])
parts = []
for path in root.glob("*.bin"):
    match = re.fullmatch(r"(\d+)_(\d+)_(\d+)\.bin", path.name)
    if not match:
        raise SystemExit(f"unexpected carrier name: {path.name}")
    idx, offset, size = map(int, match.groups())
    data = path.read_bytes()
    if len(data) != size:
        raise SystemExit(f"carrier size mismatch: {path.name}")
    parts.append((idx, offset, size, data))
parts.sort()
if len(parts) != 89:
    raise SystemExit(f"carrier count mismatch: {len(parts)}")
cursor = 0
for expected_idx, (idx, offset, size, _) in enumerate(parts):
    if idx != expected_idx or offset != cursor:
        raise SystemExit(
            f"carrier continuity mismatch: expected_idx={expected_idx} "
            f"idx={idx} offset={offset} cursor={cursor}"
        )
    cursor += size
out.write_bytes(b"".join(item[3] for item in parts))
PY

  test "$(wc -c < "$donor" | tr -d ' ')" = "$DONOR_BYTES" || die "donor byte-count mismatch"
  test "$(sha256sum "$donor" | awk '{print $1}')" = "$DONOR_SHA256" || die "donor sha256 mismatch"
  test "$(git hash-object "$donor")" = "$DONOR_BLOB" || die "donor Git blob mismatch"

  cp "$donor" repair/payload/ui/images/app_256.png
  cp "$donor" repair/spk/PACKAGE_ICON_256.PNG

  python3 - <<'PY'
from pathlib import Path
import hashlib
import json

path = Path("repair/SOURCE_MANIFEST.json")
entries = json.loads(path.read_text(encoding="utf-8"))
targets = {
    "payload/ui/images/app_256.png",
    "spk/PACKAGE_ICON_256.PNG",
}
seen = set()
for entry in entries:
    if entry.get("path") in targets:
        entry["bytes"] = 62827
        entry["sha256"] = "0bbab931e7ed5836917dee72b80fe68295ee8182aa08bc0a00250bcb11f442d5"
        seen.add(entry["path"])
if seen != targets:
    raise SystemExit(f"manifest target mismatch: {sorted(seen)}")
data = (json.dumps(entries, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
if len(data) != 4403:
    raise SystemExit(f"manifest bytes mismatch: {len(data)}")
if hashlib.sha256(data).hexdigest() != "f07ba02bb67b64e2b07ae741943ec50324261a022c5e54c9a73d2547b49db81d":
    raise SystemExit("manifest sha256 mismatch")
path.write_bytes(data)
PY

  test "$(git hash-object repair/SOURCE_MANIFEST.json)" = "$MANIFEST_BLOB" || die "manifest Git blob mismatch"
  test "$(wc -c < repair/SOURCE_MANIFEST.json | tr -d ' ')" = "$MANIFEST_BYTES" || die "manifest byte-count mismatch"

  expected_paths="$tmp/expected-paths"
  printf '%s\n' \
    SOURCE_MANIFEST.json \
    payload/ui/images/app_256.png \
    spk/PACKAGE_ICON_256.PNG \
    > "$expected_paths"

  git -C repair diff --name-only | LC_ALL=C sort > "$tmp/worktree-paths"
  cmp -s "$expected_paths" "$tmp/worktree-paths" || die "unexpected worktree path delta"

  git -C repair add -- \
    SOURCE_MANIFEST.json \
    payload/ui/images/app_256.png \
    spk/PACKAGE_ICON_256.PNG

  git -C repair diff --cached --name-only | LC_ALL=C sort > "$tmp/staged-paths"
  cmp -s "$expected_paths" "$tmp/staged-paths" || die "unexpected staged path delta"

  tree="$(git -C repair write-tree)"
  test "$tree" = "$EXPECTED_TREE" || die "candidate tree mismatch"

  commit="$(
    printf '%s\n' "$COMMIT_MESSAGE" |
      GIT_AUTHOR_NAME="Vera Build Team" \
      GIT_AUTHOR_EMAIL="build-team@example.invalid" \
      GIT_AUTHOR_DATE="@$COMMIT_EPOCH +0000" \
      GIT_COMMITTER_NAME="Vera Build Team" \
      GIT_COMMITTER_EMAIL="build-team@example.invalid" \
      GIT_COMMITTER_DATE="@$COMMIT_EPOCH +0000" \
      git -C repair commit-tree "$tree" -p "$REPAIR_BASE"
  )"
  test "$commit" = "$EXPECTED_COMMIT" || die "candidate commit identity mismatch"

  git -C repair reset --hard "$commit" >/dev/null
  test "$(git -C repair rev-parse HEAD^)" = "$REPAIR_BASE" || die "candidate parent mismatch"
  test "$(git -C repair rev-parse HEAD^{tree})" = "$EXPECTED_TREE" || die "post-commit tree mismatch"
  test "$(git -C repair ls-tree HEAD SOURCE_MANIFEST.json | awk '{print $3}')" = "$MANIFEST_BLOB" || die "committed manifest blob mismatch"
  test "$(git -C repair ls-tree HEAD payload/ui/images/app_256.png | awk '{print $3}')" = "$DONOR_BLOB" || die "committed payload icon blob mismatch"
  test "$(git -C repair ls-tree HEAD spk/PACKAGE_ICON_256.PNG | awk '{print $3}')" = "$DONOR_BLOB" || die "committed SPK icon blob mismatch"

  (
    cd repair
    python3 -m unittest discover -s tests -v
    python3 -m compileall -q payload tools tests
    for file in spk/scripts/*; do
      sh -n "$file"
    done
    python3 tools/build_spk.py
    python3 tools/verify_spk.py "$SPK_PATH" --manifest SOURCE_MANIFEST.json
    test "$(sha256sum "$SPK_PATH" | awk '{print $1}')" = "$EXPECTED_SPK_SHA256"
  )

  test "$(remote_sha repair "$REPAIR_REF")" = "$REPAIR_BASE" || die "repair remote moved during qualification"
}

validate_activation() {
  test -f "$ACTIVATION_PATH" || die "activation file missing"
  activation_env="$(
    python3 - "$ACTIVATION_PATH" <<'PY'
import json
from pathlib import Path
import re
import shlex
import sys

path = Path(sys.argv[1])
obj = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schema",
    "operation_id",
    "coordination_event_id",
    "qualifier_commit",
    "repair_base_sha",
    "repair_base_tree",
    "expected_candidate_commit",
    "expected_candidate_tree",
    "expected_spk_sha256",
}
if set(obj) != required:
    raise SystemExit("activation key-set mismatch")
if obj["schema"] != "BT2_SYNOLOGY_V15_PUBLICATION_ACTIVATION_V2":
    raise SystemExit("activation schema mismatch")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,80}", obj["operation_id"]):
    raise SystemExit("activation operation_id invalid")
if not isinstance(obj["coordination_event_id"], int) or obj["coordination_event_id"] <= 0:
    raise SystemExit("activation coordination_event_id invalid")
for key in ("qualifier_commit", "repair_base_sha", "repair_base_tree", "expected_candidate_commit", "expected_candidate_tree"):
    if not isinstance(obj[key], str) or not re.fullmatch(r"[0-9a-f]{40}", obj[key]):
        raise SystemExit(f"activation {key} invalid")
if not isinstance(obj["expected_spk_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", obj["expected_spk_sha256"]):
    raise SystemExit("activation SPK digest invalid")
for key, value in obj.items():
    env_key = "A_" + key.upper()
    if isinstance(value, str):
        print(f"{env_key}={shlex.quote(value)}")
    elif isinstance(value, int):
        print(f"{env_key}={value}")
PY
  )" || die "activation parse failed"
  eval "$activation_env"

  test "$A_REPAIR_BASE_SHA" = "$REPAIR_BASE" || die "activation repair base mismatch"
  test "$A_REPAIR_BASE_TREE" = "$REPAIR_BASE_TREE" || die "activation repair tree mismatch"
  test "$A_EXPECTED_CANDIDATE_COMMIT" = "$EXPECTED_COMMIT" || die "activation candidate commit mismatch"
  test "$A_EXPECTED_CANDIDATE_TREE" = "$EXPECTED_TREE" || die "activation candidate tree mismatch"
  test "$A_EXPECTED_SPK_SHA256" = "$EXPECTED_SPK_SHA256" || die "activation SPK digest mismatch"
  test "${GITHUB_REF:-}" = "${ACTIVATION_PREFIX}${A_OPERATION_ID}" || die "activation ref mismatch"
  activation_parent_count="$(git -C controller rev-list --parents -n 1 HEAD | awk '{print NF-1}')"
  test "$activation_parent_count" = "1" || die "activation commit must have exactly one parent"
  test "$(git -C controller rev-parse HEAD^)" = "$A_QUALIFIER_COMMIT" || die "activation parent/qualifier mismatch"
  test "$(git -C controller diff --name-only HEAD^ HEAD)" = "$ACTIVATION_REPO_PATH" || die "activation commit path-set mismatch"
}

push_once_with_token() {
  local dir="$1" spec="$2" basic rc
  basic="$(printf 'x-access-token:%s' "$GH_PUSH_TOKEN" | base64 -w0)"
  if GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="http.extraHeader" \
    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $basic" \
      git -C "$dir" push origin "$spec"; then
    rc=0
  else
    rc=$?
  fi
  unset basic
  return "$rc"
}

build_consumed_marker() {
  local marker_tree marker_message
  test -n "${GITHUB_RUN_ID:-}" || die "workflow run id unavailable"
  printf '%s\n' "$GITHUB_RUN_ID" | grep -Eq '^[1-9][0-9]*$' || die "workflow run id invalid"
  CONSUMED_REF="${CONSUMED_PREFIX}${A_OPERATION_ID}"
  test "$(git -C controller status --porcelain)" = "" || die "controller worktree not clean before marker"

  A_OPERATION_ID="$A_OPERATION_ID" \
  A_COORDINATION_EVENT_ID="$A_COORDINATION_EVENT_ID" \
  A_QUALIFIER_COMMIT="$A_QUALIFIER_COMMIT" \
  A_REPAIR_BASE_SHA="$A_REPAIR_BASE_SHA" \
  A_REPAIR_BASE_TREE="$A_REPAIR_BASE_TREE" \
  A_EXPECTED_CANDIDATE_COMMIT="$A_EXPECTED_CANDIDATE_COMMIT" \
  A_EXPECTED_CANDIDATE_TREE="$A_EXPECTED_CANDIDATE_TREE" \
  A_EXPECTED_SPK_SHA256="$A_EXPECTED_SPK_SHA256" \
  GITHUB_REF="${GITHUB_REF:-}" GITHUB_SHA="${GITHUB_SHA:-}" \
  GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
  GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
  CONSUMED_PATH_ARG="$CONSUMED_PATH" \
  python3 - <<'PY'
from pathlib import Path
import json, os
obj = {
    "schema": "BT2_SYNOLOGY_V15_CONSUMED_ACTIVATION_V1",
    "operation_id": os.environ["A_OPERATION_ID"],
    "coordination_event_id": int(os.environ["A_COORDINATION_EVENT_ID"]),
    "activation_ref": os.environ["GITHUB_REF"],
    "activation_commit": os.environ["GITHUB_SHA"],
    "qualifier_commit": os.environ["A_QUALIFIER_COMMIT"],
    "github_run_id": int(os.environ["GITHUB_RUN_ID"]),
    "github_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
    "repository": os.environ["GITHUB_REPOSITORY"],
    "repair_base_sha": os.environ["A_REPAIR_BASE_SHA"],
    "repair_base_tree": os.environ["A_REPAIR_BASE_TREE"],
    "expected_candidate_commit": os.environ["A_EXPECTED_CANDIDATE_COMMIT"],
    "expected_candidate_tree": os.environ["A_EXPECTED_CANDIDATE_TREE"],
    "expected_spk_sha256": os.environ["A_EXPECTED_SPK_SHA256"],
}
Path(os.environ["CONSUMED_PATH_ARG"]).write_text(
    json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

  test -f "$CONSUMED_PATH" || die "consumed marker file missing"
  git -C controller add -- "$CONSUMED_REPO_PATH"
  test "$(git -C controller diff --cached --name-only)" = "$CONSUMED_REPO_PATH" || die "consumed marker staged path-set mismatch"
  marker_tree="$(git -C controller write-tree)"
  marker_message="Consume exact V15 activation ${A_OPERATION_ID}"
  EXPECTED_MARKER_COMMIT="$(
    printf '%s\n' "$marker_message" |
      GIT_AUTHOR_NAME="Vera Build Team" \
      GIT_AUTHOR_EMAIL="build-team@example.invalid" \
      GIT_AUTHOR_DATE="@$MARKER_EPOCH +0000" \
      GIT_COMMITTER_NAME="Vera Build Team" \
      GIT_COMMITTER_EMAIL="build-team@example.invalid" \
      GIT_COMMITTER_DATE="@$MARKER_EPOCH +0000" \
      git -C controller commit-tree "$marker_tree" -p "${GITHUB_SHA:-}"
  )"
  printf '%s\n' "$EXPECTED_MARKER_COMMIT" | grep -Eq '^[0-9a-f]{40}$' || die "consumed marker commit invalid"
}

consume_activation() {
  local marker_rc marker_state
  CONSUMED_REF="${CONSUMED_PREFIX}${A_OPERATION_ID}"
  require_ref_absent controller "$CONSUMED_REF" || die "activation already consumed or consumed-state unreadable"
  build_consumed_marker

  set +e
  push_once_with_token controller "$EXPECTED_MARKER_COMMIT:$CONSUMED_REF"
  marker_rc=$?
  set -e

  marker_state="$(remote_state controller "$CONSUMED_REF")" || die "consumed marker readback unavailable; effect state UNKNOWN; no retry permitted"
  test "$marker_state" = "SHA:$EXPECTED_MARKER_COMMIT" || die "activation consumed by another run or marker mismatch; no retry permitted"
  if test "$marker_rc" -ne 0; then
    printf '%s\n' "marker push returned nonzero but exact readback proves this run consumed activation" >&2
  fi
  printf 'CONSUMED_ACTIVATION_REF=%s\n' "$CONSUMED_REF"
  printf 'CONSUMED_ACTIVATION_COMMIT=%s\n' "$EXPECTED_MARKER_COMMIT"
}

qualify() {
  require_common_event
  test "${GITHUB_REF:-}" = "$QUALIFY_REF" || die "qualifier ref mismatch"
  construct_candidate
  test "$(remote_sha controller "$QUALIFY_REF")" = "${GITHUB_SHA:-}" || die "qualifier remote moved"
  printf 'QUALIFIED_CANDIDATE_COMMIT=%s\n' "$EXPECTED_COMMIT"
  printf 'QUALIFIED_CANDIDATE_TREE=%s\n' "$EXPECTED_TREE"
  printf 'QUALIFIED_SPK_SHA256=%s\n' "$EXPECTED_SPK_SHA256"
  printf '%s\n' "QUALIFICATION_ONLY=1"
}

publish() {
  require_common_event
  case "${GITHUB_REF:-}" in
    "$ACTIVATION_PREFIX"*) ;;
    *) die "publisher activation ref mismatch" ;;
  esac
  test -n "${GH_PUSH_TOKEN:-}" || die "push token unavailable"
  INITIAL_ENVIRONMENT_IDENTITY="$(verify_environment_gate)"
  verify_run_approval "$INITIAL_ENVIRONMENT_IDENTITY"
  validate_activation
  test "$(remote_sha controller "${GITHUB_REF:-}")" = "${GITHUB_SHA:-}" || die "activation remote moved before consumption"
  test "$(remote_sha controller "$QUALIFY_REF")" = "$A_QUALIFIER_COMMIT" || die "qualifier remote moved before consumption"
  test "$(remote_sha repair "$REPAIR_REF")" = "$REPAIR_BASE" || die "repair remote moved before consumption"
  consume_activation

  construct_candidate
  test "$(remote_sha controller "${GITHUB_REF:-}")" = "${GITHUB_SHA:-}" || die "activation remote moved before push"
  test "$(remote_sha controller "$QUALIFY_REF")" = "$A_QUALIFIER_COMMIT" || die "qualifier remote moved before push"
  test "$(remote_sha controller "$CONSUMED_REF")" = "$EXPECTED_MARKER_COMMIT" || die "consumed marker moved before push"
  test "$(remote_sha repair "$REPAIR_REF")" = "$REPAIR_BASE" || die "repair remote moved before push"
  PREPUSH_ENVIRONMENT_IDENTITY="$(verify_environment_gate)"
  test "$PREPUSH_ENVIRONMENT_IDENTITY" = "$INITIAL_ENVIRONMENT_IDENTITY" || die "publication environment identity changed after activation consumption"
  verify_run_approval "$PREPUSH_ENVIRONMENT_IDENTITY"

  set +e
  push_once_with_token repair "HEAD:$REPAIR_REF"
  push_rc=$?
  set -e

  set +e
  remote_after="$(remote_sha repair "$REPAIR_REF")"
  readback_rc=$?
  set -e

  if test "$readback_rc" -ne 0 || test -z "$remote_after"; then
    die "post-push readback unavailable; effect state UNKNOWN; no retry permitted"
  fi
  if test "$remote_after" != "$EXPECTED_COMMIT"; then
    die "post-push remote mismatch; effect state not proven; no retry permitted"
  fi
  if test "$push_rc" -ne 0; then
    printf '%s\n' "push returned nonzero but exact readback proves expected remote commit" >&2
  fi

  printf 'PUBLISHED_COMMIT=%s\n' "$EXPECTED_COMMIT"
  printf 'PUBLISHED_TREE=%s\n' "$EXPECTED_TREE"
  printf 'PUBLISHED_SPK_SHA256=%s\n' "$EXPECTED_SPK_SHA256"
}

case "$MODE" in
  qualify) qualify ;;
  publish) publish ;;
esac
