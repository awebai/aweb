#!/usr/bin/env bash
# Container client for e2e-grant-app-tools.sh. All grant/custody assertions run
# against the real stack; the client and app share the server's network.
set -euo pipefail
PROJECT="${GRANT_APP_E2E_PROJECT:?}"
AWID_URL=http://awid:8010
AWEB_URL=http://127.0.0.1:8000
LIBRARY_URL=https://library-grant.test:8765
AW_BIN=/usr/local/bin/aw
export SSL_CERT_FILE=/fixture/tls/ca.pem
WORK="$(mktemp -d /tmp/awga.XXXXXX)"
RESIDENT="$WORK/r"
GRANT="$WORK/g"
INSTANCE="$WORK/i"
mkdir -p "$RESIDENT" "$INSTANCE" "$WORK/home" "$WORK/awhome"
pass=0
fail=0
CUSTODY_PID=""
cleanup() {
  status=$?
  if [[ -n "$CUSTODY_PID" ]] && kill -0 "$CUSTODY_PID" 2>/dev/null; then
    kill "$CUSTODY_PID" 2>/dev/null || true
    wait "$CUSTODY_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
service_container() {
  docker ps -q --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$1"
}
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }
aw_in() {
  local dir="$1"
  shift
  (cd "$dir" && env HOME="$WORK/home" AW_HOME="$WORK/awhome" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 \
    NO_COLOR=1 AWEB_IDENTITY_HOME= "$AW_BIN" "$@")
}

# Grant worker: the grant home is selected explicitly (as OATS hooks do) from
# an otherwise empty instance directory.
aw_grant() {
  (cd "$INSTANCE" && env HOME="$WORK/home" AW_HOME="$WORK/awhome" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 \
    NO_COLOR=1 AWEB_IDENTITY_HOME="$GRANT" "$AW_BIN" "$@")
}

expect_ok() {
  local label="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then
    ok "$label"
  else
    bad "$label: $out"
  fi
}

expect_fail_with() {
  local label="$1" needle="$2"
  shift 2
  local out
  if out="$("$@" 2>&1)"; then
    bad "$label: unexpectedly succeeded: $out"
  elif [[ "$out" == *"$needle"* ]]; then
    ok "$label"
  else
    bad "$label: failed without '$needle': $out"
  fi
}

library_log_count() {
  docker logs "$(service_container library)" 2>&1 | grep -c -- "$1" || true
}

unbounded="$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
  | xargs -r docker inspect -f '{{.Name}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' \
  | awk '$2 == 0 || $3 == 0 || $4 == "<nil>" || $4 <= 0 {print $1}')"
[[ -z "$unbounded" ]] && ok "every container has CPU, memory and pids limits" || { bad "unbounded containers: $unbounded"; exit 1; }

echo "=== Resident identity, team and aweb connection ==="
aw_in "$RESIDENT" id create --name alice --domain grant-app.test --registry "$AWID_URL" --skip-dns-verify --json >/dev/null
aw_in "$RESIDENT" id namespace set-delivery-origin --namespace grant-app.test --origin "$AWEB_URL" --json >/dev/null
aw_in "$RESIDENT" id team create --name devteam --namespace grant-app.test --registry "$AWID_URL" --json >/dev/null
invite="$(aw_in "$RESIDENT" id team invite --team devteam --namespace grant-app.test --global --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')"
aw_in "$RESIDENT" id team accept-invite "$invite" --global --alias alice --json >/dev/null
aw_in "$RESIDENT" init --url "$AWEB_URL" >/dev/null

echo "=== Install the real Library app ==="
principal="$(aw_in "$RESIDENT" id show --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["did_key"])')"
docker exec "$(service_container aweb)" aweb install-admin grant \
  --team-id devteam:grant-app.test --principal-did "$principal" --role owner >/dev/null
aw_in "$RESIDENT" plugin install "$LIBRARY_URL" >/dev/null

echo "=== Baseline: resident calls Library directly ==="
expect_ok "resident library register" aw_in "$RESIDENT" library register
expect_ok "resident library shelf" aw_in "$RESIDENT" library shelf

echo "=== Mint refusals happen before any grant exists ==="
expect_fail_with "public tool cannot be granted" "public tool" \
  aw_in "$RESIDENT" id grant mint --scope mail.read --app-tool library:list-blueprints --ttl 1h --out "$WORK/refused1" --json
expect_fail_with "wildcard refused" "wildcard" \
  aw_in "$RESIDENT" id grant mint --scope mail.read --app-tool 'library:*' --ttl 1h --out "$WORK/refused2" --json

echo "=== Mint a grant naming exactly shelf + register ==="
mint="$(aw_in "$RESIDENT" id grant mint --bundle normal-agent --app-tool library:shelf --app-tool library:register --ttl 1h --out "$GRANT" --json)"
GRANT_ID="$(printf '%s' "$mint" | python3 -c 'import json,sys;print(json.load(sys.stdin)["grant_id"])')"
[[ -f "$RESIDENT/.aw/grants/$GRANT_ID/app-tools.json" ]] && ok "app tool policy stored in resident home" || bad "app tool policy missing from resident home"
[[ ! -e "$GRANT/grants" ]] && ok "grant home has no app tool policy" || bad "app tool policy leaked into grant home"
if python3 - "$GRANT" "$RESIDENT/.aw/signing.key" <<'PY'
import pathlib, sys
resident = pathlib.Path(sys.argv[2]).read_bytes()
leaked = [str(p) for p in pathlib.Path(sys.argv[1]).rglob("*") if p.is_file() and p.read_bytes() == resident]
sys.exit(1 if leaked else 0)
PY
then ok "grant home does not contain the resident signing key"; else bad "resident signing key found in grant home"; fi

echo "=== Start resident custody ==="
(cd "$RESIDENT" && env HOME="$WORK/home" AW_HOME="$WORK/awhome" AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 AWEB_IDENTITY_HOME= "$AW_BIN" custody serve) >"$WORK/custody.log" 2>&1 &
CUSTODY_PID=$!
socket=""
for _ in $(seq 1 100); do
  socket="$(aw_in "$RESIDENT" custody status --json 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("socket_path","") if d.get("status")=="running" else "")' 2>/dev/null || true)"
  [[ -n "$socket" ]] && break
  sleep 0.1
done
[[ -n "$socket" ]] && ok "custody running at $socket" || { bad "custody did not start: $(cat "$WORK/custody.log")"; exit 1; }
aw_in "$RESIDENT" custody status --json | grep -q '"sign_app_request.v1"' && ok "custody advertises sign_app_request.v1" || bad "sign_app_request.v1 not advertised"
python3 - "$GRANT" "$socket" <<'PY'
import pathlib, sys
grant_yaml = pathlib.Path(sys.argv[1]) / "grant.yaml"
text = grant_yaml.read_text()
assert "custody:" not in text, "grant home already has a custody locator"
grant_yaml.write_text(text.rstrip("\n") + f"\ncustody:\n    socket_path: {sys.argv[2]}\n")
PY

echo "=== Grant calls Library through custody ==="
expect_ok "grant library shelf (named read)" aw_grant library shelf
expect_ok "grant library register (named write)" aw_grant library register
expect_ok "grant library list-blueprints (public, unsigned)" aw_grant library list-blueprints

echo "=== Unnamed tools are refused before reaching Library ==="
before="$(library_log_count 'proposals/00000000-0000-4000-8000-000000000000/approve')"
shelf_seen="$(library_log_count 'GET /v1/shelf')"
expect_fail_with "grant cannot approve" "app_tool_denied" \
  aw_grant library approve --proposal_id 00000000-0000-4000-8000-000000000000
expect_fail_with "grant cannot delete a blueprint" "app_tool_denied" \
  aw_grant library delete-blueprint --blueprint_ref aweb.team
after="$(library_log_count 'proposals/00000000-0000-4000-8000-000000000000/approve')"
# Supporting evidence only when the positive control shows Library logs request
# paths; the custody refusal itself is asserted above either way.
if [[ "$shelf_seen" -gt 0 ]]; then
  [[ "$before" == "$after" ]] && ok "refused approve never reached Library (positive control: $shelf_seen shelf requests logged)" \
    || bad "refused approve reached Library"
else
  echo "  SUPPORTING-EVIDENCE-UNAVAILABLE: Library logs show no request paths (positive control GET /v1/shelf = 0)"
fi

echo "=== Revocation stops the grant ==="
expect_ok "resident revokes the grant" aw_in "$RESIDENT" id grant revoke "$GRANT_ID" --json
expect_fail_with "revoked grant cannot call Library" "grant_revoked" \
  aw_grant library shelf

echo ""
echo "grant app tools acceptance: $pass passed, $fail failed"
[[ -z "$(ls -A "$INSTANCE")" ]] && ok "instance directory untouched" || bad "grant run wrote into the instance directory: $(ls -A "$INSTANCE")"
echo "grant app tools acceptance (final): $pass passed, $fail failed"
[[ $fail -eq 0 ]]
