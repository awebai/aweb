#!/usr/bin/env bash
#
# Live acceptance for grant-backed installed-app tools (aweb-abjg).
#
# Brings up the self-hosted awid + aweb + Library stack (docker-compose.e2e.yml plus a bounded test overlay),
# creates a disposable resident identity and team, connects it to aweb, installs
# the real Library app, mints a session grant naming exactly two Library tools,
# runs `aw custody serve` for the resident, and drives `aw library <verb>` from
# the grant home against Library's real team-auth verifier.
#
# Proves:
#   - the resident itself can call Library (baseline)
#   - a grant can call the named authenticated tools (shelf, register) and
#     Library accepts them as the resident
#   - unnamed tools (approve, delete-blueprint) are refused by custody and never
#     reach Library
#   - public tools (list-blueprints) still work unsigned under a grant
#   - after revocation the grant can no longer call Library
#   - the grant home never holds the resident key or the app tool policy
#
# Usage: ./scripts/e2e-grant-app-tools.sh
#
# Environment:
#   GRANT_APP_E2E_REPO_ROOT  source checkout under test (default: this checkout).
#                            Lets a reviewed copy of this script run against an
#                            exact candidate tree without editing it.
#   AW_BIN                   prebuilt aw binary (default: go build from REPO_ROOT)
#   GRANT_APP_E2E_BUILDER    bounded buildx builder (default: $BUILDX_BUILDER or
#                            aweb-candidate-gate); BUILDX_CONFIG defaults to
#                            /tmp/aweb-candidate-buildx. A missing builder is fatal:
#                            the script never falls back to an unbounded build.
#   GRANT_APP_E2E_PROJECT    compose project (default: aweb-e2e-grant-app)
#   GRANT_APP_E2E_*_PORT     AWID/AWEB/LIBRARY/POSTGRES host ports
#                            (defaults 28010/28000/28765/56432)
#   GRANT_APP_E2E_EVIDENCE_DIR  where logs are kept (default /tmp/aweb-grant-app-evidence-<ts>);
#                            no identity homes or keys are copied there
#   KEEP_UP=1                leave the stack running on success
#
# Resources: every service is bounded at container creation by
# scripts/e2e/grant-app-acceptance.compose.yml (postgres 1 CPU/1g, redis 0.5/256m,
# awid/aweb/library 1 CPU/1g; pids limited), and images are built only through
# the named buildx builder. Do not run alongside another heavy gate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${GRANT_APP_E2E_REPO_ROOT:-$SCRIPT_DIR/..}" && pwd -P)"
OVERLAY="$SCRIPT_DIR/e2e/grant-app-acceptance.compose.yml"
COMPOSE_FILE="$REPO_ROOT/docker-compose.e2e.yml"
PROJECT="${GRANT_APP_E2E_PROJECT:-aweb-e2e-grant-app}"
export BUILDX_CONFIG="${BUILDX_CONFIG:-/tmp/aweb-candidate-buildx}"
BUILDER="${GRANT_APP_E2E_BUILDER:-${BUILDX_BUILDER:-aweb-candidate-gate}}"

export LIBRARY_E2E_AWID_PORT="${GRANT_APP_E2E_AWID_PORT:-28010}"
export LIBRARY_E2E_AWEB_PORT="${GRANT_APP_E2E_AWEB_PORT:-28000}"
export LIBRARY_E2E_LIBRARY_PORT="${GRANT_APP_E2E_LIBRARY_PORT:-28765}"
export LIBRARY_E2E_POSTGRES_PORT="${GRANT_APP_E2E_POSTGRES_PORT:-56432}"
AWID_URL="http://127.0.0.1:$LIBRARY_E2E_AWID_PORT"
AWEB_URL="http://127.0.0.1:$LIBRARY_E2E_AWEB_PORT"
LIBRARY_URL="http://127.0.0.1:$LIBRARY_E2E_LIBRARY_PORT"
export LIBRARY_E2E_LIBRARY_CONTEXT="$REPO_ROOT/naapp/library"
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="$AWEB_URL"
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="$AWID_URL"
export LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN="$LIBRARY_URL"

COMPOSE=(docker compose -p "$PROJECT" --project-directory "$REPO_ROOT" -f "$COMPOSE_FILE" -f "$OVERLAY")

EVIDENCE="${GRANT_APP_E2E_EVIDENCE_DIR:-/tmp/aweb-grant-app-evidence-$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$EVIDENCE"
exec > >(tee -a "$EVIDENCE/run.log") 2>&1
echo "evidence: $EVIDENCE"
echo "source:   $REPO_ROOT ($(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown))"
echo "script:   $SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# Short root: Unix socket paths are limited to ~104-108 bytes.
WORK="$(mktemp -d /tmp/awga.XXXXXX)"
RESIDENT="$WORK/r"
GRANT="$WORK/g"
INSTANCE="$WORK/i"
mkdir -p "$RESIDENT" "$INSTANCE" "$WORK/home" "$WORK/awhome"

pass=0
fail=0
CUSTODY_PID=""
STACK_STARTED=0

save_evidence() {
  [[ "$STACK_STARTED" == "1" ]] || return 0
  "${COMPOSE[@]}" ps >"$EVIDENCE/compose-ps.txt" 2>&1 || true
  "${COMPOSE[@]}" logs --no-color >"$EVIDENCE/compose-logs.txt" 2>&1 || true
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
    | xargs -r docker inspect -f '{{.Name}} cpus_nano={{.HostConfig.NanoCpus}} memory={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' \
    >"$EVIDENCE/container-limits.txt" 2>&1 || true
  [[ -f "$WORK/custody.log" ]] && cp "$WORK/custody.log" "$EVIDENCE/custody.log" || true
}

remove_stack() {
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans
}

# Same residue contract as e2e-library-stack.sh: nothing labelled with this
# compose project may survive a reset or teardown.
assert_project_absent() {
  local containers networks volumes images
  containers="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")"
  networks="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  images="$(docker images -q --filter "label=com.docker.compose.project=$PROJECT")"
  if [[ -n "$containers$networks$volumes$images" ]]; then
    echo "Compose project $PROJECT residue: containers=${containers:-none} networks=${networks:-none} volumes=${volumes:-none} images=${images:-none}" >&2
    return 1
  fi
}

cleanup() {
  local status=$?
  if [[ -n "$CUSTODY_PID" ]] && kill -0 "$CUSTODY_PID" 2>/dev/null; then
    kill "$CUSTODY_PID" 2>/dev/null || true
    wait "$CUSTODY_PID" 2>/dev/null || true
  fi
  save_evidence
  if [[ "$STACK_STARTED" == "1" ]] && [[ "${KEEP_UP:-}" != "1" || $status -ne 0 ]]; then
    if ! remove_stack || ! assert_project_absent; then
      echo "FATAL: teardown of compose project $PROJECT failed or left residue" >&2
      [[ $status -ne 0 ]] || status=1
    fi
  fi
  rm -rf "$WORK"
  echo "evidence kept in $EVIDENCE"
  exit "$status"
}
trap cleanup EXIT

ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }
fatal() { echo "FATAL: $1" >&2; exit 1; }

wait_health() {
  local label="$1" url="$2"
  for _ in $(seq 1 90); do
    curl -sf "$url" >/dev/null 2>&1 && { echo "  $label healthy"; return 0; }
    sleep 2
  done
  fatal "$label never became healthy ($url)"
}

echo "=== Preflight: bounded builder and tools ==="
docker buildx inspect "$BUILDER" >"$EVIDENCE/builder.txt" 2>&1 \
  || fatal "buildx builder '$BUILDER' not found (BUILDX_CONFIG=$BUILDX_CONFIG); refusing an unbounded build"
docker compose build --help 2>/dev/null | grep -q -- '--builder' \
  || fatal "docker compose build does not support --builder; upgrade Compose rather than build unbounded"
[[ -f "$COMPOSE_FILE" && -d "$LIBRARY_E2E_LIBRARY_CONTEXT" ]] || fatal "REPO_ROOT $REPO_ROOT lacks docker-compose.e2e.yml or naapp/library"

if [[ -z "${AW_BIN:-}" ]]; then
  echo "=== Building aw from $REPO_ROOT ==="
  (cd "$REPO_ROOT/cli/go" && go build -o "$WORK/aw" ./cmd/aw)
  AW_BIN="$WORK/aw"
fi

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
  "${COMPOSE[@]}" logs --no-color library 2>/dev/null | grep -c -- "$1" || true
}

echo "=== Stack: bounded build, then up without building ==="
STACK_STARTED=1
remove_stack || fatal "could not reset compose project $PROJECT"
assert_project_absent || fatal "compose project $PROJECT has residue after reset; refusing to reuse state"
"${COMPOSE[@]}" build --builder "$BUILDER"
for service in awid aweb library; do
  docker image inspect "$PROJECT-$service" >/dev/null 2>&1 \
    || fatal "image $PROJECT-$service not loaded after the bounded build"
done
"${COMPOSE[@]}" up --no-build -d
wait_health awid "$AWID_URL/health"
wait_health aweb "$AWEB_URL/health"
wait_health library "$LIBRARY_URL/health"
unbounded="$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
  | xargs -r docker inspect -f '{{.Name}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' \
  | awk '$2 == 0 || $3 == 0 || $4 == "<nil>" || $4 <= 0 {print $1}')"
[[ -z "$unbounded" ]] && ok "every container has CPU, memory and pids limits" || fatal "unbounded containers: $unbounded"

echo "=== Resident identity, team and aweb connection ==="
aw_in "$RESIDENT" id create --name alice --domain grant-app.test --registry "$AWID_URL" --skip-dns-verify --json >/dev/null
aw_in "$RESIDENT" id namespace set-delivery-origin --namespace grant-app.test --origin "$AWEB_URL" --json >/dev/null
aw_in "$RESIDENT" id team create --name devteam --namespace grant-app.test --registry "$AWID_URL" --json >/dev/null
invite="$(aw_in "$RESIDENT" id team invite --team devteam --namespace grant-app.test --global --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')"
aw_in "$RESIDENT" id team accept-invite "$invite" --global --alias alice --json >/dev/null
aw_in "$RESIDENT" init --url "$AWEB_URL" >/dev/null

echo "=== Install the real Library app ==="
aw_in "$RESIDENT" plugin install "$LIBRARY_URL" --dev-origin "$LIBRARY_URL" >/dev/null

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
