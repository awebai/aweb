#!/usr/bin/env bash
# Prove, on a fresh local tmpfs-backed stack, both that ordinary OAS retirement
# preserves an externally attached principal and that local disposable
# provisioning refuses a forged victim while authorized cleanup actually
# revokes/deletes every owned resource.
#
# Requirements: Docker Compose, Go, Python 3, curl, and an OAS source install.
# OAS_TEST_ROOT selects that install. OAS_PROOF_{AWID,AWEB,POSTGRES}_PORT and
# OAS_PROOF_PROJECT isolate concurrent runs. OAS_PROOF_REPORT selects the
# persistent JSON evidence destination; KEEP_OAS_PROOF=1 retains local fixtures.
# The harness refuses non-loopback services and never launches a model or tmux.
set -euo pipefail

canonical_dir() {
  bash -c 'cd "$1" && pwd -P' _ "$1"
}

make_temp_dir() {
  local directory
  directory="$(mktemp -d "${TMPDIR:-/tmp}/aweb-oas-retire-proof.XXXXXX")"
  canonical_dir "$directory"
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CLI_DIR="$REPO_ROOT/cli/go"
AW_BIN="${AW_BIN:-$CLI_DIR/aw}"
PROOF_HELPER="$REPO_ROOT/scripts/e2e/oas_principal_proof.py"
CAPABILITY_SOURCE="$REPO_ROOT/oas/.agents/capabilities/owned/aweb-identity-attach"
COMPOSE_FILE="$REPO_ROOT/docker-compose.e2e.yml"

preflight() {
  [[ -d "$CLI_DIR" ]] || { echo "FAIL: CLI source not found at $CLI_DIR" >&2; return 1; }
  [[ -f "$PROOF_HELPER" ]] || { echo "FAIL: proof helper not found at $PROOF_HELPER" >&2; return 1; }
  [[ -f "$COMPOSE_FILE" ]] || { echo "FAIL: compose file not found at $COMPOSE_FILE" >&2; return 1; }
  [[ -f "$CAPABILITY_SOURCE/oas.json" ]] || {
    echo "FAIL: attach capability not found at $CAPABILITY_SOURCE" >&2
    return 1
  }
}

preflight
if [[ "${1:-}" == "--preflight" ]]; then
  exit
fi

OAS_ROOT="${OAS_TEST_ROOT:-}"
if [[ -z "$OAS_ROOT" ]]; then
  OAS_ROOT="$(oas root)"
fi
OAS_ROOT="$(canonical_dir "$OAS_ROOT")"
OAS_CLI="$OAS_ROOT/bin/oas.mjs"

AWID_PORT="${OAS_PROOF_AWID_PORT:-18110}"
AWEB_PORT="${OAS_PROOF_AWEB_PORT:-18100}"
POSTGRES_PORT="${OAS_PROOF_POSTGRES_PORT:-55433}"
AWID_URL="http://127.0.0.1:$AWID_PORT"
AWEB_URL="http://127.0.0.1:$AWEB_PORT"
PROJECT="${OAS_PROOF_PROJECT:-aweb-oas-retire-proof-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")

PROOF_ROOT="$(make_temp_dir)"
PROOF_HOME="$PROOF_ROOT/home"
CONFIG_PATH="$PROOF_HOME/.config/aw/config.yaml"
STAGING="$PROOF_ROOT/staging"
PRINCIPAL_WORKSPACE="$PROOF_ROOT/principal-workspace"
OBSERVER="$PROOF_ROOT/observer"
PRINCIPAL_HOME="$PROOF_ROOT/principal-store"
FIXTURE_REPO="$PROOF_ROOT/repo"
AGENTS_ROOT="$PROOF_ROOT/agents"
PROOF_BIN="$PROOF_ROOT/bin"
EVIDENCE="$PROOF_ROOT/evidence"
REPORT="${OAS_PROOF_REPORT:-${TMPDIR:-/tmp}/aweb-oas-attached-principal-proof-report.json}"
KEEP="${KEEP_OAS_PROOF:-0}"
mkdir -p "$PROOF_HOME" "$STAGING" "$PRINCIPAL_WORKSPACE" "$OBSERVER" "$PRINCIPAL_HOME" "$FIXTURE_REPO" "$AGENTS_ROOT" "$PROOF_BIN" "$EVIDENCE"

cleanup() {
  local status=$?
  set +e
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  if [[ "$KEEP" == "1" ]]; then
    echo "Proof workspace retained at $PROOF_ROOT" >&2
  else
    rm -rf "$PROOF_ROOT"
  fi
  return "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_loopback() {
  case "$1" in
    http://127.0.0.1:*|http://localhost:*) ;;
    *) fail "proof endpoint is not loopback: $1" ;;
  esac
}
require_loopback "$AWID_URL"
require_loopback "$AWEB_URL"
[[ -f "$OAS_CLI" ]] || fail "OAS CLI not found at $OAS_CLI"

json_value() {
  local path="$1" dotted="$2"
  python3 - "$path" "$dotted" <<'PY'
import json, sys
path, dotted = sys.argv[1:]
text = open(path, encoding="utf-8").read()
start = text.find("{")
if start < 0:
    raise SystemExit(f"no JSON object in {path}")
decoder = json.JSONDecoder()
document, _ = decoder.raw_decode(text[start:])
if isinstance(document, dict) and document.get("schemaVersion") == 1 and "result" in document:
    document = document["result"]
value = document
for component in dotted.split(".") if dotted else []:
    value = value[component]
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(value)
PY
}

url_component() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

binding_operation() {
  python3 - "$1" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
print(meta["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]["journal_operation"])
PY
}

normalize_json() {
  local input="$1" output="$2"
  python3 - "$input" "$output" <<'PY'
import json, sys
source, target = sys.argv[1:]
text = open(source, encoding="utf-8").read()
start = text.find("{")
if start < 0:
    raise SystemExit(f"no JSON object in {source}")
document, _ = json.JSONDecoder().raw_decode(text[start:])
if isinstance(document, dict) and document.get("schemaVersion") == 1 and "result" in document:
    document = document["result"]
with open(target, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

file_sha256() {
  python3 - "$1" <<'PY'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
PY
}

run_aw_in() {
  local directory="$1"
  shift
  (
    cd "$directory"
    env -u AWEB_IDENTITY_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      "$AW_BIN" "$@"
  )
}

run_observer_aw() {
  (
    cd "$OBSERVER"
    env -u AWEB_IDENTITY_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      "$AW_BIN" "$@"
  )
}

run_oas_in() {
  local directory="$1"
  shift
  (
    cd "$directory"
    env -u AWEB_IDENTITY_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      AWEB_PRINCIPAL_HOME="$PRINCIPAL_HOME" \
      PI_AGENTS_ROOT="$AGENTS_ROOT" \
      PI_AGENTS_TMUX_SESSION="oas-retire-proof-no-session" \
      PATH="$PROOF_BIN:$CLI_DIR:$PATH" \
      node "$OAS_CLI" "$@"
  )
}

wait_health() {
  local label="$1" url="$2"
  local attempt
  for attempt in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  $label healthy"
      return 0
    fi
    sleep 2
  done
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --tail=50 >&2 || true
  fail "$label did not become healthy at $url"
}

capture_registry() {
  local phase="$1"
  local prefix="$EVIDENCE/registry-$phase"
  curl -fsS "$AWID_URL/v1/namespaces/proof.local/addresses/resident" > "$prefix-address.raw.json"
  normalize_json "$prefix-address.raw.json" "$prefix-address.json"
  run_observer_aw id resolve "$DID_AW" --json > "$prefix-resolve.raw.json"
  normalize_json "$prefix-resolve.raw.json" "$prefix-resolve-envelope.json"
  python3 - "$prefix-resolve-envelope.json" "$prefix-resolve.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if "payload" in document:
    payload = document["payload"]
    projected = {
        "authoritative": document.get("authoritative"),
        "status": payload.get("status"),
        "registry_url": payload.get("registry_url"),
        **payload["did_key"],
    }
else:
    projected = document
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(projected, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  run_observer_aw id verify "$DID_AW" --json > "$prefix-verify.raw.json"
  normalize_json "$prefix-verify.raw.json" "$prefix-verify.json"
  python3 - "$prefix-address.json" "$prefix-resolve.json" "$prefix-verify.json" "$DID_AW" "$DID_KEY" <<'PY'
import json, sys
address_path, resolve_path, verify_path, expected_stable, expected_key = sys.argv[1:]
address = json.load(open(address_path, encoding="utf-8"))
resolution = json.load(open(resolve_path, encoding="utf-8"))
verification = json.load(open(verify_path, encoding="utf-8"))
assert address["domain"] == "proof.local"
assert address["name"] == "resident"
assert address["did_aw"] == expected_stable
assert address["current_did_key"] == expected_key
assert resolution["did_aw"] == expected_stable
assert resolution["current_did_key"] == expected_key
assert resolution.get("status", "ok").lower() == "ok"
assert resolution.get("authoritative", True) is True
assert verification["did_aw"] == expected_stable
assert verification["current_did_key"] == expected_key
assert verification["status"] == "OK"
assert verification["entry_count"] >= 1
PY
}

compare_registry_to_pre() {
  local phase="$1"
  for kind in address resolve verify; do
    cmp "$EVIDENCE/registry-pre-$kind.json" "$EVIDENCE/registry-$phase-$kind.json" >/dev/null \
      || fail "registry $kind changed between pre and $phase"
  done
}

assert_principal_unchanged() {
  local phase="$1"
  python3 "$PROOF_HELPER" assert-unchanged --root "$PRINCIPAL_DIR" --snapshot "$EVIDENCE/principal-pre.json"
  echo "  principal store unchanged at $phase"
}

scan_instance() {
  local phase="$1"
  python3 "$PROOF_HELPER" scan-instance --principal-snapshot "$EVIDENCE/principal-pre.json" --instance "$INSTANCE_HOME"
  echo "  instance contains no principal material at $phase"
}

scan_provisioned_material() {
  local operation="$1" label="$2"
  shift 2
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local target snapshot controlled
  target="$(json_value "$intent" resource.identity_home)"
  snapshot="$EVIDENCE/$label-credential-snapshot.json"
  python3 "$PROOF_HELPER" snapshot --root "$target" --output "$snapshot"
  for controlled in "$@"; do
    python3 "$PROOF_HELPER" scan-instance --principal-snapshot "$snapshot" --instance "$controlled"
  done
}

seed_provision_lifecycle_artifacts() {
  local operation="$1"
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local alias agent workspace encoded_team encoded_alias coordinates_ttl
  alias="$(json_value "$intent" resource.alias)"
  agent="$(json_value "$intent" resource.agent_id)"
  workspace="$(json_value "$intent" resource.workspace_id)"
  docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -v ON_ERROR_STOP=1 -q -c \
    "INSERT INTO aweb.task_claims(team_id, workspace_id, alias, task_ref) VALUES ('$TEAM_ID', '$workspace', '$alias', 'proof-$operation');
     INSERT INTO aweb.reservations(team_id, resource_key, holder_alias, holder_agent_id) VALUES ('$TEAM_ID', 'proof:$operation', '$alias', '$agent');"
  encoded_team="$(url_component "$TEAM_ID")"
  encoded_alias="$(url_component "$alias")"
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence:$workspace" workspace_id "$workspace" alias "$alias" team_id "$TEAM_ID" repo_id "" current_branch "" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence_coordinates:$workspace" \
    "set:idx:all_workspaces" 1 \
    "set:idx:team_workspaces:$TEAM_ID" 1 \
    "alias:idx:alias:$encoded_team:$encoded_alias" "$workspace" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SADD idx:all_workspaces "$workspace" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SADD "idx:team_workspaces:$TEAM_ID" "$workspace" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SET "idx:alias:$encoded_team:$encoded_alias" "$workspace" EX 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli EXPIRE idx:all_workspaces 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli EXPIRE "idx:team_workspaces:$TEAM_ID" 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli PERSIST "presence_coordinates:$workspace" >/dev/null
  [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$workspace';")" == "1" ]] \
    || fail "task-claim positive control was not created for $operation"
  [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.reservations WHERE holder_agent_id = '$agent';")" == "1" ]] \
    || fail "reservation positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "1" ]] \
    || fail "presence positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "1" ]] \
    || fail "team presence index positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli GET "idx:alias:$encoded_team:$encoded_alias")" == "$workspace" ]] \
    || fail "alias presence index positive control was not created for $operation"
  docker exec "$REDIS_CONTAINER" redis-cli DEL "presence:$workspace" >/dev/null
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "0" ]] \
    || fail "primary presence did not expire before lifecycle cleanup for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "1" ]] \
    || fail "durable presence coordinates were not retained after primary expiry for $operation"
  coordinates_ttl="$(docker exec "$REDIS_CONTAINER" redis-cli TTL "presence_coordinates:$workspace")"
  [[ "$coordinates_ttl" == "-1" ]] \
    || fail "presence cleanup coordinates are not durable until explicit cleanup for $operation"
  if [[ "$operation" == "$VICTIM_OPERATION" ]]; then
    docker exec "$REDIS_CONTAINER" redis-cli DEL "presence_coordinates:$workspace" >/dev/null
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "0" ]] \
      || fail "pre-coordinate fallback fixture retained reverse coordinates for $operation"
  fi
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$workspace")" == "1" ]] \
    || fail "global presence index did not outlive primary for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "1" ]] \
    || fail "team presence index did not outlive primary for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli GET "idx:alias:$encoded_team:$encoded_alias")" == "$workspace" ]] \
    || fail "alias presence index did not outlive primary for $operation"
}

capture_provision_resource() {
  local phase="$1" operation="$2" expected="$3"
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local alias certificate agent workspace target encoded_team encoded_alias
  alias="$(json_value "$intent" resource.alias)"
  certificate="$(json_value "$intent" resource.certificate_id)"
  agent="$(json_value "$intent" resource.agent_id)"
  workspace="$(json_value "$intent" resource.workspace_id)"
  target="$(json_value "$intent" resource.identity_home)"
  encoded_team="$(url_component "$TEAM_ID")"
  encoded_alias="$(url_component "$alias")"

  run_observer_aw id team members --team-id "$TEAM_ID" --registry "$AWID_URL" \
    --include-revoked --json > "$EVIDENCE/$phase-members.raw.json"
  normalize_json "$EVIDENCE/$phase-members.raw.json" "$EVIDENCE/$phase-members.json"
  python3 - "$EVIDENCE/$phase-members.json" "$alias" "$certificate" "$expected" <<'PY'
import json, sys
path, alias, certificate, expected = sys.argv[1:]
document = json.load(open(path, encoding="utf-8"))
rows = [row for row in document["members"] if row["alias"] == alias and row["certificate_id"] == certificate]
assert len(rows) == 1, rows
revoked = bool(rows[0].get("revoked_at"))
assert revoked == (expected == "deleted"), rows[0]
PY

  local agent_row workspace_row
  agent_row="$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -F '|' -c \
    "SELECT status, deleted_at IS NOT NULL FROM aweb.agents WHERE agent_id = '$agent';")"
  workspace_row="$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -F '|' -c \
    "SELECT deleted_at IS NOT NULL FROM aweb.workspaces WHERE workspace_id = '$workspace';")"
  if [[ "$expected" == "active" ]]; then
    [[ "$agent_row" == "active|f" ]] || fail "$phase agent is not active at owning aweb authority: $agent_row"
    [[ "$workspace_row" == "f" ]] || fail "$phase workspace is not active at owning aweb authority: $workspace_row"
  else
    [[ "$agent_row" == "deleted|t" ]] || fail "$phase agent is not soft-deleted at owning aweb authority: $agent_row"
    [[ "$workspace_row" == "t" ]] || fail "$phase workspace is not soft-deleted at owning aweb authority: $workspace_row"
    [[ -f "$target/provision-operation.json" ]] || fail "$phase retained operation audit is missing"
    [[ "$(find "$target" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" == "1" ]] \
      || fail "$phase credential tree retains material beyond the operation audit"
    if [[ -d "$PROOF_HOME/.config/aw/team-invites" ]] && grep -R -F -q "$operation" "$PROOF_HOME/.config/aw/team-invites"; then
      fail "$phase still has a usable local invite grant for $operation"
    fi
    [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$workspace';")" == "0" ]] \
      || fail "$phase retained a live task claim"
    [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.reservations WHERE holder_agent_id = '$agent';")" == "0" ]] \
      || fail "$phase retained a live reservation"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "0" ]] \
      || fail "$phase retained workspace presence"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "0" ]] \
      || fail "$phase retained durable presence cleanup coordinates"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$workspace")" == "0" ]] \
      || fail "$phase retained the global presence index"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "0" ]] \
      || fail "$phase retained the team presence index"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "idx:alias:$encoded_team:$encoded_alias")" == "0" ]] \
      || fail "$phase retained the alias presence index"
    [[ "$(json_value "$intent" state)" == "complete" ]] || fail "$phase external journal is not terminal complete"
  fi
}

run_reconcile() {
  (
    cd "$FIXTURE_REPO"
    env -u OAS_EVENT -u OAS_META -u OAS_SETTINGS -u AWEB_IDENTITY_HOME \
      HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 \
      AWEB_PRINCIPAL_HOME="$PRINCIPAL_HOME" PATH="$PROOF_BIN:$CLI_DIR:$PATH" \
      node "$OAS_CLI" aweb-identity reconcile "$@"
  )
}

echo "=== Build the real aw CLI ==="
make -C "$CLI_DIR" build
[[ -x "$AW_BIN" ]] || fail "aw binary was not built at $AW_BIN"
printf '#!/bin/sh\nexit 0\n' > "$PROOF_BIN/pi"
chmod +x "$PROOF_BIN/pi"

echo "=== Start a fresh loopback tmpfs-backed AWID + aweb stack ==="
export LIBRARY_E2E_AWID_PORT="$AWID_PORT"
export LIBRARY_E2E_AWEB_PORT="$AWEB_PORT"
export LIBRARY_E2E_POSTGRES_PORT="$POSTGRES_PORT"
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="$AWID_URL"
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="$AWEB_URL"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up --build -d awid aweb
wait_health awid "$AWID_URL/health"
wait_health aweb "$AWEB_URL/health"
POSTGRES_CONTAINER="$("${COMPOSE[@]}" ps -q postgres)"
REDIS_CONTAINER="$("${COMPOSE[@]}" ps -q redis)"
[[ -n "$POSTGRES_CONTAINER" ]] || fail "proof postgres container is missing"
[[ -n "$REDIS_CONTAINER" ]] || fail "proof redis container is missing"
docker inspect -f '{{json .HostConfig.Tmpfs}}' "$POSTGRES_CONTAINER" | grep -q '/var/lib/postgresql/data' \
  || fail "proof postgres does not use tmpfs"

echo "=== Create a new throwaway durable principal only on the local stack ==="
run_aw_in "$STAGING" id create --name resident --domain proof.local --registry "$AWID_URL" --skip-dns-verify --json > "$EVIDENCE/create.json"
DID_AW="$(json_value "$EVIDENCE/create.json" did_aw)"
DID_KEY="$(json_value "$EVIDENCE/create.json" did_key)"
ADDRESS="$(json_value "$EVIDENCE/create.json" address)"
[[ "$DID_AW" == did:aw:* ]] || fail "identity creation returned no did:aw"
[[ "$DID_KEY" == did:key:* ]] || fail "identity creation returned no did:key"
[[ "$ADDRESS" == "proof.local/resident" ]] || fail "unexpected principal address: $ADDRESS"
PRINCIPAL_ID="${DID_AW#did:aw:}"
PRINCIPAL_DIR="$PRINCIPAL_HOME/proofteam/proof.local/$PRINCIPAL_ID"
mkdir -p "$PRINCIPAL_DIR"
mv "$STAGING/.aw" "$PRINCIPAL_WORKSPACE/.aw"

run_aw_in "$PRINCIPAL_WORKSPACE" id team create --name proofteam --namespace proof.local --registry "$AWID_URL" --json > "$EVIDENCE/team-create.json"
TEAM_ID="$(json_value "$EVIDENCE/team-create.json" team_id)"
[[ "$TEAM_ID" == "proofteam:proof.local" ]] || fail "unexpected team id: $TEAM_ID"
run_aw_in "$PRINCIPAL_WORKSPACE" id team invite --team proofteam --namespace proof.local --member-global --json > "$EVIDENCE/principal-invite.json"
PRINCIPAL_INVITE="$(json_value "$EVIDENCE/principal-invite.json" token)"
run_aw_in "$PRINCIPAL_WORKSPACE" id team accept-invite "$PRINCIPAL_INVITE" --global --name resident --json > "$EVIDENCE/principal-accept.json"
run_aw_in "$PRINCIPAL_WORKSPACE" init --url "$AWEB_URL" > "$EVIDENCE/principal-init.txt"

# A distinct initialized workspace triggers the gone-workspace sweep after retire.
run_observer_aw id create --name observer --domain proof.local --registry "$AWID_URL" --skip-dns-verify --json > "$EVIDENCE/observer-create.json"
run_aw_in "$PRINCIPAL_WORKSPACE" id team invite --team proofteam --namespace proof.local --member-global --json > "$EVIDENCE/observer-invite.json"
OBSERVER_INVITE="$(json_value "$EVIDENCE/observer-invite.json" token)"
run_observer_aw id team accept-invite "$OBSERVER_INVITE" --global --name observer --json > "$EVIDENCE/observer-accept.json"
run_observer_aw init --url "$AWEB_URL" > "$EVIDENCE/observer-init.txt"

mv "$PRINCIPAL_WORKSPACE/.aw" "$PRINCIPAL_DIR/credentials"
mkdir -p "$PRINCIPAL_DIR/state"
printf '{"proof":"durable-principal-state"}\n' > "$PRINCIPAL_DIR/state/proof.json"
CREDENTIALS="$PRINCIPAL_DIR/credentials"
STATE="$PRINCIPAL_DIR/state"

python3 "$PROOF_HELPER" snapshot --root "$PRINCIPAL_DIR" --output "$EVIDENCE/principal-pre.json"
capture_registry pre

echo "=== Materialize a real OAS instance with attach mode and no session launch ==="
mkdir -p "$AGENTS_ROOT/proof-resident/soul" "$AGENTS_ROOT/proof-resident/instances"
printf 'name: proof-resident\nkind: persistent\nrepo: %s\nwork: checkout\nruntime: pi\n' "$FIXTURE_REPO" > "$AGENTS_ROOT/proof-resident/soul/soul.yaml"
printf '# Throwaway proof soul\n' > "$AGENTS_ROOT/proof-resident/soul/AGENTS.md"
mkdir -p "$FIXTURE_REPO/.agents/capabilities/owned"
cp -R "$CAPABILITY_SOURCE" "$FIXTURE_REPO/.agents/capabilities/owned/aweb-identity-attach"
mkdir -p "$FIXTURE_REPO/oas/agents/proof-resident/principals"
cat > "$FIXTURE_REPO/oas/agents/proof-resident/principals/resident.yaml" <<EOF
schema_version: 1
address: $ADDRESS
stable_id: $DID_AW
team_id: $TEAM_ID
soul: proof-resident
EOF
cat > "$FIXTURE_REPO/oas-config.yaml" <<'EOF'
capabilities:
  layers:
    messaging:
      capability: aweb.identity-attach
      global:
        enabled: true
        settings:
          identity_binding:
            schema_version: 1
            mode: attach
            principal: resident
EOF
(
  cd "$FIXTURE_REPO"
  git init -q
  git config user.email proof@example.invalid
  git config user.name "OAS attach proof"
  git add .
  git commit -qm "throwaway attached-principal proof fixture"
)

run_oas_in "$FIXTURE_REPO" spawn proof-resident --purpose attached-principal-retire-proof --no-launch --json > "$EVIDENCE/oas-spawn.json"
INSTANCE_HOME="$(json_value "$EVIDENCE/oas-spawn.json" home)"
INSTANCE_NAME="$(json_value "$EVIDENCE/oas-spawn.json" instance)"
[[ -d "$INSTANCE_HOME" ]] || fail "OAS did not create the instance home"
python3 - "$EVIDENCE/oas-spawn.json" "$INSTANCE_HOME/instance.json" "$ADDRESS" "$DID_AW" "$TEAM_ID" "$PRINCIPAL_HOME" "$PRINCIPAL_DIR" "$CREDENTIALS" "$STATE" <<'PY'
import json, sys
spawn_path, meta_path, address, stable, team, home, principal, credentials, state = sys.argv[1:]
spawn = json.load(open(spawn_path, encoding="utf-8"))
if spawn.get("schemaVersion") == 1:
    spawn = spawn["result"]
assert spawn.get("warnings", []) == []
meta = json.load(open(meta_path, encoding="utf-8"))
binding = meta["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]
assert binding["schema_version"] == 1
assert binding["mode"] == "attach"
assert binding["cleanup_owner"] == "external"
assert binding["principal"] == "resident"
assert binding["address"] == address
assert binding["stable_id"] == stable
assert binding["team_id"] == team
assert binding["soul"] == "proof-resident"
assert binding["store"] == {"home": home, "principal": principal, "credentials": credentials, "state": state}
PY
assert_principal_unchanged after-spawn
scan_instance after-spawn

echo "=== Use the attached principal directly from the scaffolded instance ==="
(
  cd "$INSTANCE_HOME"
  env -u AWEB_IDENTITY_HOME \
    HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 \
    "$AW_BIN" --identity-home "$CREDENTIALS" whoami --json
) > "$EVIDENCE/instance-whoami.raw.json"
normalize_json "$EVIDENCE/instance-whoami.raw.json" "$EVIDENCE/instance-whoami.json"
python3 - "$EVIDENCE/instance-whoami.json" "$ADDRESS" "$DID_AW" <<'PY'
import json, sys
identity = json.load(open(sys.argv[1], encoding="utf-8"))
assert identity["address"] == sys.argv[2]
assert identity["stable_id"] == sys.argv[3]
PY
assert_principal_unchanged after-direct-whoami
scan_instance after-direct-whoami

echo "=== Retire through the ordinary production lifecycle ==="
run_oas_in "$FIXTURE_REPO" retire "$INSTANCE_NAME" --json > "$EVIDENCE/oas-retire.json"
[[ ! -e "$INSTANCE_HOME" ]] || fail "ordinary retire did not remove the disposable instance"
python3 - "$EVIDENCE/oas-retire.json" "$ADDRESS" "$DID_AW" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
assert document.get("warnings", []) == []
meta = document["capabilityMeta"]["aweb.identity-attach"]
assert meta["identity_binding"]["address"] == sys.argv[2]
assert meta["identity_binding"]["stable_id"] == sys.argv[3]
assert meta["identity_binding"]["cleanup_owner"] == "external"
assert meta["retirement"] == {"action": "preserve_principal", "cleanup_owner": "external"}
PY
assert_principal_unchanged after-retire
capture_registry after-retire
compare_registry_to_pre after-retire

echo "=== Trigger gone-workspace cleanup from an independent workspace ==="
run_observer_aw workspace status --json > "$EVIDENCE/observer-status.raw.json" 2> "$EVIDENCE/observer-status.stderr"
normalize_json "$EVIDENCE/observer-status.raw.json" "$EVIDENCE/observer-status.json"
python3 - "$EVIDENCE/observer-status.json" "$INSTANCE_HOME" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
instance = sys.argv[2]
def walk(value):
    if isinstance(value, dict):
        if value.get("workspace_path") == instance:
            raise AssertionError(f"disposable instance path was registered as a workspace: {instance}")
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
walk(document)
PY
assert_principal_unchanged after-gone-workspace-sweep
capture_registry after-cleanup
compare_registry_to_pre after-cleanup

echo "=== Provision two disposable identities on the real stack ==="
cat > "$FIXTURE_REPO/oas-config.yaml" <<'EOF'
capabilities:
  layers:
    messaging:
      capability: aweb.identity-attach
      global:
        enabled: true
        settings:
          identity_binding:
            schema_version: 2
            mode: provision-disposable
            minting_authority: resident
            minting_authority_path: local-controller
EOF
(
  cd "$FIXTURE_REPO"
  git add oas-config.yaml
  git commit -qm "exercise local disposable provisioning"
)
run_oas_in "$FIXTURE_REPO" spawn proof-resident --purpose real-delete-victim --no-launch --json > "$EVIDENCE/provision-victim-spawn.json"
VICTIM_HOME="$(json_value "$EVIDENCE/provision-victim-spawn.json" home)"
VICTIM_INSTANCE="$(json_value "$EVIDENCE/provision-victim-spawn.json" instance)"
VICTIM_OPERATION="$(binding_operation "$VICTIM_HOME/instance.json")"
run_oas_in "$FIXTURE_REPO" spawn proof-resident --purpose forged-receipt-carrier --no-launch --json > "$EVIDENCE/provision-attacker-spawn.json"
ATTACKER_HOME="$(json_value "$EVIDENCE/provision-attacker-spawn.json" home)"
ATTACKER_INSTANCE="$(json_value "$EVIDENCE/provision-attacker-spawn.json" instance)"
ATTACKER_OPERATION="$(binding_operation "$ATTACKER_HOME/instance.json")"
scan_provisioned_material "$VICTIM_OPERATION" victim "$VICTIM_HOME" "$ATTACKER_HOME" "$FIXTURE_REPO"
scan_provisioned_material "$ATTACKER_OPERATION" attacker "$ATTACKER_HOME" "$VICTIM_HOME" "$FIXTURE_REPO"
capture_provision_resource victim-before-forgery "$VICTIM_OPERATION" active
capture_provision_resource attacker-before-forgery "$ATTACKER_OPERATION" active

VICTIM_INTENT="$PRINCIPAL_HOME/.provisioning/intents/$VICTIM_OPERATION.json"
ATTACKER_INTENT="$PRINCIPAL_HOME/.provisioning/intents/$ATTACKER_OPERATION.json"
VICTIM_ALIAS="$(json_value "$VICTIM_INTENT" alias)"
VICTIM_TARGET="$(json_value "$VICTIM_INTENT" identity_home)"
AUTHORITY_HOME="$(json_value "$VICTIM_INTENT" authority_home)"
AUTHORITY_ADDRESS="$(json_value "$VICTIM_INTENT" authority.intended_creator.address)"
AUTHORITY_STABLE="$(json_value "$VICTIM_INTENT" authority.intended_creator.stable_id)"
CONTROLLER_DID="$(json_value "$VICTIM_INTENT" authority.controller_did)"
set +e
(
  cd "$ATTACKER_HOME"
  env -u AWEB_IDENTITY_HOME HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 \
    "$AW_BIN" id team cleanup-local-provision \
      --operation-id "$ATTACKER_OPERATION" --team-id "$TEAM_ID" --name "$VICTIM_ALIAS" \
      --authority-identity-home "$AUTHORITY_HOME" --target-identity-home "$VICTIM_TARGET" \
      --authority-address "$AUTHORITY_ADDRESS" --authority-stable-id "$AUTHORITY_STABLE" \
      --controller-did "$CONTROLLER_DID" --json
) > "$EVIDENCE/forged-execution-cleanup.txt" 2>&1
FORGED_EXECUTION_STATUS=$?
set -e
# Query the owning authorities before checking the local error. Under the guard
# mutation this is the deliberately destructive red assertion.
capture_provision_resource victim-after-forged-execution "$VICTIM_OPERATION" active
[[ "$FORGED_EXECUTION_STATUS" -ne 0 ]] || fail "forged execution cleanup unexpectedly succeeded"
grep -q "target record contradicts the requested operation" "$EVIDENCE/forged-execution-cleanup.txt" \
  || fail "forged execution cleanup was refused by the wrong boundary"

# The instance-side receipt is not cleanup authority. Retarget the attacker's
# valid receipt to the independently provisioned victim while leaving the
# capability corroboration operation-specific.
python3 - "$ATTACKER_HOME/instance.json" "$VICTIM_HOME/instance.json" <<'PY'
import json, sys
attacker_path, victim_path = sys.argv[1:]
attacker = json.load(open(attacker_path, encoding="utf-8"))
victim = json.load(open(victim_path, encoding="utf-8"))
attacker["capabilityMeta"]["aweb.identity-attach"]["identity_binding"] = victim["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]
with open(attacker_path, "w", encoding="utf-8") as stream:
    json.dump(attacker, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "=== Refuse the forged victim, then execute authorized cleanup ==="
run_oas_in "$FIXTURE_REPO" retire "$ATTACKER_INSTANCE" --json > "$EVIDENCE/forged-retire.json"
capture_provision_resource victim-after-forged-retire "$VICTIM_OPERATION" active
capture_provision_resource attacker-after-forged-retire "$ATTACKER_OPERATION" active
python3 - "$EVIDENCE/forged-retire.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
retirement = document["capabilityMeta"]["aweb.identity-attach"]["retirement"]
assert retirement["action"] == "preserve", retirement
assert retirement["cleanup_authorized"] is False, retirement
assert retirement["reason"] == "cleanup_corroboration_missing_or_mismatched", retirement
PY

seed_provision_lifecycle_artifacts "$VICTIM_OPERATION"
run_oas_in "$FIXTURE_REPO" retire "$VICTIM_INSTANCE" --json > "$EVIDENCE/authorized-retire.json"
python3 - "$EVIDENCE/authorized-retire.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
assert document.get("warnings", []) == [], document
retirement = document["capabilityMeta"]["aweb.identity-attach"]["retirement"]
assert retirement["action"] == "cleanup_complete", retirement
assert retirement["cleanup"]["status"] == "complete", retirement
PY
capture_provision_resource victim-after-authorized-retire "$VICTIM_OPERATION" deleted

# The forged carrier's ordinary instance is gone, so its genuinely owned bound
# identity is an operator-confirmed unacknowledged handoff. Exercise the
# native active/trust-gated exact-operation command rather than a direct bin.
seed_provision_lifecycle_artifacts "$ATTACKER_OPERATION"
run_reconcile --cleanup-unacknowledged "$ATTACKER_OPERATION" > "$EVIDENCE/operator-reconcile.json"
capture_provision_resource attacker-after-operator-reconcile "$ATTACKER_OPERATION" deleted

echo "=== Write proof report ==="
SOURCE_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
OAS_SHA="$(git -C "$OAS_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
SNAPSHOT_SHA="$(file_sha256 "$EVIDENCE/principal-pre.json")"
ADDRESS_SHA="$(file_sha256 "$EVIDENCE/registry-pre-address.json")"
RESOLVE_SHA="$(file_sha256 "$EVIDENCE/registry-pre-resolve.json")"
VERIFY_SHA="$(file_sha256 "$EVIDENCE/registry-pre-verify.json")"
mkdir -p "$(dirname "$REPORT")"
python3 - "$REPORT" "$SOURCE_SHA" "$OAS_SHA" "$ADDRESS" "$DID_AW" "$TEAM_ID" "$SNAPSHOT_SHA" "$ADDRESS_SHA" "$RESOLVE_SHA" "$VERIFY_SHA" "$EVIDENCE/registry-pre-address.json" "$EVIDENCE/registry-pre-resolve.json" "$EVIDENCE/registry-pre-verify.json" "$VICTIM_OPERATION" "$ATTACKER_OPERATION" <<'PY'
import json, sys
(report, source, oas_source, address, stable, team, snapshot_sha, address_sha, resolve_sha, verify_sha,
 address_path, resolve_path, verify_path, victim_operation, attacker_operation) = sys.argv[1:]
address_observation = json.load(open(address_path, encoding="utf-8"))
resolve_observation = json.load(open(resolve_path, encoding="utf-8"))
verify_observation = json.load(open(verify_path, encoding="utf-8"))
document = {
    "schema": "aweb.oas-principal-lifecycle-proof.v2",
    "source_sha": source,
    "oas_kernel_sha": oas_source,
    "stack": {"loopback_only": True, "postgres_tmpfs_verified": True},
    "principal": {"address": address, "stable_id": stable, "team_id": team, "throwaway": True},
    "attach_observation": {
        "production_entry": "oas spawn --no-launch",
        "credential_declaration_agreement": True,
        "registry_verification_attributed_to_attach": False,
    },
    "retire_observation": {
        "production_entry": "ordinary oas retire",
        "cleanup_owner": "external",
        "receipt": "preserve_principal",
        "instance_removed": True,
    },
    "provision_cleanup_observation": {
        "authority_path": "local-controller",
        "threat_demonstrated": "local-same-uid-accident-and-confused-deputy",
        "victim_operation": victim_operation,
        "forged_execution_refused_by": "target operation-record mismatch",
        "forged_receipt_refused_by": "cleanup_corroboration_missing_or_mismatched",
        "victim_remained_active_after_both_forged_paths": True,
        "authorized_retire_deleted_victim": True,
        "attacker_operation": attacker_operation,
        "native_manifest_command_deleted_unacknowledged_attacker": True,
        "positive_lifecycle_controls_removed": ["PostgreSQL task claim", "PostgreSQL reservation", "Redis expired-primary cleanup coordinates", "Redis global presence index", "Redis team presence index", "Redis alias presence index"],
        "not_created_by_no_launch_provision": ["aweb API key", "message", "delivery record"],
        "provisioned_material_copy_hardlink_symlink_scan_passed": True,
        "external_journals_terminal_complete": True,
        "owning_authorities_queried": ["AWID certificate roster", "aweb PostgreSQL lifecycle state", "aweb Redis presence", "local credential and invite stores", "external provision journal"],
    },
    "independent_observations": {
        "registry_address_unchanged": True,
        "registry_resolution_unchanged": True,
        "did_log_verified_pre_post": True,
        "gone_workspace_sweep_completed": True,
        "principal_store_unchanged": True,
        "instance_copy_hardlink_symlink_scan_passed": True,
        "principal_snapshot_sha256": snapshot_sha,
        "registry_address_sha256": address_sha,
        "registry_resolution_sha256": resolve_sha,
        "did_log_verification_sha256": verify_sha,
        "registry_address": address_observation,
        "registry_resolution": resolve_observation,
        "did_log_verification": verify_observation,
    },
    "limitations": [
        "no model session was launched; --no-launch skips only session launch, not lifecycle hooks",
        "OAS_SETTINGS binding is config-scoped",
        "v1 has no admission lease or concurrent-use fencing",
        "attach itself performs no registry resolution or DID-log verification",
        "local cleanup corroboration is same-UID accident/confused-deputy evidence, not hostile-model resistance",
    ],
}
with open(report, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "PROOF PASSED"
echo "  report: $REPORT"
echo "  principal: $ADDRESS ($DID_AW)"
echo "  principal snapshot sha256: $SNAPSHOT_SHA"
echo "  registry address sha256: $ADDRESS_SHA"
echo "  registry resolution sha256: $RESOLVE_SHA"
echo "  DID-log verification sha256: $VERIFY_SHA"
