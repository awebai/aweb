#!/usr/bin/env bash
# Prove, on a fresh local tmpfs-backed stack, that ordinary OAS retirement of
# an externally attached principal cannot alter or delete that principal.
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
OAS_ROOT="${OAS_TEST_ROOT:-}"
if [[ -z "$OAS_ROOT" ]]; then
  OAS_ROOT="$(oas root)"
fi
OAS_ROOT="$(canonical_dir "$OAS_ROOT")"
OAS_CLI="$OAS_ROOT/bin/oas.mjs"
CAPABILITY_SOURCE="$REPO_ROOT/oas/.agents/capabilities/owned/aweb-identity-attach"

AWID_PORT="${OAS_PROOF_AWID_PORT:-18110}"
AWEB_PORT="${OAS_PROOF_AWEB_PORT:-18100}"
POSTGRES_PORT="${OAS_PROOF_POSTGRES_PORT:-55433}"
AWID_URL="http://127.0.0.1:$AWID_PORT"
AWEB_URL="http://127.0.0.1:$AWEB_PORT"
PROJECT="${OAS_PROOF_PROJECT:-aweb-oas-retire-proof-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)}"
COMPOSE=(docker compose -p "$PROJECT" -f "$REPO_ROOT/docker-compose.e2e.yml")

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
[[ -d "$CAPABILITY_SOURCE" ]] || fail "attach capability not found at $CAPABILITY_SOURCE"
[[ -f "$PROOF_HELPER" ]] || fail "proof helper not found at $PROOF_HELPER"

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
[[ -n "$POSTGRES_CONTAINER" ]] || fail "proof postgres container is missing"
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

echo "=== Write proof report ==="
SOURCE_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
OAS_SHA="$(git -C "$OAS_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
SNAPSHOT_SHA="$(file_sha256 "$EVIDENCE/principal-pre.json")"
ADDRESS_SHA="$(file_sha256 "$EVIDENCE/registry-pre-address.json")"
RESOLVE_SHA="$(file_sha256 "$EVIDENCE/registry-pre-resolve.json")"
VERIFY_SHA="$(file_sha256 "$EVIDENCE/registry-pre-verify.json")"
mkdir -p "$(dirname "$REPORT")"
python3 - "$REPORT" "$SOURCE_SHA" "$OAS_SHA" "$ADDRESS" "$DID_AW" "$TEAM_ID" "$SNAPSHOT_SHA" "$ADDRESS_SHA" "$RESOLVE_SHA" "$VERIFY_SHA" "$EVIDENCE/registry-pre-address.json" "$EVIDENCE/registry-pre-resolve.json" "$EVIDENCE/registry-pre-verify.json" <<'PY'
import json, sys
(report, source, oas_source, address, stable, team, snapshot_sha, address_sha, resolve_sha, verify_sha,
 address_path, resolve_path, verify_path) = sys.argv[1:]
address_observation = json.load(open(address_path, encoding="utf-8"))
resolve_observation = json.load(open(resolve_path, encoding="utf-8"))
verify_observation = json.load(open(verify_path, encoding="utf-8"))
document = {
    "schema": "aweb.oas-attached-principal-retire-proof.v1",
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
