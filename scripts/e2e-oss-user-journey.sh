#!/usr/bin/env bash
#
# End-to-end OSS user journey test — team architecture.
#
# Simulates a new user who:
#   1. Starts awid + aweb in Docker
#   2. Creates a global identity (alice)
#   3. Registers a namespace, creates a team, invites bob
#   4. Both agents connect to aweb via certificate auth
#   5. Registers an externally controlled AWID team with the aweb service
#   6. Initializes existing team members through aw service init
#   7. Exercises mail, chat, tasks, locks
#   8. Revokes bob's membership and verifies rejection
#
# Usage:
#   ./scripts/e2e-oss-user-journey.sh
#
# Requirements:
#   - Docker and Docker Compose
#   - Go toolchain
#   - Ports 8100, 8110, 6399, 5452 available (or override via env)
#
# Environment overrides:
#   AWEB_E2E_PORT    aweb port  (default: 8100)
#   AWID_E2E_PORT    awid port  (default: 8110)
#   AWEB_E2E_REDIS   redis port (default: 6399)
#   AWEB_E2E_PG      postgres port (default: 5452)
#   AWEB_E2E_SEED_ERIN_CONTROLLER_KEY_LEAK
#                      test-only mutation: seed the production-resolved Erin
#                      controller-key path immediately before its real assertion

set -euo pipefail

canonicalize_dir() {
  local dir="$1"
  bash -c 'cd "$1" && pwd -P' _ "$dir"
}

make_temp_dir() {
  local prefix="$1"
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
  canonicalize_dir "$dir"
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SERVER_DIR="$REPO_ROOT/server"
CLI_DIR="$REPO_ROOT/cli/go"

AWEB_PORT="${AWEB_E2E_PORT:-8100}"
AWID_PORT="${AWID_E2E_PORT:-8110}"
REDIS_PORT="${AWEB_E2E_REDIS:-6399}"
PG_PORT="${AWEB_E2E_PG:-5452}"
AWEB_URL="http://localhost:$AWEB_PORT"
AWID_URL="http://localhost:$AWID_PORT"

# Isolated temp dirs
E2E_HOME="$(make_temp_dir aw-e2e-home)"
E2E_CWD="$(make_temp_dir aw-e2e-cwd)"
ALICE_DIR="$E2E_CWD/alice"
BOB_DIR="$E2E_CWD/bob"
NO_KEY_DIR="$E2E_CWD/nokey"
EVE_DIR="$E2E_CWD/eve"
CAROL_DIR="$E2E_CWD/carol"
DAVE_DIR="$E2E_CWD/dave"
GSK_DIR="$E2E_CWD/gsk"
REMOTE_ERIN_DIR="$E2E_CWD/remote-erin"
WRONG_DID_DIR="$E2E_CWD/wrong-did"
PARTNER_CONTROLLER_DIR="$E2E_CWD/partner-controller"
PARTNER_BOB_DIR="$E2E_CWD/partner-bob"
RECONNECT_DIR="$E2E_CWD/reconnect-alice"
WIZARD_BYOD_DIR="$E2E_CWD/wizard-byod"
SERVICE_CONTROLLER_DIR="$E2E_CWD/service-controller"
SERVICE_ALPHA_DIR="$E2E_CWD/service-alpha"
SERVICE_BETA_DIR="$E2E_CWD/service-beta"
BOOTSTRAP_PROJECT_DIR="$E2E_CWD/bootstrap-project"
BOOTSTRAP_TEMPLATE_DIR="$E2E_CWD/bootstrap-template"
BOOTSTRAP_LEGACY_TEMPLATE_DIR="$E2E_CWD/bootstrap-legacy-template"
BOOTSTRAP_LEGACY_WORK_DIR="$E2E_CWD/bootstrap-legacy-work"
REMOTE_ERIN_HOME="$(make_temp_dir aw-e2e-remote-erin-home)"
WRONG_DID_HOME="$(make_temp_dir aw-e2e-wrong-did-home)"
CAROL_NO_PIN_HOME="$(make_temp_dir aw-e2e-carol-no-pin-home)"
mkdir -p "$ALICE_DIR" "$BOB_DIR" "$NO_KEY_DIR" "$EVE_DIR" "$CAROL_DIR" "$DAVE_DIR" "$GSK_DIR" "$REMOTE_ERIN_DIR" "$WRONG_DID_DIR" "$PARTNER_CONTROLLER_DIR" "$PARTNER_BOB_DIR" "$RECONNECT_DIR" "$WIZARD_BYOD_DIR" "$SERVICE_CONTROLLER_DIR" "$SERVICE_ALPHA_DIR" "$SERVICE_BETA_DIR" "$BOOTSTRAP_PROJECT_DIR" "$BOOTSTRAP_TEMPLATE_DIR" "$BOOTSTRAP_LEGACY_TEMPLATE_DIR" "$BOOTSTRAP_LEGACY_WORK_DIR"
mkdir -p "$CAROL_NO_PIN_HOME/.config/aw"
ALICE_DIR="$(canonicalize_dir "$ALICE_DIR")"
BOB_DIR="$(canonicalize_dir "$BOB_DIR")"
EVE_DIR="$(canonicalize_dir "$EVE_DIR")"
CAROL_DIR="$(canonicalize_dir "$CAROL_DIR")"
DAVE_DIR="$(canonicalize_dir "$DAVE_DIR")"
GSK_DIR="$(canonicalize_dir "$GSK_DIR")"
REMOTE_ERIN_DIR="$(canonicalize_dir "$REMOTE_ERIN_DIR")"
WRONG_DID_DIR="$(canonicalize_dir "$WRONG_DID_DIR")"
PARTNER_CONTROLLER_DIR="$(canonicalize_dir "$PARTNER_CONTROLLER_DIR")"
PARTNER_BOB_DIR="$(canonicalize_dir "$PARTNER_BOB_DIR")"
RECONNECT_DIR="$(canonicalize_dir "$RECONNECT_DIR")"
WIZARD_BYOD_DIR="$(canonicalize_dir "$WIZARD_BYOD_DIR")"
SERVICE_CONTROLLER_DIR="$(canonicalize_dir "$SERVICE_CONTROLLER_DIR")"
SERVICE_ALPHA_DIR="$(canonicalize_dir "$SERVICE_ALPHA_DIR")"
SERVICE_BETA_DIR="$(canonicalize_dir "$SERVICE_BETA_DIR")"
BOOTSTRAP_PROJECT_DIR="$(canonicalize_dir "$BOOTSTRAP_PROJECT_DIR")"
BOOTSTRAP_TEMPLATE_DIR="$(canonicalize_dir "$BOOTSTRAP_TEMPLATE_DIR")"
BOOTSTRAP_LEGACY_TEMPLATE_DIR="$(canonicalize_dir "$BOOTSTRAP_LEGACY_TEMPLATE_DIR")"
BOOTSTRAP_LEGACY_WORK_DIR="$(canonicalize_dir "$BOOTSTRAP_LEGACY_WORK_DIR")"

pass=0
fail=0

cleanup() {
  local status=$?
  echo ""
  echo "--- Cleanup ---"
  if [[ -f "$SERVER_DIR/.env.e2e" ]]; then
    cd "$SERVER_DIR" && docker compose --env-file .env.e2e down -v 2>/dev/null || true
    rm -f "$SERVER_DIR/.env.e2e"
  fi
  rm -rf "$E2E_HOME" "$REMOTE_ERIN_HOME" "$WRONG_DID_HOME" "$CAROL_NO_PIN_HOME" "$E2E_CWD"
  echo ""
  if [[ $fail -gt 0 ]]; then
    echo "FAILED: $fail failures, $pass passed"
    exit 1
  elif [[ $status -ne 0 ]]; then
    echo "FAILED: script exited with status $status before recording an assertion failure ($pass passed)"
    exit "$status"
  else
    echo "ALL PASSED: $pass tests"
  fi
}
trap cleanup EXIT

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected '$expected', got '$actual')"
    fail=$((fail + 1))
  fi
}

assert_not_empty() {
  local label="$1" value="$2"
  if [[ -n "$value" ]]; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (empty)"
    fail=$((fail + 1))
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -q -- "$needle"; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected to contain '$needle', got: ${haystack:0:120})"
    fail=$((fail + 1))
  fi
}

assert_file_not_contains() {
  local label="$1" path="$2" needle="$3"
  if grep -q -- "$needle" "$path" 2>/dev/null; then
    echo "  FAIL: $label (did not expect '$needle' in $path)"
    fail=$((fail + 1))
  else
    echo "  PASS: $label"
    pass=$((pass + 1))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -q -- "$needle"; then
    echo "  FAIL: $label (did not expect '$needle', got: ${haystack:0:120})"
    fail=$((fail + 1))
  else
    echo "  PASS: $label"
    pass=$((pass + 1))
  fi
}

assert_file_exists() {
  local label="$1" path="$2"
  if [[ -f "$path" ]]; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (missing $path)"
    fail=$((fail + 1))
  fi
}

path_is_missing() {
  local path="$1"
  [[ ! -e "$path" ]]
}

assert_path_missing() {
  local label="$1" path="$2"
  if path_is_missing "$path"; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (unexpected $path)"
    fail=$((fail + 1))
  fi
}

assert_file_mode() {
  local label="$1" path="$2" expected="$3" actual
  actual="$(python3 - "$path" <<'PY'
import os, stat, sys
path = sys.argv[1]
try:
    print(f"{stat.S_IMODE(os.stat(path).st_mode):03o}")
except FileNotFoundError:
    print("")
PY
)"
  assert_eq "$label" "$expected" "$actual"
}

assert_status() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label (HTTP $actual)"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected HTTP $expected, got HTTP $actual)"
    fail=$((fail + 1))
  fi
}

# Run aw in the isolated environment with a specific working directory.
# Alice and bob share E2E_HOME so the team key and invites are accessible
# to both (simulates same-machine BYOD setup).
run_aw_with_home_in() {
  local home="$1" workdir="$2"
  shift 2
  HOME="$home" \
  AW_CONFIG_PATH="$home/.config/aw/config.yaml" \
  AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$CLI_DIR/aw" "$@"
}

run_aw_in() {
  local workdir="$1"
  shift
  run_aw_with_home_in "$E2E_HOME" "$workdir" "$@"
}

# Run aw for workspace-free commands (e.g. --help) that need only the binary.
# Uses the shared E2E_HOME as a neutral working directory.
run_aw() {
  run_aw_in "$E2E_HOME" "$@"
}

capture_success() {
  local output_var="$1" label="$2"
  shift 2
  local output status
  if output="$("$@" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  assert_eq "$label exit" "0" "$status"
  if [[ "$status" == "0" ]]; then
    printf -v "$output_var" "%s" "$output"
  else
    printf -v "$output_var" "%s" ""
    if [[ -n "$output" ]]; then
      echo "  $label output: ${output:0:240}"
    fi
  fi
  return 0
}

run_success() {
  local label="$1"
  shift
  local output status
  if output="$("$@" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  assert_eq "$label exit" "0" "$status"
  if [[ "$status" != "0" && -n "$output" ]]; then
    echo "  $label output: ${output:0:240}"
  fi
  return 0
}

# Like run_aw_in but strips AWID_REGISTRY_URL from the env so the CLI must
# fall back to identity.yaml's registry_url. Used by the aako-pattern
# reproducer to exercise the env-unset-with-identity-fallback code path
# (the aweb-aalg / aweb-aale bug-trigger condition).
run_aw_no_env_registry_in() {
  local workdir="$1"
  shift
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_SKIP_DNS_VERIFY=1 \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$CLI_DIR/aw" "$@"
}

# Run a specific aw binary (not necessarily the one built at Phase 0) in
# the isolated environment, with AWID_REGISTRY_URL stripped. Used for the
# aako-pattern reproducer's BASELINE mode where the sender CLI must come
# from a pre-aalg-fix worktree.
run_aw_bin_no_env_registry_in() {
  local aw_bin="$1" workdir="$2"
  shift 2
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_SKIP_DNS_VERIFY=1 \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$aw_bin" "$@"
}

run_aw_tty_in() {
  local workdir="$1" input="$2"
  shift 2
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 \
  python3 - "$workdir" "$input" "$CLI_DIR/aw" "$@" <<'PY'
import os
import pty
import sys

workdir = sys.argv[1]
input_data = sys.argv[2].encode()
argv = sys.argv[3:]
sent = [False]
os.chdir(workdir)

def stdin_read(_fd):
    if sent[0]:
        return b""
    sent[0] = True
    return input_data

status = pty.spawn(argv, stdin_read=stdin_read)
if hasattr(os, "waitstatus_to_exitcode"):
    sys.exit(os.waitstatus_to_exitcode(status))
sys.exit(status)
PY
}

jq_field() {
  # Extract the first JSON object from mixed output (CLI may print
  # non-JSON text before the JSON when --json is used).
  python3 -c "
import sys, json
text = sys.stdin.read()
start = text.find('{')
if start >= 0:
    try:
        d = json.loads(text[start:])
        print(d.get('$1', ''))
    except json.JSONDecodeError:
        print('')
else:
    print('')
"
}

set_inbound_mode() {
  local did_aw="$1" mode="$2"
  (
    cd "$SERVER_DIR"
    docker compose --env-file .env.e2e exec -T postgres \
      psql -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" \
      -c "UPDATE aweb.agents SET inbound_mode = '${mode}' WHERE did_aw = '${did_aw}';" >/dev/null
  )
}

psql_scalar() {
  local sql="$1"
  (
    cd "$SERVER_DIR"
    docker compose --env-file .env.e2e exec -T postgres \
      psql -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" \
      -Atq -v ON_ERROR_STOP=1 -c "$sql" 2>/dev/null | tr -d '\r' | tail -n 1
  )
}

psql_exec() {
  local sql="$1"
  (
    cd "$SERVER_DIR"
    docker compose --env-file .env.e2e exec -T postgres \
      psql -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" \
      -v ON_ERROR_STOP=1 -c "$sql" >/dev/null
  )
}

yaml_field() {
  python3 - "$1" "$2" <<'PY'
import sys

path, key = sys.argv[1], sys.argv[2]
prefix = key + ":"
try:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith(prefix):
                value = line.split(":", 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                print(value)
                break
except FileNotFoundError:
    pass
PY
}

workspace_membership_field() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys

path, team_id, field = sys.argv[1], sys.argv[2], sys.argv[3]
current_team = ""
in_memberships = False

try:
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped:
                continue
            if not in_memberships:
                if stripped == "memberships:":
                    in_memberships = True
                continue
            if not line.startswith("  "):
                break
            if stripped.startswith("- team_id:"):
                current_team = stripped.split(":", 1)[1].strip()
                continue
            if current_team != team_id:
                continue
            prefix = f"{field}:"
            if stripped.startswith(prefix):
                value = stripped.split(":", 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1]
                print(value)
                break
except FileNotFoundError:
    pass
PY
}

team_cert_path() {
  python3 - "$1" "$2" <<'PY'
import json
import os
import sys

workdir, team_id = sys.argv[1], sys.argv[2]
certs_dir = os.path.join(workdir, ".aw", "team-certs")
try:
    for name in sorted(os.listdir(certs_dir)):
        if not name.endswith(".pem"):
            continue
        path = os.path.join(certs_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                cert = json.load(f)
        except Exception:
            continue
        if (cert.get("team_id") or "").strip() == team_id:
            print(path)
            break
except FileNotFoundError:
    pass
PY
}

# ---------------------------------------------------------------------------
# Phase 0: Build CLI
# ---------------------------------------------------------------------------
echo "=== Phase 0: Build aw CLI ==="
cd "$CLI_DIR"
if ! make build 2>&1 | tail -5; then
  echo "  FATAL: CLI build failed"
  exit 1
fi
echo "  aw binary: $CLI_DIR/aw"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: Start awid + aweb in Docker
# ---------------------------------------------------------------------------
echo "=== Phase 1: Start awid + aweb in Docker ==="

cat > "$SERVER_DIR/.env.e2e" <<EOF
POSTGRES_USER=aweb
POSTGRES_PASSWORD=aweb-e2e-test
POSTGRES_DB=aweb
AWEB_PORT=$AWEB_PORT
AWID_PORT=$AWID_PORT
REDIS_PORT=$REDIS_PORT
POSTGRES_PORT=$PG_PORT
AWEB_PUBLIC_ORIGIN=$AWEB_URL
AWID_PUBLIC_REGISTRY_URL=$AWID_URL
APP_ENV=development
AWEB_FEDERATION_TEST=1
AWEB_FEDERATION_TEST_DEFAULT_REGISTRY=1
AWEB_LOG_JSON=true
AWID_LOG_JSON=true
AWID_ALLOW_INSECURE_DELIVERY_ORIGIN=1
AWID_RATE_LIMIT_BACKEND=redis
AWID_RATE_LIMIT_DISABLED=1
AWID_SKIP_DNS_VERIFY=1
EOF

cd "$SERVER_DIR"
docker compose --env-file .env.e2e down -v 2>/dev/null || true
docker compose --env-file .env.e2e build --no-cache
docker compose --env-file .env.e2e up -d

echo "Waiting for awid health..."
for i in $(seq 1 60); do
  if curl -sf "$AWID_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
awid_health="$(curl -sf "$AWID_URL/health" 2>/dev/null || echo '{}')"
awid_status="$(echo "$awid_health" | jq_field status)"
assert_eq "awid health" "ok" "$awid_status"

echo "Waiting for aweb health..."
for i in $(seq 1 60); do
  if curl -sf "$AWEB_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
aweb_health="$(curl -sf "$AWEB_URL/health" 2>/dev/null || echo '{}')"
aweb_status="$(echo "$aweb_health" | jq_field status)"
assert_eq "aweb health" "ok" "$aweb_status"

if [[ "$awid_status" != "ok" || "$aweb_status" != "ok" ]]; then
  echo "  Services not healthy, aborting."
  echo "  Docker logs:"
  cd "$SERVER_DIR" && docker compose --env-file .env.e2e logs 2>&1 | tail -30
  exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Phase 1b: Retired aw agents bootstrap family stays absent
# ---------------------------------------------------------------------------
echo "=== Phase 1b: Retired aw agents command family ==="

retired_agents_help="$(run_aw --help 2>&1)"
if echo "$retired_agents_help" | grep -qE '^  agents[[:space:]]'; then
  echo "  FAIL: retired aw agents command appears in top-level help"
  fail=$((fail + 1))
else
  echo "  PASS: retired aw agents command absent from top-level help"
  pass=$((pass + 1))
fi

retired_agents_output="$(run_aw agents --help 2>&1 || true)"
assert_contains "retired aw agents command is unavailable" "$retired_agents_output" "unknown command"

echo ""
# Phase 2: Create alice's identity
# ---------------------------------------------------------------------------
echo "=== Phase 2: Create alice's identity ==="

capture_success create_out "create_out" run_aw_in "$ALICE_DIR" id create \
  --name alice \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json

ALICE_DID_KEY="$(echo "$create_out" | jq_field did_key)"
ALICE_DID_AW="$(echo "$create_out" | jq_field did_aw)"
ALICE_ADDRESS="$(echo "$create_out" | jq_field address)"

assert_not_empty "alice did_key" "$ALICE_DID_KEY"
assert_not_empty "alice did_aw" "$ALICE_DID_AW"
assert_eq "alice address" "test.local/alice" "$ALICE_ADDRESS"
capture_success test_delivery_origin "test.local delivery origin" run_aw_in "$ALICE_DIR" \
  id namespace set-delivery-origin \
  --namespace test.local \
  --origin "$AWEB_URL" \
  --json
echo ""

# ---------------------------------------------------------------------------
# Phase 3: Create team
# ---------------------------------------------------------------------------
echo "=== Phase 3: Create team under test.local ==="

capture_success team_out "team_out" run_aw_in "$ALICE_DIR" id team create \
  --name devteam \
  --namespace test.local \
  --registry "$AWID_URL" \
  --json

TEAM_ID="$(echo "$team_out" | jq_field team_id)"
TEAM_DID_KEY="$(echo "$team_out" | jq_field team_did_key)"
TEAM_KEY_PATH="$(echo "$team_out" | jq_field team_key_path)"

assert_eq "team id" "devteam:test.local" "$TEAM_ID"
assert_not_empty "team did_key" "$TEAM_DID_KEY"
assert_not_empty "team key path from production resolver" "$TEAM_KEY_PATH"
echo ""

# ---------------------------------------------------------------------------
# Phase 4: Alice joins the team via invite/accept
# ---------------------------------------------------------------------------
echo "=== Phase 4: Alice joins team ==="

capture_success alice_invite_out "alice_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --global \
  --json

ALICE_INVITE_TOKEN="$(echo "$alice_invite_out" | jq_field token)"
assert_not_empty "alice invite token" "$ALICE_INVITE_TOKEN"

capture_success alice_accept_out "alice_accept_out" run_aw_in "$ALICE_DIR" id team accept-invite "$ALICE_INVITE_TOKEN" --global \
  --alias alice \
  --json

ALICE_ACCEPT_STATUS="$(echo "$alice_accept_out" | jq_field status)"
assert_eq "alice accepted" "accepted" "$ALICE_ACCEPT_STATUS"

# Verify cert was written
alice_cert_path="$(team_cert_path "$ALICE_DIR" "devteam:test.local")"
if [[ -f "$alice_cert_path" ]]; then
  echo "  PASS: alice cert saved"
  pass=$((pass + 1))
else
  echo "  FAIL: alice cert not found under $ALICE_DIR/.aw/team-certs for devteam:test.local"
  fail=$((fail + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 5: Verify alice's certificate
# ---------------------------------------------------------------------------
echo "=== Phase 5: Verify alice's certificate ==="

capture_success cert_out "cert_out" run_aw_in "$ALICE_DIR" id cert show --json
CERT_TEAM="$(echo "$cert_out" | jq_field team_id)"
CERT_ALIAS="$(echo "$cert_out" | jq_field alias)"

assert_eq "cert team" "devteam:test.local" "$CERT_TEAM"
assert_eq "cert alias" "alice" "$CERT_ALIAS"
echo ""

# ---------------------------------------------------------------------------
# Phase 6: Alice connects to aweb
# ---------------------------------------------------------------------------
echo "=== Phase 6: Alice connects to aweb (POST /v1/connect) ==="

run_success "alice init" run_aw_in "$ALICE_DIR" init --url "$AWEB_URL"
init_exit=$?
assert_eq "alice init exit" "0" "$init_exit"

if [[ -f "$ALICE_DIR/.aw/workspace.yaml" ]]; then
  echo "  PASS: workspace.yaml written"
  pass=$((pass + 1))
else
  echo "  FAIL: workspace.yaml not found"
  fail=$((fail + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 7: whoami
# ---------------------------------------------------------------------------
echo "=== Phase 7: Alice whoami ==="

capture_success whoami_out "whoami_out" run_aw_in "$ALICE_DIR" whoami --json
whoami_alias="$(echo "$whoami_out" | jq_field alias)"
assert_eq "whoami alias" "alice" "$whoami_alias"
echo ""

# ---------------------------------------------------------------------------
# Phase 8: workspace status
# ---------------------------------------------------------------------------
echo "=== Phase 8: Workspace status ==="

capture_success ws_out "ws_out" run_aw_in "$ALICE_DIR" workspace status
ws_exit=$?
assert_eq "workspace status exit" "0" "$ws_exit"
assert_contains "workspace status shows alice" "$ws_out" "alice"
echo ""

# ---------------------------------------------------------------------------
# Phase 9: Create bob and join team via invite
# ---------------------------------------------------------------------------
echo "=== Phase 9: Create bob and join team ==="

capture_success bob_create "bob_create" run_aw_in "$BOB_DIR" id create \
  --name bob \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json

BOB_DID_KEY="$(echo "$bob_create" | jq_field did_key)"
BOB_DID_AW="$(echo "$bob_create" | jq_field did_aw)"
assert_not_empty "bob did_key" "$BOB_DID_KEY"
assert_not_empty "bob did_aw" "$BOB_DID_AW"

# Alice creates invite for bob
capture_success bob_invite_out "bob_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --global \
  --json

BOB_INVITE_TOKEN="$(echo "$bob_invite_out" | jq_field token)"
assert_not_empty "bob invite token" "$BOB_INVITE_TOKEN"

# Bob accepts the invite (cert saved under $BOB_DIR/.aw/team-certs/)
capture_success bob_accept "bob_accept" run_aw_in "$BOB_DIR" id team accept-invite "$BOB_INVITE_TOKEN" --global \
  --alias bob \
  --json

BOB_ACCEPT_STATUS="$(echo "$bob_accept" | jq_field status)"
assert_eq "bob accepted" "accepted" "$BOB_ACCEPT_STATUS"

# Bob connects to aweb
run_success "bob init" run_aw_in "$BOB_DIR" init --url "$AWEB_URL"
bob_init_exit=$?
assert_eq "bob init exit" "0" "$bob_init_exit"

# Create a local-only teammate and remove the service-local E2E key row to
# simulate an old client. Global identities may already have AWID-published
# keys, so they are not a useful missing-key fixture.
capture_success nokey_invite_out "nokey_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --json
NOKEY_INVITE_TOKEN="$(echo "$nokey_invite_out" | jq_field token)"
assert_not_empty "nokey invite token" "$NOKEY_INVITE_TOKEN"
capture_success nokey_accept "nokey_accept" run_aw_in "$NO_KEY_DIR" id team accept-invite "$NOKEY_INVITE_TOKEN" \
  --alias nokey \
  --json
NOKEY_ACCEPT_STATUS="$(echo "$nokey_accept" | jq_field status)"
assert_eq "nokey accepted" "accepted" "$NOKEY_ACCEPT_STATUS"
run_success "nokey init" run_aw_in "$NO_KEY_DIR" init --url "$AWEB_URL"
psql_exec "DELETE FROM aweb.agent_encryption_keys e USING aweb.agents a WHERE e.agent_id = a.agent_id AND a.team_id = 'devteam:test.local' AND a.alias = 'nokey';"
echo ""

# ---------------------------------------------------------------------------
# Phase 9a: E2E encryption keys fail closed until recipients publish keys
# ---------------------------------------------------------------------------
echo "=== Phase 9a: E2E encryption key setup ==="

if alice_e2ee_setup="$(run_aw_in "$ALICE_DIR" id encryption-key setup --json 2>&1)"; then
  alice_e2ee_setup_exit=0
else
  alice_e2ee_setup_exit=$?
fi
assert_eq "alice e2ee key setup exit" "0" "$alice_e2ee_setup_exit"
alice_e2ee_key=""
if [[ "$alice_e2ee_setup_exit" == "0" ]]; then
  alice_e2ee_key="$(echo "$alice_e2ee_setup" | jq_field key_id)"
elif [[ -n "$alice_e2ee_setup" ]]; then
  echo "  alice e2ee key setup output: ${alice_e2ee_setup:0:240}"
fi
assert_not_empty "alice e2ee key id" "$alice_e2ee_key"

if missing_key_out="$(run_aw_in "$ALICE_DIR" mail send \
  --to nokey \
  --subject "E2EE_MISSING_KEY_SUBJECT" \
  --body "E2EE_MISSING_KEY_BODY" \
  --e2ee 2>&1)"; then
  missing_key_exit=0
else
  missing_key_exit=$?
fi
assert_eq "e2ee mail missing recipient key fails closed" "1" "$missing_key_exit"
assert_contains "missing recipient key message" "$missing_key_out" "E2E encryption key"
missing_key_plaintext_count="$(psql_scalar "SELECT COUNT(*) FROM aweb.messages WHERE subject = 'E2EE_MISSING_KEY_SUBJECT' OR body = 'E2EE_MISSING_KEY_BODY';")"
assert_eq "missing-key e2ee attempt stores no plaintext row" "0" "$missing_key_plaintext_count"

if bob_e2ee_setup="$(run_aw_in "$BOB_DIR" id encryption-key setup --json 2>&1)"; then
  bob_e2ee_setup_exit=0
else
  bob_e2ee_setup_exit=$?
fi
assert_eq "bob e2ee key setup exit" "0" "$bob_e2ee_setup_exit"
bob_e2ee_key=""
if [[ "$bob_e2ee_setup_exit" == "0" ]]; then
  bob_e2ee_key="$(echo "$bob_e2ee_setup" | jq_field key_id)"
elif [[ -n "$bob_e2ee_setup" ]]; then
  echo "  bob e2ee key setup output: ${bob_e2ee_setup:0:240}"
fi
assert_not_empty "bob e2ee key id" "$bob_e2ee_key"
echo ""

# ---------------------------------------------------------------------------
# Phase 9b: E2E mail — server routes ciphertext, clients read plaintext
# ---------------------------------------------------------------------------
echo "=== Phase 9b: E2E mail ciphertext-at-rest ==="

E2EE_LOCAL_SUBJECT="E2EE_LOCAL_SUBJECT_SENTINEL_260526"
E2EE_LOCAL_BODY="E2EE_LOCAL_BODY_SENTINEL_260526"
e2ee_sse_capture_file="$(mktemp "${TMPDIR:-/tmp}/aw-e2ee-sse.XXXXXX")"
run_aw_in "$BOB_DIR" events stream --json --timeout 8 >"$e2ee_sse_capture_file" 2>/dev/null &
e2ee_sse_pid=$!
sleep 2
if e2ee_send_out="$(run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "$E2EE_LOCAL_SUBJECT" \
  --body "$E2EE_LOCAL_BODY" \
  --e2ee \
  --json 2>&1)"; then
  e2ee_send_exit=0
else
  e2ee_send_exit=$?
fi
assert_eq "e2ee local mail send exit" "0" "$e2ee_send_exit"
if [[ "$e2ee_send_exit" != "0" ]]; then
  echo "$e2ee_send_out"
fi
e2ee_message_id="$(echo "$e2ee_send_out" | jq_field message_id)"
e2ee_conversation_id="$(echo "$e2ee_send_out" | jq_field conversation_id)"
assert_not_empty "e2ee local message id" "$e2ee_message_id"
assert_not_empty "e2ee local conversation id" "$e2ee_conversation_id"
wait "$e2ee_sse_pid" 2>/dev/null || true

capture_success bob_e2ee_inbox "bob_e2ee_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
bob_e2ee_body="$(echo "$bob_e2ee_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')==cid), ''))" "$e2ee_conversation_id" 2>/dev/null || echo "")"
bob_e2ee_subject="$(echo "$bob_e2ee_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('subject','') for m in msgs if m.get('conversation_id')==cid), ''))" "$e2ee_conversation_id" 2>/dev/null || echo "")"
assert_eq "bob decrypts e2ee local body" "$E2EE_LOCAL_BODY" "$bob_e2ee_body"
assert_eq "bob decrypts e2ee local subject" "$E2EE_LOCAL_SUBJECT" "$bob_e2ee_subject"

capture_success alice_e2ee_sent "alice_e2ee_sent" run_aw_in "$ALICE_DIR" mail show --conversation-id "$e2ee_conversation_id" --json
alice_e2ee_self_copy="$(echo "$alice_e2ee_sent" | python3 -c "import sys,json; body=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')==body), ''))" "$E2EE_LOCAL_BODY" 2>/dev/null || echo "")"
assert_eq "alice decrypts sender self-copy" "$E2EE_LOCAL_BODY" "$alice_e2ee_self_copy"

db_plaintext_count="$(psql_scalar "SELECT COUNT(*) FROM aweb.messages WHERE message_id = '$e2ee_message_id' AND (COALESCE(subject, '') LIKE '%$E2EE_LOCAL_SUBJECT%' OR COALESCE(body, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(signature, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(signed_payload, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(encrypted_envelope::text, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(encrypted_ciphertext, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%$E2EE_LOCAL_BODY%');")"
assert_eq "e2ee plaintext absent from message storage" "0" "$db_plaintext_count"
chat_plaintext_count="$(psql_scalar "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%$E2EE_LOCAL_BODY%' OR COALESCE(signed_payload, '') LIKE '%$E2EE_LOCAL_BODY%';")"
assert_eq "e2ee mail plaintext absent from chat storage" "0" "$chat_plaintext_count"
assert_file_not_contains "e2ee plaintext absent from SSE capture subject" "$e2ee_sse_capture_file" "$E2EE_LOCAL_SUBJECT"
assert_file_not_contains "e2ee plaintext absent from SSE capture body" "$e2ee_sse_capture_file" "$E2EE_LOCAL_BODY"
assert_file_not_contains "e2ee plaintext absent from docker aweb logs" <(cd "$SERVER_DIR" && docker compose --env-file .env.e2e logs --no-color aweb 2>/dev/null || true) "$E2EE_LOCAL_BODY"
e2ee_dump_file="$(mktemp "${TMPDIR:-/tmp}/aw-e2ee-db-dump.XXXXXX")"
(cd "$SERVER_DIR" && docker compose --env-file .env.e2e exec -T postgres pg_dump -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" -n aweb -n server >"$e2ee_dump_file" 2>/dev/null || true)
assert_file_not_contains "e2ee plaintext absent from db dump subject" "$e2ee_dump_file" "$E2EE_LOCAL_SUBJECT"
assert_file_not_contains "e2ee plaintext absent from db dump body" "$e2ee_dump_file" "$E2EE_LOCAL_BODY"
e2ee_sse_mode="$(grep -m1 'encrypted_v2' "$e2ee_sse_capture_file" 2>/dev/null || true)"
assert_not_empty "e2ee SSE emitted encrypted metadata" "$e2ee_sse_mode"
echo ""

# ---------------------------------------------------------------------------
# Phase 9c: E2E chat — server routes ciphertext, clients read plaintext
# ---------------------------------------------------------------------------
echo "=== Phase 9c: E2E chat ciphertext-at-rest ==="

E2EE_CHAT_BODY="E2EE_CHAT_BODY_SENTINEL_260526"
e2ee_chat_sse_capture_file="$(mktemp "${TMPDIR:-/tmp}/aw-e2ee-chat-sse.XXXXXX")"
run_aw_in "$BOB_DIR" events stream --json --timeout 8 >"$e2ee_chat_sse_capture_file" 2>/dev/null &
e2ee_chat_sse_pid=$!
sleep 2
if e2ee_chat_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave bob \
  "$E2EE_CHAT_BODY" \
  --start-conversation \
  --e2ee \
  --json 2>&1)"; then
  e2ee_chat_exit=0
else
  e2ee_chat_exit=$?
fi
assert_eq "e2ee local chat send exit" "0" "$e2ee_chat_exit"
if [[ "$e2ee_chat_exit" != "0" ]]; then
  echo "$e2ee_chat_out"
fi
wait "$e2ee_chat_sse_pid" 2>/dev/null || true

if bob_e2ee_chat_pending="$(run_aw_in "$BOB_DIR" chat pending --json 2>&1)"; then
  bob_e2ee_chat_pending_exit=0
else
  bob_e2ee_chat_pending_exit=$?
fi
assert_eq "bob e2ee chat pending exit" "0" "$bob_e2ee_chat_pending_exit"
if [[ "$bob_e2ee_chat_pending_exit" != "0" ]]; then
  echo "$bob_e2ee_chat_pending"
fi
bob_e2ee_chat_body="$(echo "$bob_e2ee_chat_pending" | python3 -c "import sys,json; body=sys.argv[1]; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_message','') for p in pending if p.get('last_message')==body), ''))" "$E2EE_CHAT_BODY" 2>/dev/null || echo "")"
assert_eq "bob decrypts e2ee chat pending" "$E2EE_CHAT_BODY" "$bob_e2ee_chat_body"

if alice_e2ee_chat_history="$(run_aw_in "$ALICE_DIR" chat history bob --json 2>&1)"; then
  alice_e2ee_chat_history_exit=0
else
  alice_e2ee_chat_history_exit=$?
fi
assert_eq "alice e2ee chat sent-history exit" "0" "$alice_e2ee_chat_history_exit"
if [[ "$alice_e2ee_chat_history_exit" != "0" ]]; then
  echo "$alice_e2ee_chat_history"
fi
alice_e2ee_chat_self_copy="$(echo "$alice_e2ee_chat_history" | python3 -c "import sys,json; body=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')==body), ''))" "$E2EE_CHAT_BODY" 2>/dev/null || echo "")"
assert_eq "alice decrypts e2ee chat sender self-copy" "$E2EE_CHAT_BODY" "$alice_e2ee_chat_self_copy"

e2ee_chat_encrypted_rows="$(psql_scalar "SELECT COUNT(*) FROM aweb.chat_messages WHERE content_mode = 'encrypted_v2' AND body = '' AND encrypted_envelope IS NOT NULL;")"
assert_eq "e2ee chat encrypted row exists" "1" "$e2ee_chat_encrypted_rows"
e2ee_chat_plaintext_count="$(psql_scalar "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%$E2EE_CHAT_BODY%' OR COALESCE(signature, '') LIKE '%$E2EE_CHAT_BODY%' OR COALESCE(signed_payload, '') LIKE '%$E2EE_CHAT_BODY%' OR COALESCE(encrypted_envelope::text, '') LIKE '%$E2EE_CHAT_BODY%' OR COALESCE(encrypted_ciphertext, '') LIKE '%$E2EE_CHAT_BODY%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%$E2EE_CHAT_BODY%';")"
assert_eq "e2ee chat plaintext absent from chat storage" "0" "$e2ee_chat_plaintext_count"
assert_file_not_contains "e2ee chat plaintext absent from SSE capture" "$e2ee_chat_sse_capture_file" "$E2EE_CHAT_BODY"
assert_file_not_contains "e2ee chat plaintext absent from docker aweb logs" <(cd "$SERVER_DIR" && docker compose --env-file .env.e2e logs --no-color aweb 2>/dev/null || true) "$E2EE_CHAT_BODY"
e2ee_chat_dump_file="$(mktemp "${TMPDIR:-/tmp}/aw-e2ee-chat-db-dump.XXXXXX")"
(cd "$SERVER_DIR" && docker compose --env-file .env.e2e exec -T postgres pg_dump -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" -n aweb -n server >"$e2ee_chat_dump_file" 2>/dev/null || true)
assert_file_not_contains "e2ee chat plaintext absent from db dump" "$e2ee_chat_dump_file" "$E2EE_CHAT_BODY"
echo ""

# ---------------------------------------------------------------------------
# Phase 10: Alice sends mail to bob
# ---------------------------------------------------------------------------
echo "=== Phase 10: Alice sends mail to bob ==="

if mail_send_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "E2E test" \
  --body "Hello from alice" 2>&1)"; then
  mail_send_exit=0
else
  mail_send_exit=$?
fi
assert_eq "mail send --plaintext exit" "0" "$mail_send_exit"
if [[ "$mail_send_exit" != "0" ]]; then
  echo "$mail_send_out"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 11: Bob reads inbox
# ---------------------------------------------------------------------------
echo "=== Phase 11: Bob reads inbox ==="

capture_success bob_inbox "bob_inbox" run_aw_in "$BOB_DIR" mail inbox --json
bob_msg_count="$(echo "$bob_inbox" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('messages',[])))" 2>/dev/null || echo "0")"
bob_msg_body="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('body','') if msgs else '')" 2>/dev/null || echo "")"

assert_eq "bob has 1 message" "1" "$bob_msg_count"
assert_eq "message body" "Hello from alice" "$bob_msg_body"
echo ""

# ---------------------------------------------------------------------------
# Phase 11a: Bare alias to a local member with a registered global identity
# ---------------------------------------------------------------------------
echo "=== Phase 11a: Bare alias to registered local member ==="

capture_success eve_create "eve_create" run_aw_in "$EVE_DIR" id create \
  --name eve \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
EVE_DID_AW="$(echo "$eve_create" | jq_field did_aw)"
assert_not_empty "eve did_aw" "$EVE_DID_AW"

capture_success eve_invite_out "eve_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --json
EVE_INVITE_TOKEN="$(echo "$eve_invite_out" | jq_field token)"
assert_not_empty "eve local invite token" "$EVE_INVITE_TOKEN"

capture_success eve_accept "eve_accept" run_aw_in "$EVE_DIR" id team accept-invite "$EVE_INVITE_TOKEN" --global \
  --alias eve \
  --json
EVE_ACCEPT_STATUS="$(echo "$eve_accept" | jq_field status)"
assert_eq "eve accepted default local invite" "accepted" "$EVE_ACCEPT_STATUS"

run_success "eve init" run_aw_in "$EVE_DIR" init --url "$AWEB_URL"
eve_init_exit=$?
assert_eq "eve init exit" "0" "$eve_init_exit"

if eve_mail_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to eve \
  --subject "Registered local e2e" \
  --body "Hello registered local eve" 2>&1)"; then
  eve_mail_exit=0
else
  eve_mail_exit=$?
fi
assert_eq "alice mails registered local eve by bare alias" "0" "$eve_mail_exit"
if [[ "$eve_mail_exit" != "0" ]]; then
  echo "$eve_mail_out"
fi

if eve_inbox="$(run_aw_in "$EVE_DIR" mail inbox --json 2>&1)"; then
  eve_inbox_exit=0
else
  eve_inbox_exit=$?
fi
assert_eq "eve inbox exit" "0" "$eve_inbox_exit"
if [[ "$eve_inbox_exit" != "0" ]]; then
  echo "$eve_inbox"
fi
eve_msg_body="$(echo "$eve_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Hello registered local eve'), ''))" 2>/dev/null || echo "")"
assert_eq "eve receives bare-alias mail despite registered identity" "Hello registered local eve" "$eve_msg_body"
echo ""

# ---------------------------------------------------------------------------
# Phase 11b: Cross-machine request/add-member/fetch-cert
# ---------------------------------------------------------------------------
echo "=== Phase 11b: Cross-machine request/add-member/fetch-cert ==="

capture_success erin_create "erin_create" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" id create \
  --name erin \
  --domain erin.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
ERIN_DID_KEY="$(echo "$erin_create" | jq_field did_key)"
ERIN_DID_AW="$(echo "$erin_create" | jq_field did_aw)"
ERIN_ADDRESS="$(echo "$erin_create" | jq_field address)"
assert_not_empty "remote erin did_key" "$ERIN_DID_KEY"
assert_not_empty "remote erin did_aw" "$ERIN_DID_AW"
assert_eq "remote erin address" "erin.local/erin" "$ERIN_ADDRESS"

capture_success erin_request "erin_request" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" id team request \
  --team devteam:test.local \
  --alias erin \
  --json
erin_add_command="$(echo "$erin_request" | jq_field command)"
assert_contains "erin request prints add-member" "$erin_add_command" "aw id team add-member"
assert_contains "erin request includes did" "$erin_add_command" "$ERIN_DID_KEY"
assert_contains "erin request includes address" "$erin_add_command" "--address erin.local/erin"

capture_success erin_add "erin_add" run_aw_in "$ALICE_DIR" id team add-member \
  --team devteam \
  --namespace test.local \
  --did "$ERIN_DID_KEY" \
  --alias erin \
  --global \
  --did-aw "$ERIN_DID_AW" \
  --address "$ERIN_ADDRESS" \
  --json
ERIN_CERT_ID="$(echo "$erin_add" | jq_field certificate_id)"
ERIN_FETCH_COMMAND="$(echo "$erin_add" | jq_field fetch_command)"
assert_not_empty "erin certificate id" "$ERIN_CERT_ID"
assert_contains "erin add-member prints fetch-cert" "$ERIN_FETCH_COMMAND" "aw id team fetch-cert"

capture_success erin_fetch "erin_fetch" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" id team fetch-cert \
  --namespace test.local \
  --team devteam \
  --cert-id "$ERIN_CERT_ID" \
  --json
ERIN_FETCH_STATUS="$(echo "$erin_fetch" | jq_field status)"
assert_eq "erin fetch-cert installed" "installed" "$ERIN_FETCH_STATUS"
erin_cert_path="$(team_cert_path "$REMOTE_ERIN_DIR" "devteam:test.local")"
assert_file_exists "erin fetched cert file" "$erin_cert_path"
erin_team_state="$REMOTE_ERIN_DIR/.aw/teams.yaml"
erin_active_team="$(yaml_field "$erin_team_state" active_team)"
assert_eq "erin active team after fetch" "devteam:test.local" "$erin_active_team"
case "$TEAM_KEY_PATH" in
  "$E2E_HOME"/*)
    erin_controller_key_path="$REMOTE_ERIN_HOME/${TEAM_KEY_PATH#"$E2E_HOME"/}"
    ;;
  *)
    echo "  FAIL: production-resolved team key path is outside the source HOME: $TEAM_KEY_PATH"
    fail=$((fail + 1))
    erin_controller_key_path=""
    ;;
esac
if [[ -n "$erin_controller_key_path" ]]; then
  if [[ "${AWEB_E2E_SEED_ERIN_CONTROLLER_KEY_LEAK:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$erin_controller_key_path")"
    printf 'simulated-production-leak' >"$erin_controller_key_path"
    echo "  SEED: simulated post-fetch controller-key leak at the production-resolved path"
  fi

  # Observe fetch-cert's real result before the negative control writes to the
  # same path. Reversing this order would erase a production leak before it can
  # fail the assertion.
  assert_path_missing "erin remote home has no controller team key" "$erin_controller_key_path"

  mkdir -p "$(dirname "$erin_controller_key_path")"
  printf 'negative-control' >"$erin_controller_key_path"
  if path_is_missing "$erin_controller_key_path"; then
    echo "  FAIL: controller-key absence check missed a seeded key at the production-resolved path"
    fail=$((fail + 1))
  else
    echo "  PASS: controller-key absence check detects a seeded key at the production-resolved path"
    pass=$((pass + 1))
  fi
  rm -f "$erin_controller_key_path"
  assert_path_missing "seeded controller-key negative control cleaned up" "$erin_controller_key_path"
fi

run_success "erin init" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" init --url "$AWEB_URL"
erin_init_exit=$?
assert_eq "erin init after fetch-cert" "0" "$erin_init_exit"

run_success "erin mail send --plaintext" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" mail send --plaintext \
  --to alice \
  --subject "Remote fetch-cert mail" \
  --body "Remote fetch-cert path works"
erin_mail_exit=$?
assert_eq "erin mail after fetch-cert" "0" "$erin_mail_exit"
capture_success alice_erin_inbox "alice_erin_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_erin_from_address="$(echo "$alice_erin_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Remote fetch-cert mail'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees erin remote from_address" "erin.local/erin" "$alice_erin_from_address"

run_success "erin chat send" run_aw_with_home_in "$REMOTE_ERIN_HOME" "$REMOTE_ERIN_DIR" chat send-and-leave --plaintext alice \
  "Remote fetch-cert chat"
erin_chat_exit=$?
assert_eq "erin chat after fetch-cert" "0" "$erin_chat_exit"
capture_success alice_erin_pending "alice_erin_pending" run_aw_in "$ALICE_DIR" chat pending --json
alice_erin_chat_from_address="$(echo "$alice_erin_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Remote fetch-cert chat'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees erin remote chat from_address" "erin.local/erin" "$alice_erin_chat_from_address"

capture_success mallory_create "mallory_create" run_aw_with_home_in "$WRONG_DID_HOME" "$WRONG_DID_DIR" id create \
  --name mallory \
  --domain mallory.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
MALLORY_DID_KEY="$(echo "$mallory_create" | jq_field did_key)"
assert_not_empty "wrong did identity created" "$MALLORY_DID_KEY"
if mallory_fetch_out="$(run_aw_with_home_in "$WRONG_DID_HOME" "$WRONG_DID_DIR" id team fetch-cert \
  --namespace test.local \
  --team devteam \
  --cert-id "$ERIN_CERT_ID" 2>&1)"; then
  mallory_fetch_exit=0
else
  mallory_fetch_exit=$?
fi
assert_eq "wrong did fetch-cert rejected" "1" "$mallory_fetch_exit"
assert_contains "wrong did fetch-cert explains auth" "$mallory_fetch_out" "403"
echo ""

# ---------------------------------------------------------------------------
# Phase 11c: External AWID team registers with aweb service
# ---------------------------------------------------------------------------
echo "=== Phase 11c: External AWID team registers with aweb service ==="

capture_success service_controller_create "service_controller_create" run_aw_in "$SERVICE_CONTROLLER_DIR" id create \
  --name controller \
  --domain service.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
SERVICE_CONTROLLER_DID="$(echo "$service_controller_create" | jq_field did_key)"
assert_not_empty "service controller did_key" "$SERVICE_CONTROLLER_DID"

capture_success service_team_out "service_team_out" run_aw_in "$SERVICE_CONTROLLER_DIR" id team create \
  --name circle \
  --namespace service.local \
  --display-name "Circle" \
  --registry "$AWID_URL" \
  --json
SERVICE_TEAM_ID="$(echo "$service_team_out" | jq_field team_id)"
SERVICE_TEAM_DID="$(echo "$service_team_out" | jq_field team_did_key)"
assert_eq "service team id" "circle:service.local" "$SERVICE_TEAM_ID"
assert_not_empty "service team did_key" "$SERVICE_TEAM_DID"

capture_success service_alpha_create "service_alpha_create" run_aw_in "$SERVICE_ALPHA_DIR" id create \
  --name alpha \
  --domain service.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
SERVICE_ALPHA_DID="$(echo "$service_alpha_create" | jq_field did_key)"
SERVICE_ALPHA_DID_AW="$(echo "$service_alpha_create" | jq_field did_aw)"
SERVICE_ALPHA_ADDRESS="$(echo "$service_alpha_create" | jq_field address)"
assert_eq "service alpha address" "service.local/alpha" "$SERVICE_ALPHA_ADDRESS"

capture_success service_beta_create "service_beta_create" run_aw_in "$SERVICE_BETA_DIR" id create \
  --name beta \
  --domain service.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
SERVICE_BETA_DID="$(echo "$service_beta_create" | jq_field did_key)"
SERVICE_BETA_DID_AW="$(echo "$service_beta_create" | jq_field did_aw)"
SERVICE_BETA_ADDRESS="$(echo "$service_beta_create" | jq_field address)"
assert_eq "service beta address" "service.local/beta" "$SERVICE_BETA_ADDRESS"

capture_success service_alpha_add "service_alpha_add" run_aw_in "$SERVICE_CONTROLLER_DIR" id team add-member \
  --team circle \
  --namespace service.local \
  --did "$SERVICE_ALPHA_DID" \
  --alias alpha \
  --global \
  --did-aw "$SERVICE_ALPHA_DID_AW" \
  --address "$SERVICE_ALPHA_ADDRESS" \
  --json
SERVICE_ALPHA_CERT_ID="$(echo "$service_alpha_add" | jq_field certificate_id)"
assert_not_empty "service alpha certificate id" "$SERVICE_ALPHA_CERT_ID"
run_success "service alpha fetch cert" run_aw_in "$SERVICE_ALPHA_DIR" id team fetch-cert \
  --namespace service.local \
  --team circle \
  --cert-id "$SERVICE_ALPHA_CERT_ID" \
  --json
assert_file_exists "service alpha fetched cert" "$(team_cert_path "$SERVICE_ALPHA_DIR" "$SERVICE_TEAM_ID")"

capture_success service_beta_add "service_beta_add" run_aw_in "$SERVICE_CONTROLLER_DIR" id team add-member \
  --team circle \
  --namespace service.local \
  --did "$SERVICE_BETA_DID" \
  --alias beta \
  --global \
  --did-aw "$SERVICE_BETA_DID_AW" \
  --address "$SERVICE_BETA_ADDRESS" \
  --json
SERVICE_BETA_CERT_ID="$(echo "$service_beta_add" | jq_field certificate_id)"
assert_not_empty "service beta certificate id" "$SERVICE_BETA_CERT_ID"
run_success "service beta fetch cert" run_aw_in "$SERVICE_BETA_DIR" id team fetch-cert \
  --namespace service.local \
  --team circle \
  --cert-id "$SERVICE_BETA_CERT_ID" \
  --json
assert_file_exists "service beta fetched cert" "$(team_cert_path "$SERVICE_BETA_DIR" "$SERVICE_TEAM_ID")"

capture_success service_register_dry "service_register_dry" run_aw_in "$SERVICE_CONTROLLER_DIR" id team register \
  --team "$SERVICE_TEAM_ID" \
  --service "$AWEB_URL" \
  --dry-run \
  --json
service_register_dry_status="$(echo "$service_register_dry" | jq_field status)"
assert_eq "service register dry-run status" "dry-run" "$service_register_dry_status"
service_team_rows_after_dry="$(psql_scalar "SELECT COUNT(*) FROM aweb.teams WHERE team_id = '$SERVICE_TEAM_ID';")"
assert_eq "service dry-run does not create team projection" "0" "$service_team_rows_after_dry"

capture_success service_register_apply "service_register_apply" run_aw_in "$SERVICE_CONTROLLER_DIR" id team register \
  --team "$SERVICE_TEAM_ID" \
  --service "$AWEB_URL" \
  --json
service_register_status="$(echo "$service_register_apply" | jq_field status)"
service_register_next_init="$(echo "$service_register_apply" | python3 -c "import sys,json; text=sys.stdin.read(); start=text.find('{'); d=json.loads(text[start:]); print(next((s.get('command','') for s in d.get('next_steps',[]) if 'service init' in s.get('command','')), ''))" 2>/dev/null || echo "")"
service_register_next_claim="$(echo "$service_register_apply" | python3 -c "import sys,json; text=sys.stdin.read(); start=text.find('{'); d=json.loads(text[start:]); print(next((s.get('command','') for s in d.get('next_steps',[]) if 'claim-human' in s.get('command','')), ''))" 2>/dev/null || echo "")"
assert_eq "service register apply status" "created" "$service_register_status"
assert_contains "service register returns service init next step" "$service_register_next_init" "aw service init --service $AWEB_URL --team $SERVICE_TEAM_ID"
assert_contains "service register returns claim-human next step" "$service_register_next_claim" "aw claim-human --email you@example.com"

service_team_rows="$(psql_scalar "SELECT COUNT(*) FROM aweb.teams WHERE team_id = '$SERVICE_TEAM_ID' AND team_did_key = '$SERVICE_TEAM_DID';")"
service_agents_before="$(psql_scalar "SELECT COUNT(*) FROM aweb.agents WHERE team_id = '$SERVICE_TEAM_ID' AND deleted_at IS NULL;")"
service_workspaces_before="$(psql_scalar "SELECT COUNT(*) FROM aweb.workspaces WHERE team_id = '$SERVICE_TEAM_ID' AND deleted_at IS NULL;")"
assert_eq "service register creates team projection" "1" "$service_team_rows"
assert_eq "service register creates no agents" "0" "$service_agents_before"
assert_eq "service register creates no workspaces" "0" "$service_workspaces_before"

run_success "service alpha init" run_aw_in "$SERVICE_ALPHA_DIR" service init --service "$AWEB_URL" --team "$SERVICE_TEAM_ID"
run_success "service beta init" run_aw_in "$SERVICE_BETA_DIR" service init --service "$AWEB_URL" --team "$SERVICE_TEAM_ID"
service_alpha_active="$(yaml_field "$SERVICE_ALPHA_DIR/.aw/teams.yaml" active_team)"
service_beta_active="$(yaml_field "$SERVICE_BETA_DIR/.aw/teams.yaml" active_team)"
service_alpha_workspace_alias="$(workspace_membership_field "$SERVICE_ALPHA_DIR/.aw/workspace.yaml" "$SERVICE_TEAM_ID" alias)"
service_beta_workspace_alias="$(workspace_membership_field "$SERVICE_BETA_DIR/.aw/workspace.yaml" "$SERVICE_TEAM_ID" alias)"
assert_eq "service alpha active team" "$SERVICE_TEAM_ID" "$service_alpha_active"
assert_eq "service beta active team" "$SERVICE_TEAM_ID" "$service_beta_active"
assert_eq "service alpha workspace membership" "alpha" "$service_alpha_workspace_alias"
assert_eq "service beta workspace membership" "beta" "$service_beta_workspace_alias"

service_agents_after="$(psql_scalar "SELECT COUNT(*) FROM aweb.agents WHERE team_id = '$SERVICE_TEAM_ID' AND deleted_at IS NULL;")"
service_workspaces_after="$(psql_scalar "SELECT COUNT(*) FROM aweb.workspaces WHERE team_id = '$SERVICE_TEAM_ID' AND deleted_at IS NULL;")"
assert_eq "service init creates two agents" "2" "$service_agents_after"
assert_eq "service init creates two workspaces" "2" "$service_workspaces_after"

run_success "service registered team mail send --plaintext" run_aw_in "$SERVICE_ALPHA_DIR" mail send --plaintext \
  --to beta \
  --subject "Service registered team e2e" \
  --body "service init path works"
capture_success service_beta_inbox "service_beta_inbox" run_aw_in "$SERVICE_BETA_DIR" mail inbox --json --show-all
service_beta_subject="$(echo "$service_beta_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('subject','') for m in msgs if m.get('subject')=='Service registered team e2e'), ''))" 2>/dev/null || echo "")"
assert_eq "service registered team mail works" "Service registered team e2e" "$service_beta_subject"
echo ""

# ---------------------------------------------------------------------------
# Phase 11d: Cross-identity messaging via contacts
# ---------------------------------------------------------------------------
echo "=== Phase 11d: Cross-identity messaging via contacts ==="

capture_success carol_create "carol_create" run_aw_in "$CAROL_DIR" id create \
  --name carol \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
CAROL_DID_AW="$(echo "$carol_create" | jq_field did_aw)"
assert_not_empty "carol did_aw" "$CAROL_DID_AW"

run_success "ops team create" run_aw_in "$ALICE_DIR" id team create \
  --name ops \
  --namespace test.local \
  --registry "$AWID_URL" \
  --json
capture_success ops_invite_out "ops_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team ops \
  --namespace test.local \
  --json
OPS_INVITE_TOKEN="$(echo "$ops_invite_out" | jq_field token)"
assert_not_empty "ops invite token" "$OPS_INVITE_TOKEN"

capture_success carol_accept "carol_accept" run_aw_in "$CAROL_DIR" id team accept-invite "$OPS_INVITE_TOKEN" --global \
  --alias carol \
  --json
CAROL_ACCEPT_STATUS="$(echo "$carol_accept" | jq_field status)"
assert_eq "carol accepted" "accepted" "$CAROL_ACCEPT_STATUS"

run_success "carol init" run_aw_in "$CAROL_DIR" init --url "$AWEB_URL"
carol_init_exit=$?
assert_eq "carol init exit" "0" "$carol_init_exit"

capture_success dave_create "dave_create" run_aw_in "$DAVE_DIR" id create \
  --name dave \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
DAVE_DID_KEY="$(echo "$dave_create" | jq_field did_key)"
assert_not_empty "dave did_key" "$DAVE_DID_KEY"

capture_success dave_invite_out "dave_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team ops \
  --namespace test.local \
  --json
DAVE_INVITE_TOKEN="$(echo "$dave_invite_out" | jq_field token)"
assert_not_empty "dave ops invite token" "$DAVE_INVITE_TOKEN"

capture_success dave_accept "dave_accept" run_aw_in "$DAVE_DIR" id team accept-invite "$DAVE_INVITE_TOKEN" --global \
  --alias dave \
  --json
DAVE_ACCEPT_STATUS="$(echo "$dave_accept" | jq_field status)"
assert_eq "dave accepted to ops" "accepted" "$DAVE_ACCEPT_STATUS"

run_success "dave init" run_aw_in "$DAVE_DIR" init --url "$AWEB_URL"
dave_init_exit=$?
assert_eq "dave init exit" "0" "$dave_init_exit"

set_inbound_mode "$ALICE_DID_AW" "team_and_contacts"
run_success "alice contacts add bob" run_aw_in "$ALICE_DIR" contacts add "test.local/bob" --label "Bob"
contacts_add_exit=$?
assert_eq "alice adds bob to contacts" "0" "$contacts_add_exit"

if bob_direct_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --to-address "test.local/alice" \
  --body "Address hello from bob" 2>&1)"; then
  bob_direct_exit=0
else
  bob_direct_exit=$?
fi
assert_eq "bob address mail to alice" "0" "$bob_direct_exit"
if [[ "$bob_direct_exit" != "0" ]]; then
  echo "$bob_direct_out"
fi

capture_success alice_contacts_inbox "alice_contacts_inbox" run_aw_in "$ALICE_DIR" mail inbox --json
alice_bob_message="$(echo "$alice_contacts_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Address hello from bob'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives bob address message" "Address hello from bob" "$alice_bob_message"

if carol_direct_out="$(run_aw_in "$CAROL_DIR" mail send --plaintext \
  --to-address "test.local/alice" \
  --body 'Blocked hello from carol' 2>&1)"; then
  carol_direct_exit=0
else
  carol_direct_exit=$?
fi
if [[ "$carol_direct_exit" != "0" ]] && echo "$carol_direct_out" | grep -qi "contacts\|403\|forbidden"; then
  echo "  PASS: carol blocked by alice contacts-only inbound mode"
  pass=$((pass + 1))
else
  echo "  FAIL: carol should be blocked by alice contacts-only inbound mode (exit=$carol_direct_exit output=${carol_direct_out:0:160})"
  fail=$((fail + 1))
fi

set_inbound_mode "$ALICE_DID_AW" "open"
run_success "carol retry mail send --plaintext" run_aw_in "$CAROL_DIR" mail send --plaintext \
  --to-address "test.local/alice" \
  --body "Address hello from carol"
carol_retry_exit=$?
assert_eq "carol direct mail succeeds after inbound mode change" "0" "$carol_retry_exit"

capture_success alice_all_inbox "alice_all_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_carol_message="$(echo "$alice_all_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Address hello from carol'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives carol address message" "Address hello from carol" "$alice_carol_message"
echo ""

# ---------------------------------------------------------------------------
# Phase 12: Chat round-trip
# ---------------------------------------------------------------------------
echo "=== Phase 12: Chat ==="

run_success "alice bob chat send-and-wait --plaintext" run_aw_in "$ALICE_DIR" chat send-and-wait --plaintext bob \
  "E2E chat from alice" --wait 3
chat_send_exit=$?
assert_eq "alice→bob chat send exit" "0" "$chat_send_exit"

capture_success bob_pending "bob_pending" run_aw_in "$BOB_DIR" chat pending
assert_contains "bob sees pending from alice" "$bob_pending" "alice"

run_success "bob chat reply" run_aw_in "$BOB_DIR" chat send-and-leave --plaintext alice \
  "Chat reply from bob"
chat_reply_exit=$?
assert_eq "bob→alice chat reply exit" "0" "$chat_reply_exit"

capture_success alice_history "alice_history" run_aw_in "$ALICE_DIR" chat history bob
assert_contains "alice sees bob's reply" "$alice_history" "Chat reply from bob"
echo ""

# ---------------------------------------------------------------------------
# Phase 12b: Cross-team tilde addressing
# ---------------------------------------------------------------------------
echo "=== Phase 12b: Cross-team tilde addressing ==="

if tilde_mail_out="$(run_aw_in "$DAVE_DIR" mail send --plaintext \
  --to devteam~alice \
  --subject "Cross-team tilde mail" \
  --body "Cross-team hello from dave" 2>&1)"; then
  tilde_mail_exit=0
else
  tilde_mail_exit=$?
fi
assert_eq "dave→devteam~alice mail exit" "0" "$tilde_mail_exit"
if [[ "$tilde_mail_exit" != "0" ]]; then
  echo "  tilde mail output: ${tilde_mail_out:0:240}"
fi

capture_success alice_tilde_inbox "alice_tilde_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_dave_message="$(echo "$alice_tilde_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Cross-team hello from dave'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives dave cross-team mail" "Cross-team hello from dave" "$alice_dave_message"

if tilde_chat_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext ops~dave \
  "Cross-team chat from alice" 2>&1)"; then
  tilde_chat_exit=0
else
  tilde_chat_exit=$?
fi
assert_eq "alice→ops~dave chat exit" "0" "$tilde_chat_exit"
if [[ "$tilde_chat_exit" != "0" ]]; then
  echo "  tilde chat output: ${tilde_chat_out:0:240}"
fi

capture_success dave_pending "dave_pending" run_aw_in "$DAVE_DIR" chat pending
assert_contains "dave sees cross-team chat from alice" "$dave_pending" "alice"
echo ""

# ---------------------------------------------------------------------------
# Phase 12c: Local server-projected addresses
# ---------------------------------------------------------------------------
echo "=== Phase 12c: Local server-projected addresses ==="

capture_success gsk_invite_out "gsk_invite_out" run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --local \
  --json
GSK_INVITE_TOKEN="$(echo "$gsk_invite_out" | jq_field token)"
assert_not_empty "gsk local invite token" "$GSK_INVITE_TOKEN"

capture_success gsk_accept "gsk_accept" run_aw_in "$GSK_DIR" id team accept-invite "$GSK_INVITE_TOKEN" \
  --alias gsk \
  --json
GSK_ACCEPT_STATUS="$(echo "$gsk_accept" | jq_field status)"
assert_eq "gsk accepted local invite" "accepted" "$GSK_ACCEPT_STATUS"

run_success "gsk init" run_aw_in "$GSK_DIR" init --url "$AWEB_URL"
gsk_init_exit=$?
assert_eq "gsk init exit" "0" "$gsk_init_exit"
if [[ ! -f "$GSK_DIR/.aw/identity.yaml" ]]; then
  echo "  PASS: gsk has no identity.yaml"
  pass=$((pass + 1))
else
  echo "  FAIL: gsk local agent should not have identity.yaml"
  fail=$((fail + 1))
fi

if gsk_mail_out="$(run_aw_in "$GSK_DIR" mail send --plaintext \
  --to alice \
  --subject "Local sender address" \
  --body "Local hello from gsk" 2>&1)"; then
  gsk_mail_exit=0
else
  gsk_mail_exit=$?
fi
assert_eq "gsk→alice mail exit" "0" "$gsk_mail_exit"
if [[ "$gsk_mail_exit" != "0" ]]; then
  echo "  gsk mail output: ${gsk_mail_out:0:240}"
fi

capture_success alice_local_inbox "alice_local_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_gsk_from_address="$(echo "$alice_local_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Local sender address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees gsk server-local mail address" "test.local/gsk" "$alice_gsk_from_address"

if gsk_identity_mail_out="$(run_aw_in "$GSK_DIR" mail send --plaintext \
  --to-address test.local/alice \
  --subject "Local identity-auth sender address" \
  --body "Identity-auth hello from gsk" 2>&1)"; then
  gsk_identity_mail_exit=0
else
  gsk_identity_mail_exit=$?
fi
assert_eq "gsk→test.local/alice identity-auth mail exit" "0" "$gsk_identity_mail_exit"
if [[ "$gsk_identity_mail_exit" != "0" ]]; then
  echo "  gsk identity-auth mail output: ${gsk_identity_mail_out:0:240}"
fi

capture_success alice_identity_mail_inbox "alice_identity_mail_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_gsk_identity_from_address="$(echo "$alice_identity_mail_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Local identity-auth sender address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees gsk identity-auth mail address" "test.local/gsk" "$alice_gsk_identity_from_address"

if alice_gsk_reply_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to-address test.local/gsk \
  --subject "Reply to local address" \
  --body "Reply to gsk by local address" 2>&1)"; then
  alice_gsk_reply_exit=0
else
  alice_gsk_reply_exit=$?
fi
assert_eq "alice→test.local/gsk mail exit" "0" "$alice_gsk_reply_exit"
if [[ "$alice_gsk_reply_exit" != "0" ]]; then
  echo "  alice→gsk mail output: ${alice_gsk_reply_out:0:240}"
fi

capture_success gsk_inbox "gsk_inbox" run_aw_in "$GSK_DIR" mail inbox --json --show-all
gsk_reply_body="$(echo "$gsk_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('subject')=='Reply to local address'), ''))" 2>/dev/null || echo "")"
assert_eq "gsk receives address-routed mail reply" "Reply to gsk by local address" "$gsk_reply_body"

if gsk_chat_out="$(run_aw_in "$GSK_DIR" chat send-and-leave --plaintext alice \
  "Local chat from gsk" 2>&1)"; then
  gsk_chat_exit=0
else
  gsk_chat_exit=$?
fi
assert_eq "gsk→alice chat exit" "0" "$gsk_chat_exit"
if [[ "$gsk_chat_exit" != "0" ]]; then
  echo "  gsk chat output: ${gsk_chat_out:0:240}"
fi

capture_success alice_gsk_pending "alice_gsk_pending" run_aw_in "$ALICE_DIR" chat pending
assert_contains "alice sees gsk server-local chat address" "$alice_gsk_pending" "test.local/gsk"

if alice_gsk_chat_reply_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext test.local/gsk \
  "Reply to local chat address" 2>&1)"; then
  alice_gsk_chat_reply_exit=0
else
  alice_gsk_chat_reply_exit=$?
fi
assert_eq "alice→test.local/gsk chat exit" "0" "$alice_gsk_chat_reply_exit"
if [[ "$alice_gsk_chat_reply_exit" != "0" ]]; then
  echo "  alice→gsk chat output: ${alice_gsk_chat_reply_out:0:240}"
fi

capture_success gsk_chat_history "gsk_chat_history" run_aw_in "$GSK_DIR" chat history alice
assert_contains "gsk receives address-routed chat reply" "$gsk_chat_history" "Reply to local chat address"
echo ""

# ---------------------------------------------------------------------------
# Phase 12d: Per-membership addresses
# ---------------------------------------------------------------------------
echo "=== Phase 12d: Per-membership addresses ==="

capture_success partner_controller_create "partner_controller_create" run_aw_in "$PARTNER_CONTROLLER_DIR" id create \
  --name controller \
  --domain partner.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
PARTNER_CONTROLLER_DID="$(echo "$partner_controller_create" | jq_field did_key)"
assert_not_empty "partner namespace controller did_key" "$PARTNER_CONTROLLER_DID"

capture_success partner_address_out "partner_address_out" run_aw_in "$PARTNER_CONTROLLER_DIR" id namespace assign-address \
  --domain partner.local \
  --name alice \
  --did-aw "$ALICE_DID_AW" \
  --json
PARTNER_ALICE_ADDRESS="$(echo "$partner_address_out" | jq_field address)"
assert_eq "partner address assigned to alice" "partner.local/alice" "$PARTNER_ALICE_ADDRESS"

capture_success partner_team_out "partner_team_out" run_aw_in "$PARTNER_CONTROLLER_DIR" id team create \
  --name main \
  --namespace partner.local \
  --registry "$AWID_URL" \
  --json
PARTNER_TEAM_ID="$(echo "$partner_team_out" | jq_field team_id)"
assert_eq "partner team id" "main:partner.local" "$PARTNER_TEAM_ID"

capture_success partner_bob_create "partner_bob_create" run_aw_in "$PARTNER_BOB_DIR" id create \
  --name bob \
  --domain partner.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json
PARTNER_BOB_ADDRESS="$(echo "$partner_bob_create" | jq_field address)"
assert_eq "partner bob address" "partner.local/bob" "$PARTNER_BOB_ADDRESS"

capture_success partner_bob_invite_out "partner_bob_invite_out" run_aw_in "$PARTNER_CONTROLLER_DIR" id team invite \
  --team main \
  --namespace partner.local \
  --global \
  --json
PARTNER_BOB_INVITE_TOKEN="$(echo "$partner_bob_invite_out" | jq_field token)"
assert_not_empty "partner bob invite token" "$PARTNER_BOB_INVITE_TOKEN"

capture_success partner_bob_accept "partner_bob_accept" run_aw_in "$PARTNER_BOB_DIR" id team accept-invite "$PARTNER_BOB_INVITE_TOKEN" --global \
  --alias bob \
  --json
PARTNER_BOB_ACCEPT_STATUS="$(echo "$partner_bob_accept" | jq_field status)"
assert_eq "partner bob accepted" "accepted" "$PARTNER_BOB_ACCEPT_STATUS"

run_success "partner bob init" run_aw_in "$PARTNER_BOB_DIR" init --url "$AWEB_URL"
partner_bob_init_exit=$?
assert_eq "partner bob init exit" "0" "$partner_bob_init_exit"

capture_success partner_alice_invite_out "partner_alice_invite_out" run_aw_in "$PARTNER_CONTROLLER_DIR" id team invite \
  --team main \
  --namespace partner.local \
  --global \
  --json
PARTNER_ALICE_INVITE_TOKEN="$(echo "$partner_alice_invite_out" | jq_field token)"
assert_not_empty "partner alice invite token" "$PARTNER_ALICE_INVITE_TOKEN"

capture_success partner_alice_accept "partner_alice_accept" run_aw_in "$ALICE_DIR" id team accept-invite "$PARTNER_ALICE_INVITE_TOKEN" --global \
  --alias alice \
  --address partner.local/alice \
  --json
PARTNER_ALICE_ACCEPT_STATUS="$(echo "$partner_alice_accept" | jq_field status)"
assert_eq "alice accepted partner team with address" "accepted" "$PARTNER_ALICE_ACCEPT_STATUS"

capture_success partner_alice_cert_out "partner_alice_cert_out" run_aw_in "$ALICE_DIR" id cert show --json
partner_alice_cert_team="$(echo "$partner_alice_cert_out" | jq_field team_id)"
partner_alice_cert_address="$(echo "$partner_alice_cert_out" | jq_field member_address)"
assert_eq "alice partner cert team" "main:partner.local" "$partner_alice_cert_team"
assert_eq "alice partner cert member_address" "partner.local/alice" "$partner_alice_cert_address"

run_success "alice switch devteam" run_aw_in "$ALICE_DIR" id team switch devteam:test.local
alice_switch_primary_exit=$?
assert_eq "alice switches to primary team without re-init" "0" "$alice_switch_primary_exit"

capture_success alice_primary_whoami "alice_primary_whoami" run_aw_in "$ALICE_DIR" whoami --json
alice_primary_whoami_domain="$(echo "$alice_primary_whoami" | jq_field domain)"
alice_primary_whoami_address="$(echo "$alice_primary_whoami" | jq_field address)"
assert_eq "alice primary whoami domain after switch" "test.local" "$alice_primary_whoami_domain"
assert_eq "alice primary whoami address after switch" "test.local/alice" "$alice_primary_whoami_address"

capture_success alice_primary_cert_out "alice_primary_cert_out" run_aw_in "$ALICE_DIR" id cert show --json
alice_primary_cert_address="$(echo "$alice_primary_cert_out" | jq_field member_address)"
assert_eq "alice primary cert member_address" "test.local/alice" "$alice_primary_cert_address"

run_success "alice primary mail send --plaintext" run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Per-membership primary" \
  --body "Primary address hello"
alice_primary_mail_exit=$?
assert_eq "alice primary-team mail exit" "0" "$alice_primary_mail_exit"

capture_success bob_per_membership_inbox "bob_per_membership_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
bob_primary_from_address="$(echo "$bob_per_membership_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership primary'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice primary from_address" "test.local/alice" "$bob_primary_from_address"

run_success "alice primary chat send" run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext bob \
  "Per-membership primary chat"
alice_primary_chat_exit=$?
assert_eq "alice primary-team chat exit" "0" "$alice_primary_chat_exit"

capture_success bob_primary_pending "bob_primary_pending" run_aw_in "$BOB_DIR" chat pending --json
bob_primary_chat_from_address="$(echo "$bob_primary_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership primary chat'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice primary chat from_address" "test.local/alice" "$bob_primary_chat_from_address"

if bob_primary_reply_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --to-address test.local/alice \
  --subject "Reply primary address" \
  --body "Reply to alice primary address" 2>&1)"; then
  bob_primary_reply_exit=0
else
  bob_primary_reply_exit=$?
fi
assert_eq "bob replies to alice primary address" "0" "$bob_primary_reply_exit"
if [[ "$bob_primary_reply_exit" != "0" ]]; then
  echo "  bob primary reply output: ${bob_primary_reply_out:0:240}"
fi

capture_success alice_primary_reply_inbox "alice_primary_reply_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_primary_reply_body="$(echo "$alice_primary_reply_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('subject')=='Reply primary address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives primary address reply" "Reply to alice primary address" "$alice_primary_reply_body"

run_success "alice switch partner" run_aw_in "$ALICE_DIR" id team switch main:partner.local
alice_partner_setup_switch_exit=$?
assert_eq "alice switches to partner team for initial connect" "0" "$alice_partner_setup_switch_exit"
run_success "alice partner init" run_aw_in "$ALICE_DIR" init --url "$AWEB_URL"
alice_partner_initial_connect_exit=$?
assert_eq "alice initially connects partner team" "0" "$alice_partner_initial_connect_exit"
run_success "alice switch devteam" run_aw_in "$ALICE_DIR" id team switch devteam:test.local
alice_primary_setup_restore_exit=$?
assert_eq "alice returns to primary after partner setup" "0" "$alice_primary_setup_restore_exit"

run_success "alice switch partner" run_aw_in "$ALICE_DIR" id team switch main:partner.local
alice_switch_partner_exit=$?
assert_eq "alice switches to partner team without re-init" "0" "$alice_switch_partner_exit"

capture_success alice_partner_whoami "alice_partner_whoami" run_aw_in "$ALICE_DIR" whoami --json
alice_partner_whoami_domain="$(echo "$alice_partner_whoami" | jq_field domain)"
alice_partner_whoami_address="$(echo "$alice_partner_whoami" | jq_field address)"
assert_eq "alice partner whoami domain after switch" "partner.local" "$alice_partner_whoami_domain"
assert_eq "alice partner whoami address after switch" "partner.local/alice" "$alice_partner_whoami_address"

run_success "alice partner mail send --plaintext" run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Per-membership partner" \
  --body "Partner address hello"
alice_partner_mail_exit=$?
assert_eq "alice partner-team mail exit" "0" "$alice_partner_mail_exit"

capture_success partner_bob_inbox "partner_bob_inbox" run_aw_in "$PARTNER_BOB_DIR" mail inbox --json --show-all
partner_bob_from_address="$(echo "$partner_bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership partner'), ''))" 2>/dev/null || echo "")"
assert_eq "partner bob sees alice partner from_address" "partner.local/alice" "$partner_bob_from_address"

run_success "alice partner chat send" run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext bob \
  "Per-membership partner chat"
alice_partner_chat_exit=$?
assert_eq "alice partner-team chat exit" "0" "$alice_partner_chat_exit"

capture_success partner_bob_pending "partner_bob_pending" run_aw_in "$PARTNER_BOB_DIR" chat pending --json
partner_bob_chat_from_address="$(echo "$partner_bob_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership partner chat'), ''))" 2>/dev/null || echo "")"
assert_eq "partner bob sees alice partner chat from_address" "partner.local/alice" "$partner_bob_chat_from_address"
if [[ "$partner_bob_chat_from_address" != "partner.local/alice" ]]; then
  echo "  partner bob pending output: ${partner_bob_pending:0:400}"
fi

if partner_bob_reply_out="$(run_aw_in "$PARTNER_BOB_DIR" mail send --plaintext \
  --to-address partner.local/alice \
  --subject "Reply partner address" \
  --body "Reply to alice partner address" 2>&1)"; then
  partner_bob_reply_exit=0
else
  partner_bob_reply_exit=$?
fi
assert_eq "partner bob replies to alice partner address" "0" "$partner_bob_reply_exit"
if [[ "$partner_bob_reply_exit" != "0" ]]; then
  echo "  partner bob reply output: ${partner_bob_reply_out:0:240}"
fi

if alice_partner_reply_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>&1)"; then
  alice_partner_reply_inbox_exit=0
else
  alice_partner_reply_inbox_exit=$?
fi
assert_eq "alice partner inbox read exit" "0" "$alice_partner_reply_inbox_exit"
if [[ "$alice_partner_reply_inbox_exit" != "0" ]]; then
  echo "  alice partner inbox output: ${alice_partner_reply_inbox:0:240}"
fi
alice_partner_reply_body="$(echo "$alice_partner_reply_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('subject')=='Reply partner address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives partner address reply" "Reply to alice partner address" "$alice_partner_reply_body"

run_success "alice switch devteam" run_aw_in "$ALICE_DIR" id team switch devteam:test.local
alice_restore_primary_exit=$?
assert_eq "alice restores primary team without re-init" "0" "$alice_restore_primary_exit"

capture_success alice_restored_whoami "alice_restored_whoami" run_aw_in "$ALICE_DIR" whoami --json
alice_restored_whoami_domain="$(echo "$alice_restored_whoami" | jq_field domain)"
alice_restored_whoami_address="$(echo "$alice_restored_whoami" | jq_field address)"
assert_eq "alice restored whoami domain after switch" "test.local" "$alice_restored_whoami_domain"
assert_eq "alice restored whoami address after switch" "test.local/alice" "$alice_restored_whoami_address"

run_success "alice restored primary mail send --plaintext" run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Per-membership restored primary" \
  --body "Restored primary address hello"
alice_restored_mail_exit=$?
assert_eq "alice restored primary-team mail exit" "0" "$alice_restored_mail_exit"

capture_success bob_restored_inbox "bob_restored_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
bob_restored_from_address="$(echo "$bob_restored_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership restored primary'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice restored primary from_address" "test.local/alice" "$bob_restored_from_address"

run_success "alice restored primary chat send" run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext bob \
  "Per-membership restored primary chat"
alice_restored_chat_exit=$?
assert_eq "alice restored primary-team chat exit" "0" "$alice_restored_chat_exit"

capture_success bob_restored_pending "bob_restored_pending" run_aw_in "$BOB_DIR" chat pending --json
bob_restored_chat_from_address="$(echo "$bob_restored_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership restored primary chat'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice restored primary chat from_address" "test.local/alice" "$bob_restored_chat_from_address"

if sse_initial_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --to alice \
  --subject "SSE continuation initial" \
  --body "SSE continuation starts here" \
  --json 2>&1)"; then
  sse_initial_exit=0
else
  sse_initial_exit=$?
fi
assert_eq "sse continuation initial mail exit" "0" "$sse_initial_exit"
sse_conversation_id="$(echo "$sse_initial_out" | jq_field conversation_id)"
assert_not_empty "sse continuation initial returns conversation_id" "$sse_conversation_id"
sse_capture_file="$(mktemp "${TMPDIR:-/tmp}/aw-sse-conversation.XXXXXX")"
run_aw_in "$BOB_DIR" events stream --json --timeout 8 >"$sse_capture_file" 2>/dev/null &
sse_capture_pid=$!
sleep 2
if sse_reply_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --conversation-id "$sse_conversation_id" \
  --subject "SSE continuation reply" \
  --body "SSE continuation live event" \
  --json 2>&1)"; then
  sse_reply_exit=0
else
  sse_reply_exit=$?
fi
assert_eq "sse continuation reply mail exit" "0" "$sse_reply_exit"
sse_reply_conversation_id="$(echo "$sse_reply_out" | jq_field conversation_id)"
assert_eq "sse continuation reply keeps conversation_id" "$sse_conversation_id" "$sse_reply_conversation_id"
wait "$sse_capture_pid" 2>/dev/null || true
sse_event_conversation_id="$(python3 -c "
import sys, json
capture_path, subject = sys.argv[1], sys.argv[2]
with open(capture_path, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if event.get('type') == 'actionable_mail' and event.get('subject') == subject:
            print(event.get('conversation_id', ''))
            break
    else:
        print('')
" "$sse_capture_file" "SSE continuation reply")"
assert_eq "sse live event carries continuation conversation_id" "$sse_conversation_id" "$sse_event_conversation_id"

if cross_ns_mail_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to-address partner.local/bob \
  --subject "Cross namespace conversation" \
  --body "Cross namespace initial" \
  --json 2>&1)"; then
  cross_ns_mail_exit=0
else
  cross_ns_mail_exit=$?
fi
assert_eq "cross-namespace global initial mail exit" "0" "$cross_ns_mail_exit"
if [[ "$cross_ns_mail_exit" != "0" ]]; then
  echo "  cross namespace mail output: ${cross_ns_mail_out:0:240}"
fi
cross_ns_conversation_id="$(echo "$cross_ns_mail_out" | jq_field conversation_id)"
assert_not_empty "cross-namespace global initial returns conversation_id" "$cross_ns_conversation_id"

if cross_ns_reply_out="$(run_aw_in "$PARTNER_BOB_DIR" mail send --plaintext \
  --conversation-id "$cross_ns_conversation_id" \
  --subject "Cross namespace reply" \
  --body "Cross namespace response" \
  --json 2>&1)"; then
  cross_ns_reply_exit=0
else
  cross_ns_reply_exit=$?
fi
assert_eq "cross-namespace global reply via stored participant route" "0" "$cross_ns_reply_exit"
if [[ "$cross_ns_reply_exit" != "0" ]]; then
  echo "  cross namespace reply output: ${cross_ns_reply_out:0:240}"
fi
cross_ns_reply_conversation_id="$(echo "$cross_ns_reply_out" | jq_field conversation_id)"
assert_eq "cross-namespace global reply stays in conversation" "$cross_ns_conversation_id" "$cross_ns_reply_conversation_id"

capture_success alice_cross_ns_inbox "alice_cross_ns_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_cross_ns_reply_body="$(echo "$alice_cross_ns_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')=='$cross_ns_conversation_id' and m.get('subject')=='Cross namespace reply'), ''))" 2>/dev/null || echo "")"
assert_eq "cross-namespace global reply delivered" "Cross namespace response" "$alice_cross_ns_reply_body"
echo ""

# ---------------------------------------------------------------------------
# Phase 12e: Messaging global/local routing contract
# ---------------------------------------------------------------------------
echo "=== Phase 12e: Messaging global/local routing contract ==="

capture_success seed_bob_address_out "seed_bob_address_out" run_aw_in "$ALICE_DIR" id namespace assign-address \
  --domain test.local \
  --name bob \
  --did-aw "$BOB_DID_AW" \
  --json
seed_bob_address_status="$(echo "$seed_bob_address_out" | jq_field status)"
if [[ "$seed_bob_address_status" == "assigned" || "$seed_bob_address_status" == "already_assigned" ]]; then
  echo "  PASS: global bob registry address seeded"
  pass=$((pass + 1))
else
  echo "  FAIL: global bob registry address seeded (status=$seed_bob_address_status output=${seed_bob_address_out:0:180})"
  fail=$((fail + 1))
fi

if alice_global_addr_mail_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to-address test.local/bob \
  --subject "Global direct address" \
  --body "Global direct address mail" 2>&1)"; then
  alice_global_addr_mail_exit=0
else
  alice_global_addr_mail_exit=$?
fi
assert_eq "global direct-address mail exit" "0" "$alice_global_addr_mail_exit"
if [[ "$alice_global_addr_mail_exit" != "0" ]]; then
  echo "  global direct-address mail output: ${alice_global_addr_mail_out:0:240}"
fi

capture_success bob_matrix_inbox "bob_matrix_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
bob_global_addr_vs="$(echo "$bob_matrix_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('verification_status','') for m in msgs if m.get('subject')=='Global direct address'), ''))" 2>/dev/null || echo "")"
assert_eq "global direct-address mail verified" "verified" "$bob_global_addr_vs"
if [[ "$bob_global_addr_vs" != "verified" ]]; then
  echo "$bob_matrix_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); m=next((m for m in msgs if m.get('subject')=='Global direct address'), {}); print('  global address mail debug:', {k:m.get(k,'') for k in ['from_address','from_did','from_stable_id','to_address','to_did','to_stable_id','verification_status']})" 2>/dev/null || true
fi

if alice_global_addr_chat_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext test.local/bob \
  "Global direct address chat" 2>&1)"; then
  alice_global_addr_chat_exit=0
else
  alice_global_addr_chat_exit=$?
fi
assert_eq "global direct-address chat exit" "0" "$alice_global_addr_chat_exit"
if [[ "$alice_global_addr_chat_exit" != "0" ]]; then
  echo "  global direct-address chat output: ${alice_global_addr_chat_out:0:240}"
fi
capture_success bob_global_addr_history "bob_global_addr_history" run_aw_in "$BOB_DIR" chat history test.local/alice --json
bob_global_addr_chat_vs="$(echo "$bob_global_addr_history" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('verification_status','') for m in msgs if m.get('body')=='Global direct address chat'), ''))" 2>/dev/null || echo "")"
assert_eq "global direct-address chat verified" "verified" "$bob_global_addr_chat_vs"
if [[ "$bob_global_addr_chat_vs" != "verified" ]]; then
  echo "$bob_global_addr_history" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); m=next((m for m in msgs if m.get('body')=='Global direct address chat'), {}); print('  global address chat debug:', {k:m.get(k,'') for k in ['from_address','from_did','from_stable_id','to_address','to_did','to_stable_id','verification_status']})" 2>/dev/null || true
fi

if bob_hidden_start_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --to-address "test.local/alice" \
  --subject "Global conversation bob starts" \
  --body "Bob starts a global conversation" \
  --json 2>&1)"; then
  bob_hidden_start_exit=0
else
  bob_hidden_start_exit=$?
fi
assert_eq "global conversation bob initiates outbound mail" "0" "$bob_hidden_start_exit"
if [[ "$bob_hidden_start_exit" != "0" ]]; then
  echo "  global bob start output: ${bob_hidden_start_out:0:240}"
fi
bob_hidden_conversation_id="$(echo "$bob_hidden_start_out" | jq_field conversation_id)"
assert_not_empty "global conversation initial mail returns conversation_id" "$bob_hidden_conversation_id"

capture_success alice_hidden_start_inbox "alice_hidden_start_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_hidden_start_body="$(echo "$alice_hidden_start_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')=='$bob_hidden_conversation_id'), ''))" 2>/dev/null || echo "")"
assert_eq "global conversation alice receives bob initiation" "Bob starts a global conversation" "$alice_hidden_start_body"

if alice_hidden_reply_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --conversation-id "$bob_hidden_conversation_id" \
  --subject "Global conversation reply" \
  --body "Reply through stored participant route" \
  --json 2>&1)"; then
  alice_hidden_reply_exit=0
else
  alice_hidden_reply_exit=$?
fi
assert_eq "global conversation alice replies by stored participant route" "0" "$alice_hidden_reply_exit"
if [[ "$alice_hidden_reply_exit" != "0" ]]; then
  echo "  global reply output: ${alice_hidden_reply_out:0:240}"
fi
alice_hidden_reply_conversation_id="$(echo "$alice_hidden_reply_out" | jq_field conversation_id)"
assert_eq "global conversation reply stays in same conversation" "$bob_hidden_conversation_id" "$alice_hidden_reply_conversation_id"

capture_success bob_hidden_reply_inbox "bob_hidden_reply_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
bob_hidden_reply_body="$(echo "$bob_hidden_reply_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')=='$bob_hidden_conversation_id' and m.get('subject')=='Global conversation reply'), ''))" 2>/dev/null || echo "")"
assert_eq "global conversation bob receives stored-route reply" "Reply through stored participant route" "$bob_hidden_reply_body"

if carol_leaked_conversation_out="$(run_aw_in "$CAROL_DIR" mail send --plaintext \
  --conversation-id "$bob_hidden_conversation_id" \
  --subject "Conversation leaked id" \
  --body "Carol should not enter this conversation" 2>&1)"; then
  carol_leaked_conversation_exit=0
else
  carol_leaked_conversation_exit=$?
fi
if [[ "$carol_leaked_conversation_exit" != "0" ]] && echo "$carol_leaked_conversation_out" | grep -qi "not a participant\|403"; then
  echo "  PASS: leaked conversation_id rejected as non-participant"
  pass=$((pass + 1))
else
  echo "  FAIL: leaked conversation_id should return participant rejection (exit=$carol_leaked_conversation_exit output=${carol_leaked_conversation_out:0:180})"
  fail=$((fail + 1))
fi

if missing_conversation_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --conversation-id "99999999-9999-4999-8999-999999999999" \
  --subject "Missing conversation" \
  --body "Missing conversation should fail" 2>&1)"; then
  missing_conversation_exit=0
else
  missing_conversation_exit=$?
fi
if [[ "$missing_conversation_exit" != "0" ]] && echo "$missing_conversation_out" | grep -qi "Conversation not found\|404"; then
  echo "  PASS: missing conversation_id returns not found"
  pass=$((pass + 1))
else
  echo "  FAIL: missing conversation_id should return 404 (exit=$missing_conversation_exit output=${missing_conversation_out:0:180})"
  fail=$((fail + 1))
fi

psql_exec "UPDATE aweb.conversations SET status = 'closed' WHERE conversation_id = '${bob_hidden_conversation_id}'::uuid;"
if closed_conversation_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --conversation-id "$bob_hidden_conversation_id" \
  --subject "Closed conversation" \
  --body "Closed conversation should fail" 2>&1)"; then
  closed_conversation_exit=0
else
  closed_conversation_exit=$?
fi
if [[ "$closed_conversation_exit" != "0" ]] && echo "$closed_conversation_out" | grep -qi "closed\|403"; then
  echo "  PASS: closed conversation rejects continuation"
  pass=$((pass + 1))
else
  echo "  FAIL: closed conversation should reject continuation (exit=$closed_conversation_exit output=${closed_conversation_out:0:180})"
  fail=$((fail + 1))
fi

if ttl_start_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Conversation TTL slide" \
  --body "TTL initial" \
  --json 2>&1)"; then
  ttl_start_exit=0
else
  ttl_start_exit=$?
fi
assert_eq "conversation ttl slide initial mail exit" "0" "$ttl_start_exit"
if [[ "$ttl_start_exit" != "0" ]]; then
  echo "  ttl slide initial output: ${ttl_start_out:0:240}"
fi
ttl_conversation_id="$(echo "$ttl_start_out" | jq_field conversation_id)"
assert_not_empty "conversation ttl slide initial returns conversation_id" "$ttl_conversation_id"
psql_exec "UPDATE aweb.conversations SET expires_at = NOW() + INTERVAL '1 day' WHERE conversation_id = '${ttl_conversation_id}'::uuid;"
if ttl_reply_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --conversation-id "$ttl_conversation_id" \
  --subject "Conversation TTL reply" \
  --body "TTL reply" \
  --json 2>&1)"; then
  ttl_reply_exit=0
else
  ttl_reply_exit=$?
fi
assert_eq "conversation ttl slide continuation exit" "0" "$ttl_reply_exit"
ttl_slid="$(psql_scalar "SELECT CASE WHEN expires_at > NOW() + INTERVAL '29 days' THEN 'yes' ELSE 'no' END FROM aweb.conversations WHERE conversation_id = '${ttl_conversation_id}'::uuid;")"
assert_eq "conversation continuation slides ttl 30 days" "yes" "$ttl_slid"

if expired_start_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Conversation concurrent expiry" \
  --body "Expiry initial" \
  --json 2>&1)"; then
  expired_start_exit=0
else
  expired_start_exit=$?
fi
assert_eq "conversation concurrent expiry initial mail exit" "0" "$expired_start_exit"
expired_conversation_id="$(echo "$expired_start_out" | jq_field conversation_id)"
assert_not_empty "conversation concurrent expiry returns conversation_id" "$expired_conversation_id"
psql_exec "UPDATE aweb.conversations SET expires_at = NOW() - INTERVAL '1 second' WHERE conversation_id = '${expired_conversation_id}'::uuid;"
expired_one_out="$E2E_CWD/expired-one.out"
expired_two_out="$E2E_CWD/expired-two.out"
expired_one_code="$E2E_CWD/expired-one.code"
expired_two_code="$E2E_CWD/expired-two.code"
(
  set +e
  run_aw_in "$BOB_DIR" mail send --plaintext \
    --conversation-id "$expired_conversation_id" \
    --subject "Expired one" \
    --body "Expired one" >"$expired_one_out" 2>&1
  echo $? >"$expired_one_code"
) &
expired_one_pid=$!
(
  set +e
  run_aw_in "$BOB_DIR" mail send --plaintext \
    --conversation-id "$expired_conversation_id" \
    --subject "Expired two" \
    --body "Expired two" >"$expired_two_out" 2>&1
  echo $? >"$expired_two_code"
) &
expired_two_pid=$!
wait "$expired_one_pid" 2>/dev/null || true
wait "$expired_two_pid" 2>/dev/null || true
expired_one_exit="$(cat "$expired_one_code" 2>/dev/null || echo 0)"
expired_two_exit="$(cat "$expired_two_code" 2>/dev/null || echo 0)"
expired_one_text="$(cat "$expired_one_out" 2>/dev/null || true)"
expired_two_text="$(cat "$expired_two_out" 2>/dev/null || true)"
expired_status="$(psql_scalar "SELECT status FROM aweb.conversations WHERE conversation_id = '${expired_conversation_id}'::uuid;")"
if [[ "$expired_one_exit" != "0" && "$expired_two_exit" != "0" && "$expired_status" == "expired" ]] && \
   echo "$expired_one_text $expired_two_text" | grep -qi "expired\|403"; then
  echo "  PASS: conversation concurrent lazy expiry rejects both continuations"
  pass=$((pass + 1))
else
  echo "  FAIL: conversation concurrent lazy expiry should reject both (exit1=$expired_one_exit exit2=$expired_two_exit status=$expired_status output1=${expired_one_text:0:120} output2=${expired_two_text:0:120})"
  fail=$((fail + 1))
fi

if alice_stable_mail_out="$(run_aw_in "$ALICE_DIR" mail send \
  --to-did "$BOB_DID_AW" \
  --subject "Global stable did target" \
  --body "Global stable did target mail" 2>&1)"; then
  alice_stable_mail_exit=0
else
  alice_stable_mail_exit=$?
fi
if [[ "$alice_stable_mail_exit" != "0" ]] && echo "$alice_stable_mail_out" | grep -qi "did:aw first-contact\|use.*address\|unsupported"; then
  echo "  PASS: global stable did:aw first-contact fails closed"
  pass=$((pass + 1))
else
  echo "  FAIL: global stable did:aw first-contact should fail closed (exit=$alice_stable_mail_exit output=${alice_stable_mail_out:0:240})"
  fail=$((fail + 1))
fi

if rotation_start_out="$(run_aw_in "$ALICE_DIR" mail send --plaintext \
  --to bob \
  --subject "Conversation rotation initial" \
  --body "Rotation initial" \
  --json 2>&1)"; then
  rotation_start_exit=0
else
  rotation_start_exit=$?
fi
assert_eq "conversation rotation initial mail exit" "0" "$rotation_start_exit"
rotation_conversation_id="$(echo "$rotation_start_out" | jq_field conversation_id)"
assert_not_empty "conversation rotation initial returns conversation_id" "$rotation_conversation_id"

if bob_rotate_out="$(run_aw_in "$BOB_DIR" id rotate-key --json 2>&1)"; then
  bob_rotate_exit=0
else
  bob_rotate_exit=$?
fi
assert_eq "conversation bob rotates did:key" "0" "$bob_rotate_exit"
if [[ "$bob_rotate_exit" != "0" ]]; then
  echo "  bob rotate output: ${bob_rotate_out:0:240}"
fi
bob_rotated_new_did="$(echo "$bob_rotate_out" | jq_field new_did)"
assert_not_empty "conversation bob rotation returns new did:key" "$bob_rotated_new_did"

if rotation_reply_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --conversation-id "$rotation_conversation_id" \
  --subject "Conversation rotation reply" \
  --body "Rotation reply after did:key change" \
  --json 2>&1)"; then
  rotation_reply_exit=0
else
  rotation_reply_exit=$?
fi
assert_eq "conversation rotated did:key continues did:aw conversation" "0" "$rotation_reply_exit"
if [[ "$rotation_reply_exit" != "0" ]]; then
  echo "  rotation reply output: ${rotation_reply_out:0:240}"
fi
rotation_reply_conversation_id="$(echo "$rotation_reply_out" | jq_field conversation_id)"
assert_eq "conversation rotated reply stays in conversation" "$rotation_conversation_id" "$rotation_reply_conversation_id"

capture_success alice_rotation_inbox "alice_rotation_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_rotation_reply_body="$(echo "$alice_rotation_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')=='$rotation_conversation_id' and m.get('subject')=='Conversation rotation reply'), ''))" 2>/dev/null || echo "")"
assert_eq "conversation rotated reply delivered" "Rotation reply after did:key change" "$alice_rotation_reply_body"

if partner_bob_bare_mail_out="$(run_aw_in "$PARTNER_BOB_DIR" mail send --plaintext \
  --to alice \
  --subject "Bare alias duplicate partner" \
  --body "Bare alias should stay in partner team" 2>&1)"; then
  partner_bob_bare_mail_exit=0
else
  partner_bob_bare_mail_exit=$?
fi
assert_eq "partner bob bare-alias mail exit with duplicate alice" "0" "$partner_bob_bare_mail_exit"
if [[ "$partner_bob_bare_mail_exit" != "0" ]]; then
  echo "  partner bob bare-alias mail output: ${partner_bob_bare_mail_out:0:240}"
fi
partner_bob_bare_mail_team="$(psql_scalar "SELECT COALESCE(a.team_id, '') FROM aweb.messages m LEFT JOIN aweb.agents a ON a.agent_id = m.to_agent_id WHERE m.subject = 'Bare alias duplicate partner' ORDER BY m.created_at DESC LIMIT 1;")"
partner_bob_bare_mail_address="$(psql_scalar "SELECT COALESCE(a.address, '') FROM aweb.messages m LEFT JOIN aweb.agents a ON a.agent_id = m.to_agent_id WHERE m.subject = 'Bare alias duplicate partner' ORDER BY m.created_at DESC LIMIT 1;")"
assert_eq "partner bob bare-alias mail routes to active team alice" "main:partner.local" "$partner_bob_bare_mail_team"
assert_eq "partner bob bare-alias mail does not route to primary alice" "partner.local/alice" "$partner_bob_bare_mail_address"

if partner_bob_bare_chat_out="$(run_aw_in "$PARTNER_BOB_DIR" chat send-and-leave --plaintext alice \
  "Bare alias duplicate partner chat" 2>&1)"; then
  partner_bob_bare_chat_exit=0
else
  partner_bob_bare_chat_exit=$?
fi
assert_eq "partner bob bare-alias chat exit with duplicate alice" "0" "$partner_bob_bare_chat_exit"
if [[ "$partner_bob_bare_chat_exit" != "0" ]]; then
  echo "  partner bob bare-alias chat output: ${partner_bob_bare_chat_out:0:240}"
fi
partner_bob_bare_chat_address="$(psql_scalar "SELECT COALESCE(cp.address, '') FROM aweb.chat_messages cm JOIN aweb.chat_participants cp ON cp.session_id = cm.session_id AND cp.alias = 'alice' WHERE cm.body = 'Bare alias duplicate partner chat' ORDER BY cm.created_at DESC LIMIT 1;")"
assert_eq "partner bob bare-alias chat routes to active team alice" "partner.local/alice" "$partner_bob_bare_chat_address"
echo ""

# ---------------------------------------------------------------------------
# Phase 13: Tasks
# ---------------------------------------------------------------------------
echo "=== Phase 13: Tasks ==="

capture_success task_create_out "task_create_out" run_aw_in "$ALICE_DIR" task create \
  --title "E2E test task" --json
TASK_REF="$(echo "$task_create_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('task_ref') or d.get('task_id',''))" 2>/dev/null || echo "")"
assert_not_empty "task created" "$TASK_REF"

capture_success task_list_out "task_list_out" run_aw_in "$ALICE_DIR" task list
assert_contains "task list shows our task" "$task_list_out" "E2E test task"
echo ""

# ---------------------------------------------------------------------------
# Phase 14: Locks
# ---------------------------------------------------------------------------
echo "=== Phase 14: Locks ==="

run_success "lock acquire" run_aw_in "$ALICE_DIR" lock acquire --resource-key test-file
lock_exit=$?
assert_eq "lock acquire exit" "0" "$lock_exit"

capture_success lock_list "lock_list" run_aw_in "$ALICE_DIR" lock list
assert_contains "lock list shows test-file" "$lock_list" "test-file"

run_success "lock release" run_aw_in "$ALICE_DIR" lock release --resource-key test-file
pass=$((pass + 1))
echo "  PASS: lock released"
echo ""

# ---------------------------------------------------------------------------
# Phase 15: Roles
# ---------------------------------------------------------------------------
echo "=== Phase 15: Roles ==="

capture_success roles_out "roles_out" run_aw_in "$ALICE_DIR" roles show
roles_exit=$?
assert_eq "roles show exit" "0" "$roles_exit"
echo ""

# ---------------------------------------------------------------------------
# Phase 16: Verify team at awid
# ---------------------------------------------------------------------------
echo "=== Phase 16: Verify team at awid ==="

team_get="$(curl -sf "$AWID_URL/v1/namespaces/test.local/teams/devteam" 2>/dev/null || echo '{}')"
team_get_name="$(echo "$team_get" | jq_field name)"
assert_eq "awid team name" "devteam" "$team_get_name"

certs_list="$(curl -sf "$AWID_URL/v1/namespaces/test.local/teams/devteam/certificates?active_only=true" 2>/dev/null || echo '{"certificates":[]}')"
cert_count="$(echo "$certs_list" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('certificates',[])))" 2>/dev/null || echo "0")"
assert_eq "6 active certificates (alice, bob, erin, eve, gsk, and nokey)" "6" "$cert_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 17: Revoke bob's membership
# ---------------------------------------------------------------------------
echo "=== Phase 17: Revoke bob's membership ==="

capture_success revoke_out "revoke_out" run_aw_in "$ALICE_DIR" id team remove-member \
  --team devteam \
  --namespace test.local \
  --member test.local/bob \
  --json

REVOKE_STATUS="$(echo "$revoke_out" | jq_field status)"
# The certificate primitive reports what it did, not one word for every outcome:
# revoked when it revoked something, no_active_certificate when the registry
# stated there was nothing active to revoke.
assert_eq "bob revoked" "revoked" "$REVOKE_STATUS"
echo ""

# ---------------------------------------------------------------------------
# Phase 18: Verify revocation at awid
# ---------------------------------------------------------------------------
echo "=== Phase 18: Verify revocation at awid ==="

revocations="$(curl -sf "$AWID_URL/v1/namespaces/test.local/teams/devteam/revocations" 2>/dev/null || echo '{"revocations":[]}')"
revocation_count="$(echo "$revocations" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('revocations',[])))" 2>/dev/null || echo "0")"
assert_eq "1 revocation" "1" "$revocation_count"

active_certs="$(curl -sf "$AWID_URL/v1/namespaces/test.local/teams/devteam/certificates?active_only=true" 2>/dev/null || echo '{"certificates":[]}')"
active_count="$(echo "$active_certs" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('certificates',[])))" 2>/dev/null || echo "0")"
assert_eq "5 active certificates (alice, erin, eve, gsk, and nokey)" "5" "$active_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 18b: Retiring an agent releases its claims, then revokes its certificate
#
# Every reading here comes from psql or from awid, never from the command under
# test. A retirement command reporting on its own success is what this whole
# change exists to stop trusting, and that applies to proving it too.
# ---------------------------------------------------------------------------
echo "=== Phase 18b: Retire nokey across both stores ==="

NOKEY_WORKSPACE_ID="$(psql_scalar "SELECT workspace_id FROM aweb.workspaces WHERE team_id = 'devteam:test.local' AND alias = 'nokey' AND deleted_at IS NULL;")"
assert_not_empty "nokey workspace id" "$NOKEY_WORKSPACE_ID"

# Give nokey a claim to lose, and age its presence past the window that refuses
# to delete a workspace still being used.
psql_exec "INSERT INTO aweb.task_claims (team_id, workspace_id, alias, human_name, task_ref, claimed_at) VALUES ('devteam:test.local', '$NOKEY_WORKSPACE_ID', 'nokey', '', 'devteam-retire-1', NOW());"
psql_exec "UPDATE aweb.workspaces SET last_seen_at = NOW() - INTERVAL '2 hours' WHERE workspace_id = '$NOKEY_WORKSPACE_ID';"

claims_before="$(psql_scalar "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$NOKEY_WORKSPACE_ID';")"
assert_eq "nokey holds a claim before retirement" "1" "$claims_before"

# The verification runs before anything is written, so a namespace that is not
# this team's must refuse and leave both stores exactly as they were. This is the
# only place the coordination call site is driven through the real command - the
# Go tests reach the verification helper directly, so they stay green if nothing
# wires it in.
if wrong_ns_out="$(run_aw_in "$ALICE_DIR" team remove-agent evil.local/nokey \
  --team-id devteam:test.local --json 2>&1)"; then
  wrong_ns_exit=0
else
  wrong_ns_exit=$?
fi
assert_eq "retiring a wrong-namespace address refuses" "1" "$wrong_ns_exit"
# Assert the VERIFICATION refused, not merely that the command exited non-zero.
# With the verification unwired the command still fails - the revoke declines
# without an established member - so a bare exit-status check passes while the
# workspace has already been deleted. The wording below is only produced before
# anything is written.
assert_contains "the verification is what refused" "$wrong_ns_out" "is a member of this team only"
assert_contains "refusal names the team namespace" "$wrong_ns_out" "not evil.local"

claims_after_refusal="$(psql_scalar "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$NOKEY_WORKSPACE_ID';")"
assert_eq "refused retirement released no claim" "1" "$claims_after_refusal"
workspace_after_refusal="$(psql_scalar "SELECT (deleted_at IS NULL) FROM aweb.workspaces WHERE workspace_id = '$NOKEY_WORKSPACE_ID';")"
assert_eq "refused retirement left the workspace record intact" "t" "$workspace_after_refusal"

capture_success retire_out "retire_out" run_aw_in "$ALICE_DIR" team remove-agent test.local/nokey \
  --team-id devteam:test.local \
  --json

RETIRE_STATUS="$(echo "$retire_out" | jq_field status)"
assert_eq "nokey retired" "retired" "$RETIRE_STATUS"

# A customer-controlled team CAN establish which principal an alias names, so a
# retirement here must not carry the disclosure that it could not. Nothing else
# asserts that the flag is driven by the verification rather than set by hand:
# the Go tests pass it in directly, so they hold whatever production does.
retire_disclosure_count="$(echo "$retire_out" | grep -c "selected by alias" || true)"
assert_eq "a verified retirement carries no unverified disclosure" "0" "$retire_disclosure_count"

# The load-bearing assertion: the rows are gone, read from the store itself.
claims_after="$(psql_scalar "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$NOKEY_WORKSPACE_ID';")"
assert_eq "retirement released nokey's claim" "0" "$claims_after"

workspace_deleted="$(psql_scalar "SELECT (deleted_at IS NOT NULL) FROM aweb.workspaces WHERE workspace_id = '$NOKEY_WORKSPACE_ID';")"
assert_eq "retirement deleted nokey's workspace record" "t" "$workspace_deleted"

# And the count the command reported agrees with what the store shows.
retire_claims_released="$(echo "$retire_out" | python3 -c "import sys,json; print(json.load(sys.stdin).get('claims_released'))" 2>/dev/null || echo "")"
assert_eq "retirement reported the claim it released" "1" "$retire_claims_released"

nokey_active_certs="$(curl -sf "$AWID_URL/v1/namespaces/test.local/teams/devteam/certificates?active_only=true" 2>/dev/null || echo '{"certificates":[]}')"
nokey_active_count="$(echo "$nokey_active_certs" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('certificates',[])))" 2>/dev/null || echo "0")"
assert_eq "4 active certificates after retiring nokey" "4" "$nokey_active_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 19: Alice still works after bob's revocation
# ---------------------------------------------------------------------------
echo "=== Phase 19: Alice still works ==="

capture_success alice_whoami "alice_whoami" run_aw_in "$ALICE_DIR" whoami --json
alice_alias_check="$(echo "$alice_whoami" | jq_field alias)"
assert_eq "alice still connected" "alice" "$alice_alias_check"
echo ""

# ---------------------------------------------------------------------------
# Phase 20: Bob's requests fail after cache flush
# ---------------------------------------------------------------------------
echo "=== Phase 20: Bob's requests fail after revocation ==="

echo "  Flushing cached team revocations from Redis..."
revocation_flush_out="$(
  cd "$SERVER_DIR" && docker compose --env-file .env.e2e exec -T redis sh -lc "
    keys=\$(redis-cli --scan --pattern 'awid:registry_cache:v1:team_revocations:*')
    if [ -n \"\$keys\" ]; then
      printf '%s\n' \"\$keys\" | xargs redis-cli DEL
    else
      echo 0
    fi
  "
)"
echo "$revocation_flush_out"

if bob_mail_out="$(run_aw_in "$BOB_DIR" mail send --plaintext \
  --to alice --body "should fail" 2>&1)"; then
  bob_mail_exit=0
else
  bob_mail_exit=$?
fi

if echo "$bob_mail_out" | grep -qi "revoked\|unauthorized\|forbidden\|401\|403\|certificate"; then
  echo "  PASS: bob's request rejected after revocation"
  pass=$((pass + 1))
else
  echo "  FAIL: bob request should be rejected after revocation cache flush (exit=$bob_mail_exit output=${bob_mail_out:0:120})"
  fail=$((fail + 1))
  exit 1
fi
echo ""

phase_aw_init_reconnect() {
  echo "=== Phase 21: aw init reconnect (Case A) ==="

  rm -rf "$RECONNECT_DIR"
  mkdir -p "$RECONNECT_DIR/.aw"
  cp "$ALICE_DIR/.aw/identity.yaml" "$RECONNECT_DIR/.aw/identity.yaml"
  cp "$ALICE_DIR/.aw/signing.key" "$RECONNECT_DIR/.aw/signing.key"
  mkdir -p "$RECONNECT_DIR/.aw/team-certs"
  alice_primary_cert_path="$(team_cert_path "$ALICE_DIR" "devteam:test.local")"
  cp "$alice_primary_cert_path" "$RECONNECT_DIR/.aw/team-certs/"
  RECONNECT_DIR="$(canonicalize_dir "$RECONNECT_DIR")"

  if reconnect_out="$(run_aw_in "$RECONNECT_DIR" init --url "$AWEB_URL" </dev/null 2>&1)"; then
    reconnect_exit=0
  else
    reconnect_exit=$?
  fi
  assert_eq "reconnect init exit" "0" "$reconnect_exit"
  if [[ "$reconnect_exit" != "0" ]]; then
    echo "  reconnect init output: ${reconnect_out:0:480}"
  fi
  assert_not_contains "reconnect skipped onboarding path prompt" "$reconnect_out" "How should this agent get its identity?"
  assert_not_contains "reconnect skipped post-init prompts" "$reconnect_out" "Inject agent docs into this repo?"
  assert_file_exists "reconnect workspace.yaml written" "$RECONNECT_DIR/.aw/workspace.yaml"
  assert_file_exists "reconnect teams.yaml written" "$RECONNECT_DIR/.aw/teams.yaml"

  reconnect_team="$(yaml_field "$RECONNECT_DIR/.aw/teams.yaml" active_team)"
  reconnect_alias="$(workspace_membership_field "$RECONNECT_DIR/.aw/workspace.yaml" "$reconnect_team" alias)"
  reconnect_role="$(workspace_membership_field "$RECONNECT_DIR/.aw/workspace.yaml" "$reconnect_team" role_name)"
  assert_eq "reconnect workspace team" "devteam:test.local" "$reconnect_team"
  assert_eq "reconnect workspace alias" "alice" "$reconnect_alias"
  assert_eq "reconnect workspace role empty" "" "$reconnect_role"

  if reconnect_mail_out="$(run_aw_in "$RECONNECT_DIR" mail send --plaintext --to alice --subject "Reconnect e2e" --body "Reconnect path works" 2>&1)"; then
    reconnect_mail_exit=0
  else
    reconnect_mail_exit=$?
  fi
  assert_eq "reconnect mail send --plaintext exit" "0" "$reconnect_mail_exit"
  if [[ "$reconnect_mail_exit" != "0" ]]; then
    echo "  reconnect mail output: ${reconnect_mail_out:0:480}"
  fi
  echo ""
}

phase_aw_init_local_quickstart() {
  echo "=== Phase 22: aw init implicit local quickstart ==="

  rm -rf "$WIZARD_BYOD_DIR"
  mkdir -p "$WIZARD_BYOD_DIR"
  WIZARD_BYOD_DIR="$(canonicalize_dir "$WIZARD_BYOD_DIR")"

  local local_alias="local-alice"
  local local_team="default:local"

  if wizard_out="$(run_aw_in "$WIZARD_BYOD_DIR" init \
    --awid-registry "$AWID_URL" \
    --aweb-url "$AWEB_URL" \
    --alias "$local_alias" 2>&1)"; then
    wizard_exit=0
  else
    wizard_exit=$?
  fi
  assert_eq "wizard init exit" "0" "$wizard_exit"
  if [[ "$wizard_exit" != "0" ]]; then
    echo "  wizard output: ${wizard_out:0:480}"
  fi
  if [[ ! -f "$WIZARD_BYOD_DIR/.aw/identity.yaml" ]]; then
    echo "  PASS: local quickstart has no identity.yaml"
    pass=$((pass + 1))
  else
    echo "  FAIL: local quickstart should not write identity.yaml"
    fail=$((fail + 1))
  fi
  assert_file_exists "wizard signing.key written" "$WIZARD_BYOD_DIR/.aw/signing.key"
  assert_file_exists "wizard workspace.yaml written" "$WIZARD_BYOD_DIR/.aw/workspace.yaml"
  assert_file_exists "wizard teams.yaml written" "$WIZARD_BYOD_DIR/.aw/teams.yaml"
  assert_file_mode "wizard signing.key mode" "$WIZARD_BYOD_DIR/.aw/signing.key" "600"
  wizard_cert_path="$(team_cert_path "$WIZARD_BYOD_DIR" "$local_team")"
  assert_file_exists "wizard team certificate written" "$wizard_cert_path"

  wizard_workspace_team="$(yaml_field "$WIZARD_BYOD_DIR/.aw/teams.yaml" active_team)"
  wizard_workspace_alias="$(workspace_membership_field "$WIZARD_BYOD_DIR/.aw/workspace.yaml" "$wizard_workspace_team" alias)"
  assert_eq "wizard workspace team" "$local_team" "$wizard_workspace_team"
  assert_eq "wizard workspace alias" "$local_alias" "$wizard_workspace_alias"

  capture_success wizard_cert_out "wizard_cert_out" run_aw_in "$WIZARD_BYOD_DIR" id cert show --json
  wizard_cert_team="$(echo "$wizard_cert_out" | jq_field team_id)"
  wizard_cert_alias="$(echo "$wizard_cert_out" | jq_field alias)"
  assert_eq "wizard cert team" "$local_team" "$wizard_cert_team"
  assert_eq "wizard cert alias" "$local_alias" "$wizard_cert_alias"

  wizard_namespace="$(curl -sf "$AWID_URL/v1/namespaces/local" 2>/dev/null || echo '{}')"
  wizard_namespace_domain="$(echo "$wizard_namespace" | jq_field domain)"
  assert_eq "local namespace registered" "local" "$wizard_namespace_domain"

  wizard_team_get="$(curl -sf "$AWID_URL/v1/namespaces/local/teams/default" 2>/dev/null || echo '{}')"
  wizard_team_name="$(echo "$wizard_team_get" | jq_field name)"
  assert_eq "local team registered" "default" "$wizard_team_name"

  wizard_certs="$(curl -sf "$AWID_URL/v1/namespaces/local/teams/default/certificates?active_only=true" 2>/dev/null || echo '{"certificates":[]}')"
  wizard_cert_count="$(echo "$wizard_certs" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('certificates',[])))" 2>/dev/null || echo "0")"
  assert_eq "wizard active certificate count" "1" "$wizard_cert_count"

  if wizard_mail_out="$(run_aw_in "$WIZARD_BYOD_DIR" mail send --plaintext --to "$local_alias" --subject "Local quickstart e2e" --body "Local quickstart path works" 2>&1)"; then
    wizard_mail_exit=0
  else
    wizard_mail_exit=$?
  fi
  assert_eq "wizard mail send --plaintext exit" "0" "$wizard_mail_exit"
  if [[ "$wizard_mail_exit" != "0" ]]; then
    echo "  wizard mail output: ${wizard_mail_out:0:480}"
  fi
  assert_contains "wizard output shows local team" "$wizard_out" "default:local"
  echo ""
}

phase_aw_init_reconnect
phase_aw_init_local_quickstart

# ---------------------------------------------------------------------------
# Phase 23: Amy-symptom reproducer (aweb-aalj)
# ---------------------------------------------------------------------------
# Per Randy's 2bc20cf6: reproducer-as-gate discipline. Amy's stack is the
# bug-DATA source; dev environment must verify locally before any v0.5.8
# release tags fire.
#
# This phase reuses Phase 12d's setup (alice has a cross-team-cert
# membership in main:partner.local while her identity is in test.local —
# exactly the aako-pattern: cert.member_address ≠ identity.address). Her
# did:aw is already registered under both test.local/alice and
# partner.local/alice.
#
# Three modes (env: AMY_REPRODUCER_MODE = baseline | intermediate | post):
#   - baseline:     pre-aalg-fix sender CLI + channel 1.3.2 dist
#                   → server vs=identity_mismatch on both transports
#                   → channel mail header verified=false; chat verified=true
#   - intermediate: current sender CLI + channel 1.3.2 dist (default)
#                   → server vs=verified on both transports (aalg fix landed)
#                   → channel mail header still verified=false
#                     (aale-renderer-asymmetry not yet fixed); chat verified=true
#   - post:         current sender CLI + post-aale-fix channel dist
#                   → server vs=verified on both
#                   → channel mail header verified=true; chat verified=true
#
# Env overrides:
#   AMY_REPRODUCER_MODE       baseline | intermediate (default) | post
#   AMY_BASELINE_AW_BIN       path to a pre-aalg-fix aw binary (required for baseline mode)
#   AMY_CHANNEL_DIST_PATH     path to channel/dist/index.js (default: $REPO_ROOT/channel/dist/index.js)
#   AMY_CAPTURE_SECONDS       channel-capture window (default: 25)
phase_amy_symptom_reproducer() {
  echo "=== Phase 23: Amy-symptom reproducer (aako-pattern + cross-namespace + channel capture) ==="

  local mode="${AMY_REPRODUCER_MODE:-intermediate}"
  local capture_seconds="${AMY_CAPTURE_SECONDS:-25}"
  local channel_dist="${AMY_CHANNEL_DIST_PATH:-$REPO_ROOT/channel/dist/index.js}"
  local sender_bin="$CLI_DIR/aw"
  case "$mode" in
    baseline)
      if [[ -z "${AMY_BASELINE_AW_BIN:-}" || ! -x "$AMY_BASELINE_AW_BIN" ]]; then
        echo "  SKIP: baseline mode requires AMY_BASELINE_AW_BIN pointing at a pre-aalg-fix aw binary"
        return 0
      fi
      sender_bin="$AMY_BASELINE_AW_BIN"
      ;;
    intermediate|post)
      ;;
    *)
      echo "  FAIL: unknown AMY_REPRODUCER_MODE=$mode"
      fail=$((fail + 1))
      return 0
      ;;
  esac
  echo "  mode=$mode sender_bin=$sender_bin channel_dist=$channel_dist capture_seconds=$capture_seconds"

  if [[ ! -f "$channel_dist" ]]; then
    echo "  Building channel dist (one-time)..."
    (cd "$REPO_ROOT/channel" && npm ci --silent && npm run build --silent) >/dev/null 2>&1 || {
      echo "  FAIL: channel dist build failed at $REPO_ROOT/channel"
      fail=$((fail + 1))
      return 0
    }
  fi
  if [[ ! -f "$channel_dist" ]]; then
    echo "  FAIL: channel dist still missing at $channel_dist after build"
    fail=$((fail + 1))
    return 0
  fi

  # Switch alice to her cross-team-cert team (main:partner.local). Her
  # identity remains in test.local so cert.member_address (partner.local/alice)
  # ≠ identity.address (test.local/alice) — the aako-pattern.
  run_success "alice switch partner" run_aw_in "$ALICE_DIR" id team switch main:partner.local
  local switch_exit=$?
  assert_eq "amy reproducer: alice switches to partner.local team" "0" "$switch_exit"

  local alice_active_team
  alice_active_team="$(yaml_field "$ALICE_DIR/.aw/teams.yaml" active_team)"
  assert_eq "amy reproducer: active_team is partner cross-team-cert" "main:partner.local" "$alice_active_team"

  # Ensure alice's identity.yaml has registry_url set (the bug-trigger
  # condition is: AWID_REGISTRY_URL env stripped + identity.yaml has
  # registry_url + cross-team-cert workspace). The registry_url field may
  # or may not have been written by `id create --registry`; ensure it is.
  if ! grep -q "^registry_url:" "$ALICE_DIR/.aw/identity.yaml" 2>/dev/null; then
    echo "registry_url: $AWID_URL" >> "$ALICE_DIR/.aw/identity.yaml"
    echo "  amy reproducer: appended registry_url=$AWID_URL to identity.yaml"
  fi

  # Spawn the channel-capture process subscribed to PARTNER_BOB's events.
  # When alice is on her partner.local team (the aako-pattern membership),
  # her "bob" alias resolves to the partner_bob identity, not the
  # devteam:test.local bob (whose cert was revoked in Phase 17).
  # PARTNER_BOB_DIR is the only valid receiver workspace at this point in
  # the script. The channel runs in that workspace and connects to the
  # test aweb server like a normal plugin would.
  # POSIX mktemp requires the X's at the END of the template (no extension
  # suffix). Use plain temp files; consumers (python parse) don't care about
  # the file extension.
  local capture_file
  capture_file="$(mktemp "${TMPDIR:-/tmp}/amy-channel-capture-jsonl.XXXXXX")"
  local capture_log
  capture_log="$(mktemp "${TMPDIR:-/tmp}/amy-channel-capture-log.XXXXXX")"
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 \
    bash -c 'cd "$1" && shift && exec "$@"' _ "$PARTNER_BOB_DIR" \
    node "$REPO_ROOT/scripts/lib/capture-channel-events.mjs" "$channel_dist" "$capture_seconds" \
    >"$capture_file" 2>"$capture_log" &
  local capture_pid=$!
  echo "  amy reproducer: spawned channel-capture pid=$capture_pid (file=$capture_file)"
  # Give the channel a moment to perform its handshake + initial fetch
  # before we send messages, otherwise the events race the subscription.
  sleep 5

  # Send mail and chat from alice (aako-pattern sender, AWID_REGISTRY_URL stripped)
  # to bob via the configured sender binary.
  local mail_subject="amy-symptom mail $(date +%s)"
  local mail_body="amy reproducer mail body"
  run_aw_bin_no_env_registry_in "$sender_bin" "$ALICE_DIR" mail send --plaintext \
    --to bob \
    --subject "$mail_subject" \
    --body "$mail_body" >/dev/null 2>&1
  local mail_exit=$?
  assert_eq "amy reproducer: mail send --plaintext exit" "0" "$mail_exit"

  run_aw_bin_no_env_registry_in "$sender_bin" "$ALICE_DIR" chat send-and-leave --plaintext bob \
    "amy reproducer chat" >/dev/null 2>&1
  local chat_exit=$?
  assert_eq "amy reproducer: chat send exit" "0" "$chat_exit"

  # Wait for the channel-capture to complete.
  wait "$capture_pid" 2>/dev/null || true

  # Server-side: verification_status from partner_bob's mail inbox + chat
  # history for messages from alice in this phase.
  local bob_inbox_json
  capture_success bob_inbox_json "bob_inbox_json" run_aw_in "$PARTNER_BOB_DIR" mail inbox --json --show-all
  local server_mail_vs
  server_mail_vs="$(echo "$bob_inbox_json" | python3 -c "
import sys, json
subject = sys.argv[1]
data = json.load(sys.stdin)
msgs = data.get('messages', [])
msg = next((m for m in msgs if m.get('subject') == subject), None)
print(msg.get('verification_status', '') if msg else '')
" "$mail_subject")"
  echo "  amy reproducer: server_mail_verification_status=$server_mail_vs"
  local server_mail_conversation_id
  server_mail_conversation_id="$(echo "$bob_inbox_json" | python3 -c "
import sys, json
subject = sys.argv[1]
data = json.load(sys.stdin)
msgs = data.get('messages', [])
msg = next((m for m in msgs if m.get('subject') == subject), None)
print(msg.get('conversation_id', '') if msg else '')
" "$mail_subject")"
  echo "  amy reproducer: server_mail_conversation_id=$server_mail_conversation_id"

  # `chat pending` returns conversation summaries without per-message
  # verification_status. Use `chat history alice` to pull the message-level
  # detail and find the chat we just sent.
  local bob_history_json
  capture_success bob_history_json "bob_history_json" run_aw_in "$PARTNER_BOB_DIR" chat history alice --json
  local server_chat_vs
  server_chat_vs="$(echo "$bob_history_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
messages = data.get('messages', [])
target = next((m for m in messages if m.get('body') == 'amy reproducer chat'), None)
print(target.get('verification_status', '') if target else '')
")"
  echo "  amy reproducer: server_chat_verification_status=$server_chat_vs"
  local server_chat_conversation_id
  server_chat_conversation_id="$(echo "$bob_history_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
messages = data.get('messages', [])
target = next((m for m in messages if m.get('body') == 'amy reproducer chat'), None)
print(target.get('conversation_id', '') if target else '')
")"
  echo "  amy reproducer: server_chat_conversation_id=$server_chat_conversation_id"

  # Channel-side: parse the capture file for mail and chat events; extract
  # meta.verified.
  local channel_mail_verified
  channel_mail_verified="$(python3 -c "
import sys, json
subject = sys.argv[1]
with open(sys.argv[2], 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            params = json.loads(line)
        except Exception:
            continue
        meta = params.get('meta', {}) or {}
        if meta.get('type') == 'mail' and meta.get('subject') == subject:
            print(meta.get('verified', ''))
            break
    else:
        print('')
" "$mail_subject" "$capture_file")"
  echo "  amy reproducer: channel_mail_verified=$channel_mail_verified"
  local channel_mail_conversation_id
  channel_mail_conversation_id="$(python3 -c "
import sys, json
subject = sys.argv[1]
with open(sys.argv[2], 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            params = json.loads(line)
        except Exception:
            continue
        meta = params.get('meta', {}) or {}
        if meta.get('type') == 'mail' and meta.get('subject') == subject:
            print(meta.get('conversation_id', ''))
            break
    else:
        print('')
" "$mail_subject" "$capture_file")"
  echo "  amy reproducer: channel_mail_conversation_id=$channel_mail_conversation_id"

  local channel_chat_verified
  channel_chat_verified="$(python3 -c "
import sys, json
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            params = json.loads(line)
        except Exception:
            continue
        meta = params.get('meta', {}) or {}
        if meta.get('type') == 'chat' and params.get('content') == 'amy reproducer chat':
            print(meta.get('verified', ''))
            break
    else:
        print('')
" "$capture_file")"
  echo "  amy reproducer: channel_chat_verified=$channel_chat_verified"
  local channel_chat_conversation_id
  channel_chat_conversation_id="$(python3 -c "
import sys, json
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            params = json.loads(line)
        except Exception:
            continue
        meta = params.get('meta', {}) or {}
        if meta.get('type') == 'chat' and params.get('content') == 'amy reproducer chat':
            print(meta.get('conversation_id', ''))
            break
    else:
        print('')
" "$capture_file")"
  echo "  amy reproducer: channel_chat_conversation_id=$channel_chat_conversation_id"

  # Mode-specific assertions.
  case "$mode" in
    baseline)
      # Canonical baseline gate-clear for aalg substance: pre-aalg sender
      # produces malformed envelope (to_did="" + no to_stable_id) → server
      # records identity_mismatch on BOTH transports. This is the bug-on-
      # pre-fix half of Randy's gate-clear-for-tag signal; the closure-on-
      # post-fix half lives in the INTERMEDIATE mode assertions.
      #
      # Channel rendering during BASELINE is captured but NOT asserted.
      # Reason: TOFU pin state from earlier e2e phases (alice was
      # successfully pinned at PARTNER_BOB during Phases 9-12d when her
      # mail verified) can upgrade subsequent verification regardless of
      # fresh server status. Channel observations are diagnostic only;
      # the reliable aalg-substance signal is server VS.
      #
      # Reproducing Amy's exact observed channel asymmetry (mail=false /
      # chat=true) requires a third-mode setup (post-aalg sender + npm
      # channel 1.3.2 — the pre-Pass-B published artifact). That is
      # outside this harness's scope; the aalg-bug-dominant BASELINE +
      # POST-fix INTERMEDIATE is sufficient for the v0.5.8 gate-clear
      # per Randy's collapsed framing (his ab0105ad).
      assert_eq "amy reproducer baseline: server mail vs=identity_mismatch (aalg-bug reproduced)" "identity_mismatch" "$server_mail_vs"
      assert_eq "amy reproducer baseline: server chat vs=identity_mismatch (aalg-bug reproduced)" "identity_mismatch" "$server_chat_vs"
      echo "  amy reproducer baseline: channel rendering captured (informational; pin-state from earlier phases can upgrade): mail=$channel_mail_verified chat=$channel_chat_verified"
      ;;
    intermediate)
      # Current main (post-aalg + post-Pass-B-recipient-binding-conformance).
      # Pass B's recipient-binding TS port closed the renderer-asymmetry
      # user-symptom — channel mail-event header now also renders verified=true,
      # not just chat-event. The original v0.5.8/v0.5.9 split (which expected
      # mail=false here) was wrong; collapsed per Randy ab0105ad.
      assert_eq "amy reproducer intermediate: server mail vs=verified (aalg fix)" "verified" "$server_mail_vs"
      assert_eq "amy reproducer intermediate: server chat vs=verified (aalg fix)" "verified" "$server_chat_vs"
      assert_eq "amy reproducer intermediate: channel mail header verified=true (Pass B closes renderer asymmetry)" "true" "$channel_mail_verified"
      assert_eq "amy reproducer intermediate: channel chat header verified=true" "true" "$channel_chat_verified"
      assert_not_empty "amy reproducer intermediate: server mail conversation_id present" "$server_mail_conversation_id"
      assert_eq "amy reproducer intermediate: channel mail conversation_id matches SSE payload" "$server_mail_conversation_id" "$channel_mail_conversation_id"
      assert_not_empty "amy reproducer intermediate: server chat conversation_id present" "$server_chat_conversation_id"
      assert_eq "amy reproducer intermediate: channel chat conversation_id matches SSE payload" "$server_chat_conversation_id" "$channel_chat_conversation_id"
      ;;
    post)
      assert_eq "amy reproducer post: server mail vs=verified" "verified" "$server_mail_vs"
      assert_eq "amy reproducer post: server chat vs=verified" "verified" "$server_chat_vs"
      assert_eq "amy reproducer post: channel mail header verified=true (asymmetry fixed)" "true" "$channel_mail_verified"
      assert_eq "amy reproducer post: channel chat header verified=true" "true" "$channel_chat_verified"
      assert_not_empty "amy reproducer post: server mail conversation_id present" "$server_mail_conversation_id"
      assert_eq "amy reproducer post: channel mail conversation_id matches SSE payload" "$server_mail_conversation_id" "$channel_mail_conversation_id"
      assert_not_empty "amy reproducer post: server chat conversation_id present" "$server_chat_conversation_id"
      assert_eq "amy reproducer post: channel chat conversation_id matches SSE payload" "$server_chat_conversation_id" "$channel_chat_conversation_id"
      ;;
  esac

  # Restore alice's primary team for any subsequent phases.
  run_success "alice switch devteam" run_aw_in "$ALICE_DIR" id team switch devteam:test.local || true

  echo "  amy reproducer: capture file preserved at $capture_file (log: $capture_log)"
  echo ""
}

if [[ -n "${AMY_REPRODUCER_RUN:-}" ]]; then
  phase_amy_symptom_reproducer
fi

echo "=== Done ==="
