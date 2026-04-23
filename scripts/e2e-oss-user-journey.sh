#!/usr/bin/env bash
#
# End-to-end OSS user journey test — team architecture.
#
# Simulates a new user who:
#   1. Starts awid + aweb in Docker
#   2. Creates a persistent identity (alice)
#   3. Registers a namespace, creates a team, invites bob
#   4. Both agents connect to aweb via certificate auth
#   5. Exercises mail, chat, tasks, locks
#   6. Revokes bob's membership and verifies rejection
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
CAROL_DIR="$E2E_CWD/carol"
DAVE_DIR="$E2E_CWD/dave"
GSK_DIR="$E2E_CWD/gsk"
PARTNER_CONTROLLER_DIR="$E2E_CWD/partner-controller"
PARTNER_BOB_DIR="$E2E_CWD/partner-bob"
RECONNECT_DIR="$E2E_CWD/reconnect-alice"
WIZARD_BYOD_DIR="$E2E_CWD/wizard-byod"
mkdir -p "$ALICE_DIR" "$BOB_DIR" "$CAROL_DIR" "$DAVE_DIR" "$GSK_DIR" "$PARTNER_CONTROLLER_DIR" "$PARTNER_BOB_DIR" "$RECONNECT_DIR" "$WIZARD_BYOD_DIR"
ALICE_DIR="$(canonicalize_dir "$ALICE_DIR")"
BOB_DIR="$(canonicalize_dir "$BOB_DIR")"
CAROL_DIR="$(canonicalize_dir "$CAROL_DIR")"
DAVE_DIR="$(canonicalize_dir "$DAVE_DIR")"
GSK_DIR="$(canonicalize_dir "$GSK_DIR")"
PARTNER_CONTROLLER_DIR="$(canonicalize_dir "$PARTNER_CONTROLLER_DIR")"
PARTNER_BOB_DIR="$(canonicalize_dir "$PARTNER_BOB_DIR")"
RECONNECT_DIR="$(canonicalize_dir "$RECONNECT_DIR")"
WIZARD_BYOD_DIR="$(canonicalize_dir "$WIZARD_BYOD_DIR")"

pass=0
fail=0

cleanup() {
  echo ""
  echo "--- Cleanup ---"
  if [[ -f "$SERVER_DIR/.env.e2e" ]]; then
    cd "$SERVER_DIR" && docker compose --env-file .env.e2e down -v 2>/dev/null || true
    rm -f "$SERVER_DIR/.env.e2e"
  fi
  rm -rf "$E2E_HOME" "$E2E_CWD"
  echo ""
  if [[ $fail -gt 0 ]]; then
    echo "FAILED: $fail failures, $pass passed"
    exit 1
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
  if echo "$haystack" | grep -q "$needle"; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected to contain '$needle', got: ${haystack:0:120})"
    fail=$((fail + 1))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -q "$needle"; then
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
run_aw_in() {
  local workdir="$1"
  shift
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$CLI_DIR/aw" "$@"
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

set_messaging_policy() {
  local did_aw="$1" policy="$2"
  (
    cd "$SERVER_DIR"
    docker compose --env-file .env.e2e exec -T postgres \
      psql -U "${POSTGRES_USER:-aweb}" -d "${POSTGRES_DB:-aweb}" \
      -c "UPDATE aweb.agents SET messaging_policy = '${policy}' WHERE did_aw = '${did_aw}';" >/dev/null
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
AWEB_LOG_JSON=true
AWID_LOG_JSON=true
AWID_RATE_LIMIT_BACKEND=redis
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
# Phase 2: Create alice's identity
# ---------------------------------------------------------------------------
echo "=== Phase 2: Create alice's identity ==="

create_out="$(run_aw_in "$ALICE_DIR" id create \
  --name alice \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"

ALICE_DID_KEY="$(echo "$create_out" | jq_field did_key)"
ALICE_DID_AW="$(echo "$create_out" | jq_field did_aw)"
ALICE_ADDRESS="$(echo "$create_out" | jq_field address)"

assert_not_empty "alice did_key" "$ALICE_DID_KEY"
assert_not_empty "alice did_aw" "$ALICE_DID_AW"
assert_eq "alice address" "test.local/alice" "$ALICE_ADDRESS"
echo ""

# ---------------------------------------------------------------------------
# Phase 3: Create team
# ---------------------------------------------------------------------------
echo "=== Phase 3: Create team under test.local ==="

team_out="$(run_aw_in "$ALICE_DIR" id team create \
  --name devteam \
  --namespace test.local \
  --registry "$AWID_URL" \
  --json 2>/dev/null)"

TEAM_ID="$(echo "$team_out" | jq_field team_id)"
TEAM_DID_KEY="$(echo "$team_out" | jq_field team_did_key)"

assert_eq "team id" "devteam:test.local" "$TEAM_ID"
assert_not_empty "team did_key" "$TEAM_DID_KEY"
echo ""

# ---------------------------------------------------------------------------
# Phase 4: Alice joins the team via invite/accept
# ---------------------------------------------------------------------------
echo "=== Phase 4: Alice joins team ==="

alice_invite_out="$(run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --json 2>/dev/null)"

ALICE_INVITE_TOKEN="$(echo "$alice_invite_out" | jq_field token)"
assert_not_empty "alice invite token" "$ALICE_INVITE_TOKEN"

alice_accept_out="$(run_aw_in "$ALICE_DIR" id team accept-invite "$ALICE_INVITE_TOKEN" \
  --alias alice \
  --json 2>/dev/null)"

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

cert_out="$(run_aw_in "$ALICE_DIR" id cert show --json 2>/dev/null)"
CERT_TEAM="$(echo "$cert_out" | jq_field team_id)"
CERT_ALIAS="$(echo "$cert_out" | jq_field alias)"

assert_eq "cert team" "devteam:test.local" "$CERT_TEAM"
assert_eq "cert alias" "alice" "$CERT_ALIAS"
echo ""

# ---------------------------------------------------------------------------
# Phase 6: Alice connects to aweb
# ---------------------------------------------------------------------------
echo "=== Phase 6: Alice connects to aweb (POST /v1/connect) ==="

run_aw_in "$ALICE_DIR" init --url "$AWEB_URL" 2>/dev/null
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

whoami_out="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
whoami_alias="$(echo "$whoami_out" | jq_field alias)"
assert_eq "whoami alias" "alice" "$whoami_alias"
echo ""

# ---------------------------------------------------------------------------
# Phase 8: workspace status
# ---------------------------------------------------------------------------
echo "=== Phase 8: Workspace status ==="

ws_out="$(run_aw_in "$ALICE_DIR" workspace status 2>/dev/null)"
ws_exit=$?
assert_eq "workspace status exit" "0" "$ws_exit"
assert_contains "workspace status shows alice" "$ws_out" "alice"
echo ""

# ---------------------------------------------------------------------------
# Phase 9: Create bob and join team via invite
# ---------------------------------------------------------------------------
echo "=== Phase 9: Create bob and join team ==="

bob_create="$(run_aw_in "$BOB_DIR" id create \
  --name bob \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"

BOB_DID_KEY="$(echo "$bob_create" | jq_field did_key)"
assert_not_empty "bob did_key" "$BOB_DID_KEY"

# Alice creates invite for bob
bob_invite_out="$(run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --json 2>/dev/null)"

BOB_INVITE_TOKEN="$(echo "$bob_invite_out" | jq_field token)"
assert_not_empty "bob invite token" "$BOB_INVITE_TOKEN"

# Bob accepts the invite (cert saved under $BOB_DIR/.aw/team-certs/)
bob_accept="$(run_aw_in "$BOB_DIR" id team accept-invite "$BOB_INVITE_TOKEN" \
  --alias bob \
  --json 2>/dev/null)"

BOB_ACCEPT_STATUS="$(echo "$bob_accept" | jq_field status)"
assert_eq "bob accepted" "accepted" "$BOB_ACCEPT_STATUS"

# Bob connects to aweb
run_aw_in "$BOB_DIR" init --url "$AWEB_URL" 2>/dev/null
bob_init_exit=$?
assert_eq "bob init exit" "0" "$bob_init_exit"
echo ""

# ---------------------------------------------------------------------------
# Phase 10: Alice sends mail to bob
# ---------------------------------------------------------------------------
echo "=== Phase 10: Alice sends mail to bob ==="

run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "E2E test" \
  --body "Hello from alice" 2>/dev/null
mail_send_exit=$?
assert_eq "mail send exit" "0" "$mail_send_exit"
echo ""

# ---------------------------------------------------------------------------
# Phase 11: Bob reads inbox
# ---------------------------------------------------------------------------
echo "=== Phase 11: Bob reads inbox ==="

bob_inbox="$(run_aw_in "$BOB_DIR" mail inbox --json 2>/dev/null)"
bob_msg_count="$(echo "$bob_inbox" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('messages',[])))" 2>/dev/null || echo "0")"
bob_msg_body="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('body','') if msgs else '')" 2>/dev/null || echo "")"

assert_eq "bob has 1 message" "1" "$bob_msg_count"
assert_eq "message body" "Hello from alice" "$bob_msg_body"
echo ""

# ---------------------------------------------------------------------------
# Phase 11b: Cross-identity messaging via contacts
# ---------------------------------------------------------------------------
echo "=== Phase 11b: Cross-identity messaging via contacts ==="

carol_create="$(run_aw_in "$CAROL_DIR" id create \
  --name carol \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"
CAROL_DID_AW="$(echo "$carol_create" | jq_field did_aw)"
assert_not_empty "carol did_aw" "$CAROL_DID_AW"

run_aw_in "$ALICE_DIR" id team create \
  --name ops \
  --namespace test.local \
  --registry "$AWID_URL" \
  --json 2>/dev/null >/dev/null
ops_invite_out="$(run_aw_in "$ALICE_DIR" id team invite \
  --team ops \
  --namespace test.local \
  --json 2>/dev/null)"
OPS_INVITE_TOKEN="$(echo "$ops_invite_out" | jq_field token)"
assert_not_empty "ops invite token" "$OPS_INVITE_TOKEN"

carol_accept="$(run_aw_in "$CAROL_DIR" id team accept-invite "$OPS_INVITE_TOKEN" \
  --alias carol \
  --json 2>/dev/null)"
CAROL_ACCEPT_STATUS="$(echo "$carol_accept" | jq_field status)"
assert_eq "carol accepted" "accepted" "$CAROL_ACCEPT_STATUS"

run_aw_in "$CAROL_DIR" init --url "$AWEB_URL" >/dev/null 2>&1
carol_init_exit=$?
assert_eq "carol init exit" "0" "$carol_init_exit"

dave_create="$(run_aw_in "$DAVE_DIR" id create \
  --name dave \
  --domain test.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"
DAVE_DID_KEY="$(echo "$dave_create" | jq_field did_key)"
assert_not_empty "dave did_key" "$DAVE_DID_KEY"

dave_invite_out="$(run_aw_in "$ALICE_DIR" id team invite \
  --team ops \
  --namespace test.local \
  --json 2>/dev/null)"
DAVE_INVITE_TOKEN="$(echo "$dave_invite_out" | jq_field token)"
assert_not_empty "dave ops invite token" "$DAVE_INVITE_TOKEN"

dave_accept="$(run_aw_in "$DAVE_DIR" id team accept-invite "$DAVE_INVITE_TOKEN" \
  --alias dave \
  --json 2>/dev/null)"
DAVE_ACCEPT_STATUS="$(echo "$dave_accept" | jq_field status)"
assert_eq "dave accepted to ops" "accepted" "$DAVE_ACCEPT_STATUS"

run_aw_in "$DAVE_DIR" init --url "$AWEB_URL" >/dev/null 2>&1
dave_init_exit=$?
assert_eq "dave init exit" "0" "$dave_init_exit"

set_messaging_policy "$ALICE_DID_AW" "contacts"
run_aw_in "$ALICE_DIR" contacts add "test.local/bob" --label "Bob" >/dev/null 2>&1
contacts_add_exit=$?
assert_eq "alice adds bob to contacts" "0" "$contacts_add_exit"

run_aw_in "$BOB_DIR" mail send \
  --to-did "$ALICE_DID_AW" \
  --body "Direct hello from bob" >/dev/null 2>&1
bob_direct_exit=$?
assert_eq "bob direct mail to alice did" "0" "$bob_direct_exit"

alice_contacts_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json 2>/dev/null)"
alice_bob_message="$(echo "$alice_contacts_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Direct hello from bob'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives bob direct message" "Direct hello from bob" "$alice_bob_message"

if carol_direct_out="$(run_aw_in "$CAROL_DIR" mail send \
  --to-did "$ALICE_DID_AW" \
  --body 'Blocked hello from carol' 2>&1)"; then
  carol_direct_exit=0
else
  carol_direct_exit=$?
fi
if [[ "$carol_direct_exit" != "0" ]] && echo "$carol_direct_out" | grep -qi "contacts\|403\|forbidden"; then
  echo "  PASS: carol blocked by alice contacts policy"
  pass=$((pass + 1))
else
  echo "  FAIL: carol should be blocked by alice contacts policy (exit=$carol_direct_exit output=${carol_direct_out:0:160})"
  fail=$((fail + 1))
fi

set_messaging_policy "$ALICE_DID_AW" "everyone"
run_aw_in "$CAROL_DIR" mail send \
  --to-did "$ALICE_DID_AW" \
  --body "Direct hello from carol" >/dev/null 2>&1
carol_retry_exit=$?
assert_eq "carol direct mail succeeds after policy change" "0" "$carol_retry_exit"

alice_all_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>/dev/null)"
alice_carol_message="$(echo "$alice_all_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Direct hello from carol'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives carol direct message" "Direct hello from carol" "$alice_carol_message"
echo ""

# ---------------------------------------------------------------------------
# Phase 12: Chat round-trip
# ---------------------------------------------------------------------------
echo "=== Phase 12: Chat ==="

run_aw_in "$ALICE_DIR" chat send-and-wait bob \
  "E2E chat from alice" --start-conversation --wait 3 2>/dev/null
chat_send_exit=$?
assert_eq "alice→bob chat send exit" "0" "$chat_send_exit"

bob_pending="$(run_aw_in "$BOB_DIR" chat pending 2>/dev/null)"
assert_contains "bob sees pending from alice" "$bob_pending" "alice"

run_aw_in "$BOB_DIR" chat send-and-leave alice \
  "Chat reply from bob" 2>/dev/null
chat_reply_exit=$?
assert_eq "bob→alice chat reply exit" "0" "$chat_reply_exit"

alice_history="$(run_aw_in "$ALICE_DIR" chat history bob 2>/dev/null)"
assert_contains "alice sees bob's reply" "$alice_history" "Chat reply from bob"
echo ""

# ---------------------------------------------------------------------------
# Phase 12b: Cross-team tilde addressing
# ---------------------------------------------------------------------------
echo "=== Phase 12b: Cross-team tilde addressing ==="

if tilde_mail_out="$(run_aw_in "$DAVE_DIR" mail send \
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

alice_tilde_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>/dev/null)"
alice_dave_message="$(echo "$alice_tilde_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')=='Cross-team hello from dave'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives dave cross-team mail" "Cross-team hello from dave" "$alice_dave_message"

if tilde_chat_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave ops~dave \
  "Cross-team chat from alice" 2>&1)"; then
  tilde_chat_exit=0
else
  tilde_chat_exit=$?
fi
assert_eq "alice→ops~dave chat exit" "0" "$tilde_chat_exit"
if [[ "$tilde_chat_exit" != "0" ]]; then
  echo "  tilde chat output: ${tilde_chat_out:0:240}"
fi

dave_pending="$(run_aw_in "$DAVE_DIR" chat pending 2>/dev/null)"
assert_contains "dave sees cross-team chat from alice" "$dave_pending" "alice"
echo ""

# ---------------------------------------------------------------------------
# Phase 12c: Ephemeral server-local addresses
# ---------------------------------------------------------------------------
echo "=== Phase 12c: Ephemeral server-local addresses ==="

gsk_invite_out="$(run_aw_in "$ALICE_DIR" id team invite \
  --team devteam \
  --namespace test.local \
  --ephemeral \
  --json 2>/dev/null)"
GSK_INVITE_TOKEN="$(echo "$gsk_invite_out" | jq_field token)"
assert_not_empty "gsk ephemeral invite token" "$GSK_INVITE_TOKEN"

gsk_accept="$(run_aw_in "$GSK_DIR" id team accept-invite "$GSK_INVITE_TOKEN" \
  --alias gsk \
  --json 2>/dev/null)"
GSK_ACCEPT_STATUS="$(echo "$gsk_accept" | jq_field status)"
assert_eq "gsk accepted ephemeral invite" "accepted" "$GSK_ACCEPT_STATUS"

run_aw_in "$GSK_DIR" init --url "$AWEB_URL" >/dev/null 2>&1
gsk_init_exit=$?
assert_eq "gsk init exit" "0" "$gsk_init_exit"
if [[ ! -f "$GSK_DIR/.aw/identity.yaml" ]]; then
  echo "  PASS: gsk has no identity.yaml"
  pass=$((pass + 1))
else
  echo "  FAIL: gsk ephemeral agent should not have identity.yaml"
  fail=$((fail + 1))
fi

run_aw_in "$GSK_DIR" mail send \
  --to alice \
  --subject "Ephemeral sender address" \
  --body "Ephemeral hello from gsk" >/dev/null 2>&1
gsk_mail_exit=$?
assert_eq "gsk→alice mail exit" "0" "$gsk_mail_exit"

alice_ephemeral_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>/dev/null)"
alice_gsk_from_address="$(echo "$alice_ephemeral_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Ephemeral sender address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees gsk server-local mail address" "test.local/gsk" "$alice_gsk_from_address"

run_aw_in "$GSK_DIR" mail send \
  --to-address test.local/alice \
  --subject "Ephemeral identity-auth sender address" \
  --body "Identity-auth hello from gsk" >/dev/null 2>&1
gsk_identity_mail_exit=$?
assert_eq "gsk→test.local/alice identity-auth mail exit" "0" "$gsk_identity_mail_exit"

alice_identity_mail_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>/dev/null)"
alice_gsk_identity_from_address="$(echo "$alice_identity_mail_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Ephemeral identity-auth sender address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice sees gsk identity-auth mail address" "test.local/gsk" "$alice_gsk_identity_from_address"

if alice_gsk_reply_out="$(run_aw_in "$ALICE_DIR" mail send \
  --to-address test.local/gsk \
  --subject "Reply to ephemeral address" \
  --body "Reply to gsk by local address" 2>&1)"; then
  alice_gsk_reply_exit=0
else
  alice_gsk_reply_exit=$?
fi
assert_eq "alice→test.local/gsk mail exit" "0" "$alice_gsk_reply_exit"
if [[ "$alice_gsk_reply_exit" != "0" ]]; then
  echo "  alice→gsk mail output: ${alice_gsk_reply_out:0:240}"
fi

gsk_inbox="$(run_aw_in "$GSK_DIR" mail inbox --json --show-all 2>/dev/null)"
gsk_reply_body="$(echo "$gsk_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('subject')=='Reply to ephemeral address'), ''))" 2>/dev/null || echo "")"
assert_eq "gsk receives address-routed mail reply" "Reply to gsk by local address" "$gsk_reply_body"

if gsk_chat_out="$(run_aw_in "$GSK_DIR" chat send-and-leave alice \
  "Ephemeral chat from gsk" 2>&1)"; then
  gsk_chat_exit=0
else
  gsk_chat_exit=$?
fi
assert_eq "gsk→alice chat exit" "0" "$gsk_chat_exit"
if [[ "$gsk_chat_exit" != "0" ]]; then
  echo "  gsk chat output: ${gsk_chat_out:0:240}"
fi

alice_gsk_pending="$(run_aw_in "$ALICE_DIR" chat pending 2>/dev/null)"
assert_contains "alice sees gsk server-local chat address" "$alice_gsk_pending" "test.local/gsk"

if alice_gsk_chat_reply_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave test.local/gsk \
  "Reply to ephemeral chat address" 2>&1)"; then
  alice_gsk_chat_reply_exit=0
else
  alice_gsk_chat_reply_exit=$?
fi
assert_eq "alice→test.local/gsk chat exit" "0" "$alice_gsk_chat_reply_exit"
if [[ "$alice_gsk_chat_reply_exit" != "0" ]]; then
  echo "  alice→gsk chat output: ${alice_gsk_chat_reply_out:0:240}"
fi

gsk_chat_history="$(run_aw_in "$GSK_DIR" chat history alice 2>/dev/null)"
assert_contains "gsk receives address-routed chat reply" "$gsk_chat_history" "Reply to ephemeral chat address"
echo ""

# ---------------------------------------------------------------------------
# Phase 12d: Per-membership addresses
# ---------------------------------------------------------------------------
echo "=== Phase 12d: Per-membership addresses ==="

partner_controller_create="$(run_aw_in "$PARTNER_CONTROLLER_DIR" id create \
  --name controller \
  --domain partner.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"
PARTNER_CONTROLLER_DID="$(echo "$partner_controller_create" | jq_field did_key)"
assert_not_empty "partner namespace controller did_key" "$PARTNER_CONTROLLER_DID"

partner_address_out="$(run_aw_in "$PARTNER_CONTROLLER_DIR" id namespace assign-address \
  --domain partner.local \
  --name alice \
  --did-aw "$ALICE_DID_AW" \
  --json 2>/dev/null)"
PARTNER_ALICE_ADDRESS="$(echo "$partner_address_out" | jq_field address)"
assert_eq "partner address assigned to alice" "partner.local/alice" "$PARTNER_ALICE_ADDRESS"

partner_team_out="$(run_aw_in "$PARTNER_CONTROLLER_DIR" id team create \
  --name main \
  --namespace partner.local \
  --registry "$AWID_URL" \
  --json 2>/dev/null)"
PARTNER_TEAM_ID="$(echo "$partner_team_out" | jq_field team_id)"
assert_eq "partner team id" "main:partner.local" "$PARTNER_TEAM_ID"

partner_bob_create="$(run_aw_in "$PARTNER_BOB_DIR" id create \
  --name bob \
  --domain partner.local \
  --registry "$AWID_URL" \
  --skip-dns-verify \
  --json 2>/dev/null)"
PARTNER_BOB_ADDRESS="$(echo "$partner_bob_create" | jq_field address)"
assert_eq "partner bob address" "partner.local/bob" "$PARTNER_BOB_ADDRESS"

partner_bob_invite_out="$(run_aw_in "$PARTNER_CONTROLLER_DIR" id team invite \
  --team main \
  --namespace partner.local \
  --json 2>/dev/null)"
PARTNER_BOB_INVITE_TOKEN="$(echo "$partner_bob_invite_out" | jq_field token)"
assert_not_empty "partner bob invite token" "$PARTNER_BOB_INVITE_TOKEN"

partner_bob_accept="$(run_aw_in "$PARTNER_BOB_DIR" id team accept-invite "$PARTNER_BOB_INVITE_TOKEN" \
  --alias bob \
  --json 2>/dev/null)"
PARTNER_BOB_ACCEPT_STATUS="$(echo "$partner_bob_accept" | jq_field status)"
assert_eq "partner bob accepted" "accepted" "$PARTNER_BOB_ACCEPT_STATUS"

run_aw_in "$PARTNER_BOB_DIR" init --url "$AWEB_URL" >/dev/null 2>&1
partner_bob_init_exit=$?
assert_eq "partner bob init exit" "0" "$partner_bob_init_exit"

partner_alice_invite_out="$(run_aw_in "$PARTNER_CONTROLLER_DIR" id team invite \
  --team main \
  --namespace partner.local \
  --json 2>/dev/null)"
PARTNER_ALICE_INVITE_TOKEN="$(echo "$partner_alice_invite_out" | jq_field token)"
assert_not_empty "partner alice invite token" "$PARTNER_ALICE_INVITE_TOKEN"

partner_alice_accept="$(run_aw_in "$ALICE_DIR" id team accept-invite "$PARTNER_ALICE_INVITE_TOKEN" \
  --alias alice \
  --address partner.local/alice \
  --json 2>/dev/null)"
PARTNER_ALICE_ACCEPT_STATUS="$(echo "$partner_alice_accept" | jq_field status)"
assert_eq "alice accepted partner team with address" "accepted" "$PARTNER_ALICE_ACCEPT_STATUS"

partner_alice_cert_out="$(run_aw_in "$ALICE_DIR" id cert show --json 2>/dev/null)"
partner_alice_cert_team="$(echo "$partner_alice_cert_out" | jq_field team_id)"
partner_alice_cert_address="$(echo "$partner_alice_cert_out" | jq_field member_address)"
assert_eq "alice partner cert team" "main:partner.local" "$partner_alice_cert_team"
assert_eq "alice partner cert member_address" "partner.local/alice" "$partner_alice_cert_address"

run_aw_in "$ALICE_DIR" id team switch devteam:test.local >/dev/null 2>&1
alice_switch_primary_exit=$?
assert_eq "alice switches to primary team without re-init" "0" "$alice_switch_primary_exit"

alice_primary_whoami="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
alice_primary_whoami_domain="$(echo "$alice_primary_whoami" | jq_field domain)"
alice_primary_whoami_address="$(echo "$alice_primary_whoami" | jq_field address)"
assert_eq "alice primary whoami domain after switch" "test.local" "$alice_primary_whoami_domain"
assert_eq "alice primary whoami address after switch" "test.local/alice" "$alice_primary_whoami_address"

alice_primary_cert_out="$(run_aw_in "$ALICE_DIR" id cert show --json 2>/dev/null)"
alice_primary_cert_address="$(echo "$alice_primary_cert_out" | jq_field member_address)"
assert_eq "alice primary cert member_address" "test.local/alice" "$alice_primary_cert_address"

run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "Per-membership primary" \
  --body "Primary address hello" >/dev/null 2>&1
alice_primary_mail_exit=$?
assert_eq "alice primary-team mail exit" "0" "$alice_primary_mail_exit"

bob_per_membership_inbox="$(run_aw_in "$BOB_DIR" mail inbox --json --show-all 2>/dev/null)"
bob_primary_from_address="$(echo "$bob_per_membership_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership primary'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice primary from_address" "test.local/alice" "$bob_primary_from_address"

run_aw_in "$ALICE_DIR" chat send-and-leave bob \
  "Per-membership primary chat" >/dev/null 2>&1
alice_primary_chat_exit=$?
assert_eq "alice primary-team chat exit" "0" "$alice_primary_chat_exit"

bob_primary_pending="$(run_aw_in "$BOB_DIR" chat pending --json 2>/dev/null)"
bob_primary_chat_from_address="$(echo "$bob_primary_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership primary chat'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice primary chat from_address" "test.local/alice" "$bob_primary_chat_from_address"

if bob_primary_reply_out="$(run_aw_in "$BOB_DIR" mail send \
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

alice_primary_reply_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>/dev/null)"
alice_primary_reply_body="$(echo "$alice_primary_reply_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('subject')=='Reply primary address'), ''))" 2>/dev/null || echo "")"
assert_eq "alice receives primary address reply" "Reply to alice primary address" "$alice_primary_reply_body"

run_aw_in "$ALICE_DIR" id team switch main:partner.local >/dev/null 2>&1
alice_partner_setup_switch_exit=$?
assert_eq "alice switches to partner team for initial connect" "0" "$alice_partner_setup_switch_exit"
run_aw_in "$ALICE_DIR" init --url "$AWEB_URL" >/dev/null 2>&1
alice_partner_initial_connect_exit=$?
assert_eq "alice initially connects partner team" "0" "$alice_partner_initial_connect_exit"
run_aw_in "$ALICE_DIR" id team switch devteam:test.local >/dev/null 2>&1
alice_primary_setup_restore_exit=$?
assert_eq "alice returns to primary after partner setup" "0" "$alice_primary_setup_restore_exit"

run_aw_in "$ALICE_DIR" id team switch main:partner.local >/dev/null 2>&1
alice_switch_partner_exit=$?
assert_eq "alice switches to partner team without re-init" "0" "$alice_switch_partner_exit"

alice_partner_whoami="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
alice_partner_whoami_domain="$(echo "$alice_partner_whoami" | jq_field domain)"
alice_partner_whoami_address="$(echo "$alice_partner_whoami" | jq_field address)"
assert_eq "alice partner whoami domain after switch" "partner.local" "$alice_partner_whoami_domain"
assert_eq "alice partner whoami address after switch" "partner.local/alice" "$alice_partner_whoami_address"

run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "Per-membership partner" \
  --body "Partner address hello" >/dev/null 2>&1
alice_partner_mail_exit=$?
assert_eq "alice partner-team mail exit" "0" "$alice_partner_mail_exit"

partner_bob_inbox="$(run_aw_in "$PARTNER_BOB_DIR" mail inbox --json --show-all 2>/dev/null)"
partner_bob_from_address="$(echo "$partner_bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership partner'), ''))" 2>/dev/null || echo "")"
assert_eq "partner bob sees alice partner from_address" "partner.local/alice" "$partner_bob_from_address"

run_aw_in "$ALICE_DIR" chat send-and-leave bob \
  "Per-membership partner chat" >/dev/null 2>&1
alice_partner_chat_exit=$?
assert_eq "alice partner-team chat exit" "0" "$alice_partner_chat_exit"

partner_bob_pending="$(run_aw_in "$PARTNER_BOB_DIR" chat pending --json 2>/dev/null)"
partner_bob_chat_from_address="$(echo "$partner_bob_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership partner chat'), ''))" 2>/dev/null || echo "")"
assert_eq "partner bob sees alice partner chat from_address" "partner.local/alice" "$partner_bob_chat_from_address"

if partner_bob_reply_out="$(run_aw_in "$PARTNER_BOB_DIR" mail send \
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

run_aw_in "$ALICE_DIR" id team switch devteam:test.local >/dev/null 2>&1
alice_restore_primary_exit=$?
assert_eq "alice restores primary team without re-init" "0" "$alice_restore_primary_exit"

alice_restored_whoami="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
alice_restored_whoami_domain="$(echo "$alice_restored_whoami" | jq_field domain)"
alice_restored_whoami_address="$(echo "$alice_restored_whoami" | jq_field address)"
assert_eq "alice restored whoami domain after switch" "test.local" "$alice_restored_whoami_domain"
assert_eq "alice restored whoami address after switch" "test.local/alice" "$alice_restored_whoami_address"

run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "Per-membership restored primary" \
  --body "Restored primary address hello" >/dev/null 2>&1
alice_restored_mail_exit=$?
assert_eq "alice restored primary-team mail exit" "0" "$alice_restored_mail_exit"

bob_restored_inbox="$(run_aw_in "$BOB_DIR" mail inbox --json --show-all 2>/dev/null)"
bob_restored_from_address="$(echo "$bob_restored_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('from_address','') for m in msgs if m.get('subject')=='Per-membership restored primary'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice restored primary from_address" "test.local/alice" "$bob_restored_from_address"

run_aw_in "$ALICE_DIR" chat send-and-leave bob \
  "Per-membership restored primary chat" >/dev/null 2>&1
alice_restored_chat_exit=$?
assert_eq "alice restored primary-team chat exit" "0" "$alice_restored_chat_exit"

bob_restored_pending="$(run_aw_in "$BOB_DIR" chat pending --json 2>/dev/null)"
bob_restored_chat_from_address="$(echo "$bob_restored_pending" | python3 -c "import sys,json; pending=json.load(sys.stdin).get('pending',[]); print(next((p.get('last_from_address','') for p in pending if p.get('last_message')=='Per-membership restored primary chat'), ''))" 2>/dev/null || echo "")"
assert_eq "bob sees alice restored primary chat from_address" "test.local/alice" "$bob_restored_chat_from_address"
echo ""

# ---------------------------------------------------------------------------
# Phase 13: Tasks
# ---------------------------------------------------------------------------
echo "=== Phase 13: Tasks ==="

task_create_out="$(run_aw_in "$ALICE_DIR" task create \
  --title "E2E test task" --json 2>/dev/null)"
TASK_REF="$(echo "$task_create_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('task_ref') or d.get('task_id',''))" 2>/dev/null || echo "")"
assert_not_empty "task created" "$TASK_REF"

task_list_out="$(run_aw_in "$ALICE_DIR" task list 2>/dev/null)"
assert_contains "task list shows our task" "$task_list_out" "E2E test task"
echo ""

# ---------------------------------------------------------------------------
# Phase 14: Locks
# ---------------------------------------------------------------------------
echo "=== Phase 14: Locks ==="

run_aw_in "$ALICE_DIR" lock acquire --resource-key test-file 2>/dev/null
lock_exit=$?
assert_eq "lock acquire exit" "0" "$lock_exit"

lock_list="$(run_aw_in "$ALICE_DIR" lock list 2>/dev/null)"
assert_contains "lock list shows test-file" "$lock_list" "test-file"

run_aw_in "$ALICE_DIR" lock release --resource-key test-file 2>/dev/null
pass=$((pass + 1))
echo "  PASS: lock released"
echo ""

# ---------------------------------------------------------------------------
# Phase 15: Roles
# ---------------------------------------------------------------------------
echo "=== Phase 15: Roles ==="

roles_out="$(run_aw_in "$ALICE_DIR" roles show 2>/dev/null)"
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
assert_eq "3 active certificates" "3" "$cert_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 17: Revoke bob's membership
# ---------------------------------------------------------------------------
echo "=== Phase 17: Revoke bob's membership ==="

revoke_out="$(run_aw_in "$ALICE_DIR" id team remove-member \
  --team devteam \
  --namespace test.local \
  --member test.local/bob \
  --json 2>/dev/null)"

REVOKE_STATUS="$(echo "$revoke_out" | jq_field status)"
assert_eq "bob revoked" "removed" "$REVOKE_STATUS"
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
assert_eq "2 active certificates (alice and gsk)" "2" "$active_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 19: Alice still works after bob's revocation
# ---------------------------------------------------------------------------
echo "=== Phase 19: Alice still works ==="

alice_whoami="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
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

if bob_mail_out="$(run_aw_in "$BOB_DIR" mail send \
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

  reconnect_out="$(run_aw_in "$RECONNECT_DIR" init --url "$AWEB_URL" </dev/null 2>&1)"
  reconnect_exit=$?
  assert_eq "reconnect init exit" "0" "$reconnect_exit"
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

  reconnect_mail_out="$(run_aw_in "$RECONNECT_DIR" mail send --to alice --subject "Reconnect e2e" --body "Reconnect path works" 2>&1)"
  reconnect_mail_exit=$?
  assert_eq "reconnect mail send exit" "0" "$reconnect_mail_exit"
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

  wizard_cert_out="$(run_aw_in "$WIZARD_BYOD_DIR" id cert show --json 2>/dev/null)"
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

  wizard_mail_out="$(run_aw_in "$WIZARD_BYOD_DIR" mail send --to "$local_alias" --subject "Local quickstart e2e" --body "Local quickstart path works" 2>&1)"
  wizard_mail_exit=$?
  assert_eq "wizard mail send exit" "0" "$wizard_mail_exit"
  assert_contains "wizard output shows local team" "$wizard_out" "default:local"
  echo ""
}

phase_aw_init_reconnect
phase_aw_init_local_quickstart

echo "=== Done ==="
