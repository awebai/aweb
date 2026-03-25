#!/usr/bin/env bash
#
# End-to-end OSS user journey test.
#
# Simulates a new user who:
#   1. Starts the server with Docker Compose
#   2. Builds the aw CLI
#   3. Creates a project (unauthenticated)
#   4. Inits a second workspace (project authority)
#   5. Creates a spawn invite (identity authority)
#   6. Accepts the invite (token authority)
#   7. Sends and receives signed mail between identities
#   8. Acks a message
#
# Usage:
#   ./scripts/e2e-oss-user-journey.sh
#
# Requirements:
#   - Docker and Docker Compose
#   - Go toolchain
#   - Ports 8100, 6399, 5452 available (or override via env)
#
# Environment overrides:
#   AWEB_E2E_PORT    server port  (default: 8100)
#   AWEB_E2E_REDIS   redis port   (default: 6399)
#   AWEB_E2E_PG      postgres port (default: 5452)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"
CLI_DIR="$REPO_ROOT/cli/go"

AWEB_PORT="${AWEB_E2E_PORT:-8100}"
REDIS_PORT="${AWEB_E2E_REDIS:-6399}"
PG_PORT="${AWEB_E2E_PG:-5452}"
SERVER_URL="http://localhost:$AWEB_PORT"

# Isolated home so aw config doesn't interfere with the user's real config.
E2E_HOME="$(mktemp -d "${TMPDIR:-/tmp}/aw-e2e-home.XXXXXX")"
E2E_CWD="$(mktemp -d "${TMPDIR:-/tmp}/aw-e2e-cwd.XXXXXX")"

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
    ((pass++))
  else
    echo "  FAIL: $label (expected '$expected', got '$actual')"
    ((fail++))
  fi
}

assert_not_empty() {
  local label="$1" value="$2"
  if [[ -n "$value" ]]; then
    echo "  PASS: $label"
    ((pass++))
  else
    echo "  FAIL: $label (empty)"
    ((fail++))
  fi
}

assert_status() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label (HTTP $actual)"
    ((pass++))
  else
    echo "  FAIL: $label (expected HTTP $expected, got HTTP $actual)"
    ((fail++))
  fi
}

# Run aw in the isolated environment. All aw calls go through here.
# Uses env(1) to ensure variables propagate into the subshell and cd
# doesn't affect the parent. XDG_CONFIG_HOME ensures aw doesn't read
# the user's real ~/.config/aw.
# Fully isolated aw execution:
# - HOME points to temp dir (signing keys go here)
# - AW_CONFIG_PATH overrides config file location
# - CWD is a clean temp dir (no .aw/context from parent dirs)
run_aw() {
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$E2E_CWD" "$CLI_DIR/aw" "$@"
}

jq_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"
}

# ---------------------------------------------------------------------------
# Phase 0: Build CLI
# ---------------------------------------------------------------------------
echo "=== Phase 0: Build aw CLI ==="
cd "$CLI_DIR"
make build 2>&1 | tail -1
echo "  aw binary: $CLI_DIR/aw"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: Start server
# ---------------------------------------------------------------------------
echo "=== Phase 1: Start server in Docker ==="

CUSTODY_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

cat > "$SERVER_DIR/.env.e2e" <<EOF
POSTGRES_USER=aweb
POSTGRES_PASSWORD=aweb-e2e-test
POSTGRES_DB=aweb
AWEB_PORT=$AWEB_PORT
REDIS_PORT=$REDIS_PORT
POSTGRES_PORT=$PG_PORT
AWEB_CUSTODY_KEY=$CUSTODY_KEY
AWEB_MANAGED_DOMAIN=aweb.local
AWEB_LOG_JSON=true
EOF

cd "$SERVER_DIR"
docker compose --env-file .env.e2e down -v 2>/dev/null || true
docker compose --env-file .env.e2e up --build -d 2>&1 | tail -5

echo "Waiting for server health..."
for i in $(seq 1 60); do
  if curl -sf "$SERVER_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

health="$(curl -sf "$SERVER_URL/health" 2>/dev/null || echo '{}')"
health_status="$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")"
assert_eq "server health" "ok" "$health_status"
if [[ "$health_status" != "ok" ]]; then
  echo "  Server not healthy after 120s, aborting."
  echo "  Docker logs:"
  cd "$SERVER_DIR" && docker compose --env-file .env.e2e logs aweb 2>&1 | tail -20
  exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 2: Create project (unauthenticated)
# ---------------------------------------------------------------------------
echo "=== Phase 2: Create project (unauthenticated) ==="

create_out="$(run_aw project create \
  --server-url "$SERVER_URL" \
  --project e2e-journey \
  --alias alice \
  --save-config=false \
  --write-context=false \
  --json 2>/dev/null)"

PROJECT_ID="$(echo "$create_out" | jq_field project_id)"
ALICE_KEY="$(echo "$create_out" | jq_field api_key)"
PROJECT_SLUG="$(echo "$create_out" | jq_field project_slug)"
NAMESPACE="$(echo "$create_out" | jq_field namespace)"
ALICE_ALIAS="$(echo "$create_out" | jq_field alias)"

assert_not_empty "project_id" "$PROJECT_ID"
assert_eq "project_slug" "e2e-journey" "$PROJECT_SLUG"
assert_eq "alice alias" "alice" "$ALICE_ALIAS"
assert_not_empty "api_key starts with aw_sk_" "$ALICE_KEY"
assert_eq "namespace" "e2e-journey.aweb.local" "$NAMESPACE"
echo ""

# ---------------------------------------------------------------------------
# Phase 3: Init second workspace (project authority)
# ---------------------------------------------------------------------------
echo "=== Phase 3: Init second workspace (project authority via AWEB_API_KEY) ==="

init_out="$(AWEB_API_KEY="$ALICE_KEY" run_aw init \
  --server-url "$SERVER_URL" \
  --alias bob \
  --json 2>/dev/null)"

BOB_KEY="$(echo "$init_out" | jq_field api_key)"
BOB_PROJECT="$(echo "$init_out" | jq_field project_id)"
BOB_ALIAS="$(echo "$init_out" | jq_field alias)"

assert_eq "bob in same project" "$PROJECT_ID" "$BOB_PROJECT"
assert_eq "bob alias" "bob" "$BOB_ALIAS"
assert_not_empty "bob api_key" "$BOB_KEY"
echo ""

# ---------------------------------------------------------------------------
# Phase 4: Init without auth should fail (401)
# ---------------------------------------------------------------------------
echo "=== Phase 4: Init without auth should fail ==="

unauth_status="$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$SERVER_URL/v1/workspaces/init" \
  -H 'Content-Type: application/json' \
  -d '{"project_slug":"e2e-journey","alias":"intruder"}' 2>/dev/null || echo "000")"

assert_eq "unauthenticated init rejected" "401" "$unauth_status"
echo ""

# ---------------------------------------------------------------------------
# Phase 5: Spawn create-invite (identity authority)
# ---------------------------------------------------------------------------
echo "=== Phase 5: Spawn create-invite (identity authority) ==="

invite_out="$(AWEB_URL="$SERVER_URL" AWEB_API_KEY="$ALICE_KEY" run_aw spawn create-invite \
  --alias reviewer \
  --json 2>/dev/null)"

INVITE_TOKEN="$(echo "$invite_out" | jq_field token)"
INVITE_NS="$(echo "$invite_out" | jq_field namespace_slug)"

assert_not_empty "invite token" "$INVITE_TOKEN"
assert_eq "invite namespace" "e2e-journey" "$INVITE_NS"
echo ""

# ---------------------------------------------------------------------------
# Phase 6: Spawn accept-invite (token authority)
# ---------------------------------------------------------------------------
echo "=== Phase 6: Spawn accept-invite (token authority, no API key) ==="

accept_out="$(run_aw spawn accept-invite "$INVITE_TOKEN" \
  --server "$SERVER_URL" \
  --alias reviewer \
  --save-config=false \
  --json 2>/dev/null)"

# accept-invite may write .aw/context in CWD even with --save-config=false.
# Remove it to prevent contaminating subsequent commands.
rm -f "$E2E_CWD/.aw/context"

REVIEWER_KEY="$(echo "$accept_out" | jq_field api_key)"
REVIEWER_PROJECT="$(echo "$accept_out" | jq_field project_id)"
REVIEWER_ALIAS="$(echo "$accept_out" | jq_field alias)"

assert_eq "reviewer in same project" "$PROJECT_ID" "$REVIEWER_PROJECT"
assert_eq "reviewer alias" "reviewer" "$REVIEWER_ALIAS"
assert_not_empty "reviewer api_key" "$REVIEWER_KEY"
echo ""

# ---------------------------------------------------------------------------
# Phase 7: Mail send and receive
# ---------------------------------------------------------------------------
echo "=== Phase 7: Alice sends mail to bob ==="

AWEB_URL="$SERVER_URL" AWEB_API_KEY="$ALICE_KEY" run_aw mail send \
  --to bob \
  --subject "E2E test" \
  --body "Hello from alice" 2>/dev/null
((pass++))
echo "  PASS: mail sent"

echo ""
echo "=== Phase 8: Bob reads inbox ==="

bob_inbox="$(AWEB_URL="$SERVER_URL" AWEB_API_KEY="$BOB_KEY" run_aw mail inbox --json 2>/dev/null)"
bob_msg_count="$(echo "$bob_inbox" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('messages',[])))" 2>/dev/null || echo "")"
bob_msg_body="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('body','') if msgs else '')" 2>/dev/null || echo "")"
bob_msg_verified="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('verification_status','') if msgs else '')" 2>/dev/null || echo "")"
BOB_MSG_ID="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('message_id','') if msgs else '')" 2>/dev/null || echo "")"

assert_eq "bob has 1 message" "1" "$bob_msg_count"
assert_eq "message body" "Hello from alice" "$bob_msg_body"
assert_eq "signature verified" "verified" "$bob_msg_verified"
echo ""

# ---------------------------------------------------------------------------
# Phase 8: Mail ack
# ---------------------------------------------------------------------------
echo "=== Phase 9: Bob acks the message ==="

AWEB_URL="$SERVER_URL" AWEB_API_KEY="$BOB_KEY" run_aw mail ack --message-id "$BOB_MSG_ID" 2>/dev/null
((pass++))
echo "  PASS: message acked"

bob_unread="$(AWEB_URL="$SERVER_URL" AWEB_API_KEY="$BOB_KEY" run_aw mail inbox --unread-only --json 2>/dev/null)"
bob_unread_count="$(echo "$bob_unread" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('messages',[])))" 2>/dev/null || echo "")"
assert_eq "bob unread inbox empty" "0" "$bob_unread_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 9: Cross-identity messaging (reviewer -> alice)
# ---------------------------------------------------------------------------
echo "=== Phase 10: Reviewer (from spawn) sends mail to alice ==="

AWEB_URL="$SERVER_URL" AWEB_API_KEY="$REVIEWER_KEY" run_aw mail send \
  --to alice \
  --body "Hello from reviewer (spawned identity)" 2>/dev/null
((pass++))
echo "  PASS: cross-identity mail sent"

alice_inbox="$(AWEB_URL="$SERVER_URL" AWEB_API_KEY="$ALICE_KEY" run_aw mail inbox --json 2>/dev/null)"
alice_msg_from="$(echo "$alice_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('from_alias','') if msgs else '')" 2>/dev/null || echo "")"
assert_eq "message from reviewer" "reviewer" "$alice_msg_from"
echo ""

# ---------------------------------------------------------------------------
# Phase 10: Bob replies to alice
# ---------------------------------------------------------------------------
echo "=== Phase 11: Bob replies to alice ==="

AWEB_URL="$SERVER_URL" AWEB_API_KEY="$BOB_KEY" run_aw mail send \
  --to alice \
  --subject "Re: E2E test" \
  --body "Got it, reply from bob" 2>/dev/null
((pass++))
echo "  PASS: reply sent"
echo ""

echo "=== All user journey phases complete ==="
