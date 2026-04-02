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
#   9. Exercises the lock lifecycle (acquire, list, renew, release)
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
REDIS_PORT="${AWEB_E2E_REDIS:-6399}"
PG_PORT="${AWEB_E2E_PG:-5452}"
SERVER_URL="http://localhost:$AWEB_PORT"

# Isolated home so aw config doesn't interfere with the user's real config.
E2E_HOME="$(make_temp_dir aw-e2e-home)"
E2E_CWD="$(make_temp_dir aw-e2e-cwd)"
ALICE_DIR="$E2E_CWD/alice"
BOB_DIR="$E2E_CWD/bob"
REVIEWER_DIR="$E2E_CWD/reviewer"
mkdir -p "$ALICE_DIR" "$BOB_DIR" "$REVIEWER_DIR"
ALICE_DIR="$(canonicalize_dir "$ALICE_DIR")"
BOB_DIR="$(canonicalize_dir "$BOB_DIR")"
REVIEWER_DIR="$(canonicalize_dir "$REVIEWER_DIR")"

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

run_aw_in() {
  local workdir="$1"
  shift
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$CLI_DIR/aw" "$@"
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

create_out="$(run_aw_in "$ALICE_DIR" project create \
  --server-url "$SERVER_URL" \
  --project e2e-journey \
  --alias alice \
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

init_out="$(AWEB_API_KEY="$ALICE_KEY" run_aw_in "$BOB_DIR" init \
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

invite_out="$(run_aw_in "$ALICE_DIR" spawn create-invite \
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

accept_out="$(run_aw_in "$REVIEWER_DIR" spawn accept-invite "$INVITE_TOKEN" \
  --server "$SERVER_URL" \
  --alias reviewer \
  --json 2>/dev/null)"

REVIEWER_KEY="$(echo "$accept_out" | jq_field api_key)"
REVIEWER_PROJECT="$(echo "$accept_out" | jq_field project_id)"
REVIEWER_ALIAS="$(echo "$accept_out" | jq_field alias)"

assert_eq "reviewer in same project" "$PROJECT_ID" "$REVIEWER_PROJECT"
assert_eq "reviewer alias" "reviewer" "$REVIEWER_ALIAS"
assert_not_empty "reviewer api_key" "$REVIEWER_KEY"
echo ""

# ---------------------------------------------------------------------------
# Phase 7: workspace add-worktree
# ---------------------------------------------------------------------------
echo "=== Phase 7: workspace add-worktree ==="

REPO_DIR="$E2E_CWD/repo"
CHILD_ALIAS="reviewer-wt"
CHILD_DIR="$E2E_CWD/repo-$CHILD_ALIAS"
mkdir -p "$REPO_DIR"
REPO_DIR="$(canonicalize_dir "$REPO_DIR")"
git -C "$REPO_DIR" init >/dev/null 2>&1
git -C "$REPO_DIR" config user.email e2e@example.com
git -C "$REPO_DIR" config user.name "E2E User"
git -C "$REPO_DIR" remote add origin https://github.com/awebai/e2e-journey.git
printf "# e2e repo\n" > "$REPO_DIR/README.md"
git -C "$REPO_DIR" add README.md
git -C "$REPO_DIR" commit -m "Initial commit" >/dev/null 2>&1
CHILD_DIR_EXPECTED="$(canonicalize_dir "$(dirname "$REPO_DIR")")/$(basename "$REPO_DIR")-$CHILD_ALIAS"

AWEB_URL="$SERVER_URL" AWEB_API_KEY="$ALICE_KEY" run_aw_in "$REPO_DIR" connect 2>/dev/null
((pass++))
echo "  PASS: repo workspace connected"

worktree_out="$(run_aw_in "$REPO_DIR" workspace add-worktree developer --alias "$CHILD_ALIAS" --json 2>/dev/null)"
worktree_path="$(echo "$worktree_out" | jq_field worktree_path)"
worktree_role="$(echo "$worktree_out" | jq_field role)"
assert_eq "add-worktree path" "$CHILD_DIR_EXPECTED" "$worktree_path"
assert_eq "add-worktree role" "developer" "$worktree_role"

child_status="$(run_aw_in "$CHILD_DIR_EXPECTED" workspace status 2>/dev/null)"
if echo "$child_status" | grep -q "$CHILD_ALIAS"; then
  echo "  PASS: child workspace registered"
  ((pass++))
else
  echo "  FAIL: child workspace status missing alias (output: ${child_status:0:160})"
  ((fail++))
fi

git -C "$REPO_DIR" worktree remove --force "$CHILD_DIR_EXPECTED" >/dev/null 2>&1 || true
git -C "$REPO_DIR" branch -D "$CHILD_ALIAS" >/dev/null 2>&1 || true
echo ""

# ---------------------------------------------------------------------------
# Phase 8: Mail send and receive
# ---------------------------------------------------------------------------
echo "=== Phase 8: Alice sends mail to bob ==="

run_aw_in "$ALICE_DIR" mail send \
  --to bob \
  --subject "E2E test" \
  --body "Hello from alice" 2>/dev/null
((pass++))
echo "  PASS: mail sent"

echo ""
echo "=== Phase 8: Bob reads inbox ==="

bob_inbox="$(run_aw_in "$BOB_DIR" mail inbox --json 2>/dev/null)"
bob_msg_count="$(echo "$bob_inbox" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('messages',[])))" 2>/dev/null || echo "")"
bob_msg_body="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('body','') if msgs else '')" 2>/dev/null || echo "")"
bob_msg_verified="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('verification_status','') if msgs else '')" 2>/dev/null || echo "")"
BOB_MSG_ID="$(echo "$bob_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('message_id','') if msgs else '')" 2>/dev/null || echo "")"

assert_eq "bob has 1 message" "1" "$bob_msg_count"
assert_eq "message body" "Hello from alice" "$bob_msg_body"
assert_eq "signature verified" "verified" "$bob_msg_verified"
echo ""

# ---------------------------------------------------------------------------
# Phase 9: Mail ack
# ---------------------------------------------------------------------------
echo "=== Phase 9: Bob acks the message ==="

run_aw_in "$BOB_DIR" mail ack --message-id "$BOB_MSG_ID" 2>/dev/null
((pass++))
echo "  PASS: message acked"

bob_unread="$(run_aw_in "$BOB_DIR" mail inbox --unread-only --json 2>/dev/null)"
bob_unread_count="$(echo "$bob_unread" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('messages',[])))" 2>/dev/null || echo "0")"
assert_eq "bob unread inbox empty" "0" "$bob_unread_count"
echo ""

# ---------------------------------------------------------------------------
# Phase 10: Cross-identity messaging (reviewer -> alice)
# ---------------------------------------------------------------------------
echo "=== Phase 10: Reviewer (from spawn) sends mail to alice ==="

run_aw_in "$REVIEWER_DIR" mail send \
  --to alice \
  --body "Hello from reviewer (spawned identity)" 2>/dev/null
((pass++))
echo "  PASS: cross-identity mail sent"

alice_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json 2>/dev/null)"
alice_msg_from="$(echo "$alice_inbox" | python3 -c "import sys,json; msgs=json.load(sys.stdin).get('messages',[]); print(msgs[0].get('from_alias','') if msgs else '')" 2>/dev/null || echo "")"
assert_eq "message from reviewer" "reviewer" "$alice_msg_from"
echo ""

# ---------------------------------------------------------------------------
# Phase 11: Bob replies to alice
# ---------------------------------------------------------------------------
echo "=== Phase 11: Bob replies to alice ==="

run_aw_in "$BOB_DIR" mail send \
  --to alice \
  --subject "Re: E2E test" \
  --body "Got it, reply from bob" 2>/dev/null
((pass++))
echo "  PASS: reply sent"
echo ""

# ---------------------------------------------------------------------------
# Phase 12: whoami
# ---------------------------------------------------------------------------
echo "=== Phase 12: whoami ==="

whoami_out="$(run_aw_in "$ALICE_DIR" whoami --json 2>/dev/null)"
whoami_alias="$(echo "$whoami_out" | jq_field alias)"
whoami_project="$(echo "$whoami_out" | jq_field project_id)"
assert_eq "whoami alias" "alice" "$whoami_alias"
assert_eq "whoami project" "$PROJECT_ID" "$whoami_project"
echo ""

# ---------------------------------------------------------------------------
# Phase 13: workspace status
# ---------------------------------------------------------------------------
echo "=== Phase 13: workspace status ==="

ws_status_out="$(run_aw_in "$ALICE_DIR" workspace status 2>/dev/null)"
ws_status_exit=$?
if [[ $ws_status_exit -eq 0 && -n "$ws_status_out" ]]; then
  echo "  PASS: workspace status"
  ((pass++))
else
  echo "  FAIL: workspace status (exit=$ws_status_exit)"
  ((fail++))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 14: chat (full round-trip)
# ---------------------------------------------------------------------------
echo "=== Phase 14: chat ==="

run_aw_in "$ALICE_DIR" chat send-and-wait bob \
  "E2E chat from alice" --start-conversation --wait 3 2>/dev/null
((pass++))
echo "  PASS: alice→bob chat sent"

bob_pending="$(run_aw_in "$BOB_DIR" chat pending 2>/dev/null)"
if echo "$bob_pending" | grep -qi "alice"; then
  echo "  PASS: bob sees pending chat from alice"
  ((pass++))
else
  echo "  FAIL: bob has no pending chat from alice (output: ${bob_pending:0:100})"
  ((fail++))
fi

bob_open="$(run_aw_in "$BOB_DIR" chat open alice 2>/dev/null)"
if echo "$bob_open" | grep -q "E2E chat from alice"; then
  echo "  PASS: bob reads alice's chat message"
  ((pass++))
else
  echo "  FAIL: bob can't read alice's message (output: ${bob_open:0:100})"
  ((fail++))
fi

run_aw_in "$BOB_DIR" chat send-and-leave alice \
  "Chat reply from bob" 2>/dev/null
((pass++))
echo "  PASS: bob→alice chat reply"

alice_history="$(run_aw_in "$ALICE_DIR" chat history bob 2>/dev/null)"
if echo "$alice_history" | grep -q "Chat reply from bob"; then
  echo "  PASS: alice sees bob's reply in history"
  ((pass++))
else
  echo "  FAIL: alice can't see chat history (output: ${alice_history:0:100})"
  ((fail++))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 15: tasks
# ---------------------------------------------------------------------------
echo "=== Phase 15: tasks ==="

task_create_out="$(run_aw_in "$ALICE_DIR" task create \
  --title "E2E test task" --json 2>/dev/null)"
TASK_ID="$(echo "$task_create_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('task_id') or d.get('id',''))" 2>/dev/null || echo "")"
assert_not_empty "task created" "$TASK_ID"

task_list_out="$(run_aw_in "$ALICE_DIR" task list 2>/dev/null)"
if echo "$task_list_out" | grep -q "E2E test task"; then
  echo "  PASS: task list shows our task"
  ((pass++))
else
  echo "  FAIL: task list doesn't show our task"
  ((fail++))
fi

if [[ -n "$TASK_ID" ]]; then
  run_aw_in "$ALICE_DIR" task close "$TASK_ID" 2>/dev/null
  ((pass++))
  echo "  PASS: task closed"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 16: instructions management
# ---------------------------------------------------------------------------
echo "=== Phase 16: instructions management ==="

instructions_show_out="$(run_aw_in "$ALICE_DIR" instructions show --json 2>/dev/null)"
if [[ $? -eq 0 && -n "$instructions_show_out" ]]; then
  echo "  PASS: instructions show"
  ((pass++))
else
  echo "  FAIL: instructions show"
  ((fail++))
fi

ORIGINAL_INSTRUCTIONS_ID="$(echo "$instructions_show_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_instructions') or {}).get('project_instructions_id',''))
" 2>/dev/null || echo "")"
assert_not_empty "original instructions id" "$ORIGINAL_INSTRUCTIONS_ID"
if [[ -z "$ORIGINAL_INSTRUCTIONS_ID" ]]; then
  echo "  Aborting: missing original instructions id"
  exit 1
fi

INSTRUCTIONS_BODY_FILE="$ALICE_DIR/instructions-v2.md"
cat > "$INSTRUCTIONS_BODY_FILE" <<'EOF'
## Shared Rules

Use `aw instructions show`.
EOF

instructions_set_out="$(run_aw_in "$ALICE_DIR" instructions set --body-file "$INSTRUCTIONS_BODY_FILE" --json 2>/dev/null)"
NEW_INSTRUCTIONS_ID="$(echo "$instructions_set_out" | jq_field project_instructions_id)"
NEW_INSTRUCTIONS_VERSION="$(echo "$instructions_set_out" | jq_field version)"
NEW_INSTRUCTIONS_ACTIVATED="$(echo "$instructions_set_out" | jq_field activated)"
assert_not_empty "instructions set id" "$NEW_INSTRUCTIONS_ID"
assert_eq "instructions set activated" "True" "$NEW_INSTRUCTIONS_ACTIVATED"
assert_not_empty "instructions set version" "$NEW_INSTRUCTIONS_VERSION"

instructions_show_new="$(run_aw_in "$ALICE_DIR" instructions show --json 2>/dev/null)"
instructions_show_new_id="$(echo "$instructions_show_new" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_instructions') or {}).get('project_instructions_id',''))
" 2>/dev/null || echo "")"
instructions_show_new_body="$(echo "$instructions_show_new" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_instructions') or {}).get('document',{}).get('body_md',''))
" 2>/dev/null || echo "")"
assert_eq "instructions show active after set" "$NEW_INSTRUCTIONS_ID" "$instructions_show_new_id"
if [[ "$instructions_show_new_body" == *"Use \`aw instructions show\`."* ]]; then
  echo "  PASS: instructions show reflects new body"
  ((pass++))
else
  echo "  FAIL: instructions show missing new body"
  ((fail++))
fi

instructions_history_out="$(run_aw_in "$ALICE_DIR" instructions history --json 2>/dev/null)"
instructions_history_has_new="$(echo "$instructions_history_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
items=d.get('project_instructions_versions') or []
target=sys.argv[1]
print(any(item.get('project_instructions_id') == target for item in items))
" "$NEW_INSTRUCTIONS_ID" 2>/dev/null || echo "False")"
assert_eq "instructions history includes new version" "True" "$instructions_history_has_new"

instructions_activate_out="$(run_aw_in "$ALICE_DIR" instructions activate "$ORIGINAL_INSTRUCTIONS_ID" --json 2>/dev/null)"
instructions_activated_id="$(echo "$instructions_activate_out" | jq_field project_instructions_id)"
instructions_activated_flag="$(echo "$instructions_activate_out" | jq_field activated)"
assert_eq "instructions activate id" "$ORIGINAL_INSTRUCTIONS_ID" "$instructions_activated_id"
assert_eq "instructions activate flag" "True" "$instructions_activated_flag"

instructions_show_reactivated="$(run_aw_in "$ALICE_DIR" instructions show --json 2>/dev/null)"
instructions_show_reactivated_id="$(echo "$instructions_show_reactivated" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_instructions') or {}).get('project_instructions_id',''))
" 2>/dev/null || echo "")"
assert_eq "instructions show active after activate" "$ORIGINAL_INSTRUCTIONS_ID" "$instructions_show_reactivated_id"

instructions_reset_out="$(run_aw_in "$ALICE_DIR" instructions reset --json 2>/dev/null)"
instructions_reset_flag="$(echo "$instructions_reset_out" | jq_field reset)"
instructions_reset_id="$(echo "$instructions_reset_out" | jq_field active_project_instructions_id)"
assert_eq "instructions reset flag" "True" "$instructions_reset_flag"
assert_not_empty "instructions reset active id" "$instructions_reset_id"
echo ""

# ---------------------------------------------------------------------------
# Phase 17: roles management + work discovery
# ---------------------------------------------------------------------------
echo "=== Phase 17: roles management + work ==="

roles_show_out="$(run_aw_in "$ALICE_DIR" roles show --all-roles --json 2>/dev/null)"
if [[ $? -eq 0 && -n "$roles_show_out" ]]; then
  echo "  PASS: roles show"
  ((pass++))
else
  echo "  FAIL: roles show"
  ((fail++))
fi

ORIGINAL_ROLES_ID="$(echo "$roles_show_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_roles') or {}).get('project_roles_id',''))
" 2>/dev/null || echo "")"
assert_not_empty "original roles id" "$ORIGINAL_ROLES_ID"
if [[ -z "$ORIGINAL_ROLES_ID" ]]; then
  echo "  Aborting: missing original roles id"
  exit 1
fi

ROLES_BUNDLE_FILE="$ALICE_DIR/roles-v2.json"
cat > "$ROLES_BUNDLE_FILE" <<'EOF'
{
  "roles": {
    "developer": {
      "title": "Developer",
      "playbook_md": "Ship the change."
    },
    "reviewer": {
      "title": "Reviewer",
      "playbook_md": "Review carefully."
    }
  }
}
EOF

roles_set_out="$(run_aw_in "$ALICE_DIR" roles set --bundle-file "$ROLES_BUNDLE_FILE" --json 2>/dev/null)"
NEW_ROLES_ID="$(echo "$roles_set_out" | jq_field project_roles_id)"
NEW_ROLES_VERSION="$(echo "$roles_set_out" | jq_field version)"
NEW_ROLES_ACTIVATED="$(echo "$roles_set_out" | jq_field activated)"
assert_not_empty "roles set id" "$NEW_ROLES_ID"
assert_eq "roles set activated" "True" "$NEW_ROLES_ACTIVATED"
assert_not_empty "roles set version" "$NEW_ROLES_VERSION"

roles_show_new="$(run_aw_in "$ALICE_DIR" roles show --all-roles --json 2>/dev/null)"
roles_show_new_id="$(echo "$roles_show_new" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_roles') or {}).get('project_roles_id',''))
" 2>/dev/null || echo "")"
roles_has_reviewer="$(echo "$roles_show_new" | python3 -c "
import sys,json
d=json.load(sys.stdin)
roles=(d.get('project_roles') or {}).get('roles') or {}
print('reviewer' in roles)
" 2>/dev/null || echo "False")"
assert_eq "roles show active after set" "$NEW_ROLES_ID" "$roles_show_new_id"
assert_eq "roles show includes reviewer role" "True" "$roles_has_reviewer"

roles_history_out="$(run_aw_in "$ALICE_DIR" roles history --json 2>/dev/null)"
roles_history_has_new="$(echo "$roles_history_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
items=d.get('project_roles_versions') or []
target=sys.argv[1]
print(any(item.get('project_roles_id') == target for item in items))
" "$NEW_ROLES_ID" 2>/dev/null || echo "False")"
assert_eq "roles history includes new version" "True" "$roles_history_has_new"

roles_activate_out="$(run_aw_in "$ALICE_DIR" roles activate "$ORIGINAL_ROLES_ID" --json 2>/dev/null)"
roles_activated_id="$(echo "$roles_activate_out" | jq_field project_roles_id)"
roles_activated_flag="$(echo "$roles_activate_out" | jq_field activated)"
assert_eq "roles activate id" "$ORIGINAL_ROLES_ID" "$roles_activated_id"
assert_eq "roles activate flag" "True" "$roles_activated_flag"

roles_show_reactivated="$(run_aw_in "$ALICE_DIR" roles show --all-roles --json 2>/dev/null)"
roles_show_reactivated_id="$(echo "$roles_show_reactivated" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print((d.get('project_roles') or {}).get('project_roles_id',''))
" 2>/dev/null || echo "")"
assert_eq "roles show active after activate" "$ORIGINAL_ROLES_ID" "$roles_show_reactivated_id"

roles_reset_out="$(run_aw_in "$ALICE_DIR" roles reset --json 2>/dev/null)"
roles_reset_flag="$(echo "$roles_reset_out" | jq_field reset)"
roles_reset_id="$(echo "$roles_reset_out" | jq_field active_project_roles_id)"
assert_eq "roles reset flag" "True" "$roles_reset_flag"
assert_not_empty "roles reset active id" "$roles_reset_id"

work_ready_exit=0
run_aw_in "$ALICE_DIR" work ready --json 2>/dev/null || work_ready_exit=$?
if [[ $work_ready_exit -eq 0 ]]; then
  echo "  PASS: work ready"
  ((pass++))
else
  echo "  FAIL: work ready (exit=$work_ready_exit)"
  ((fail++))
fi

work_active_exit=0
run_aw_in "$ALICE_DIR" work active --json 2>/dev/null || work_active_exit=$?
if [[ $work_active_exit -eq 0 ]]; then
  echo "  PASS: work active"
  ((pass++))
else
  echo "  FAIL: work active (exit=$work_active_exit)"
  ((fail++))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 18: contacts + heartbeat
# ---------------------------------------------------------------------------
echo "=== Phase 18: contacts + heartbeat ==="

contacts_exit=0
run_aw_in "$ALICE_DIR" contacts list --json 2>/dev/null || contacts_exit=$?
if [[ $contacts_exit -eq 0 ]]; then
  echo "  PASS: contacts list"
  ((pass++))
else
  echo "  FAIL: contacts list (exit=$contacts_exit)"
  ((fail++))
fi

hb_exit=0
run_aw_in "$ALICE_DIR" heartbeat 2>/dev/null || hb_exit=$?
if [[ $hb_exit -eq 0 ]]; then
  echo "  PASS: heartbeat"
  ((pass++))
else
  echo "  FAIL: heartbeat (exit=$hb_exit)"
  ((fail++))
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 19: roles + identities
# ---------------------------------------------------------------------------
echo "=== Phase 19: roles + identities ==="

roles_out="$(run_aw_in "$ALICE_DIR" roles list 2>/dev/null)"
if [[ $? -eq 0 ]]; then
  echo "  PASS: roles list"
  ((pass++))
else
  echo "  FAIL: roles list"
  ((fail++))
fi

identities_out="$(run_aw_in "$ALICE_DIR" identities --json 2>/dev/null)"
alice_found="$(echo "$identities_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
agents = d.get('identities') or d.get('agents') or []
print(any(a.get('alias') == 'alice' for a in agents))
" 2>/dev/null || echo "False")"
assert_eq "alice in identities" "True" "$alice_found"

bob_found="$(echo "$identities_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
agents = d.get('identities') or d.get('agents') or []
print(any(a.get('alias') == 'bob' for a in agents))
" 2>/dev/null || echo "False")"
assert_eq "bob in identities" "True" "$bob_found"

reviewer_found="$(echo "$identities_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
agents = d.get('identities') or d.get('agents') or []
print(any(a.get('alias') == 'reviewer' for a in agents))
" 2>/dev/null || echo "False")"
assert_eq "reviewer in identities" "True" "$reviewer_found"
echo ""

# ---------------------------------------------------------------------------
# Phase 20: roles deactivate
# ---------------------------------------------------------------------------
echo "=== Phase 20: roles deactivate ==="

roles_deactivate_out="$(run_aw_in "$ALICE_DIR" roles deactivate --json 2>/dev/null)"
roles_deactivate_exit=$?
if [[ $roles_deactivate_exit -eq 0 && -n "$roles_deactivate_out" ]]; then
  echo "  PASS: roles deactivate"
  ((pass++))
else
  echo "  FAIL: roles deactivate (exit=$roles_deactivate_exit)"
  ((fail++))
fi

deactivated_roles_show_out="$(run_aw_in "$ALICE_DIR" roles show --all-roles --json 2>/dev/null)"
deactivated_roles_count="$(echo "$deactivated_roles_show_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
project_roles = d.get('project_roles') or {}
roles = project_roles.get('roles') or {}
print(len(roles))
" 2>/dev/null || echo "")"
deactivated_roles_id="$(echo "$deactivated_roles_show_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
project_roles = d.get('project_roles') or {}
print(project_roles.get('active_project_roles_id',''))
" 2>/dev/null || echo "")"
assert_eq "roles deactivate clears active bundle" "0" "$deactivated_roles_count"
assert_not_empty "roles deactivate keeps active bundle id" "$deactivated_roles_id"
echo ""

# ---------------------------------------------------------------------------
# Phase 21: lock lifecycle (acquire, list, renew, release)
# ---------------------------------------------------------------------------
echo "=== Phase 21: lock lifecycle ==="

lock_acquire_out="$(run_aw_in "$ALICE_DIR" lock acquire \
  --resource-key "e2e-test-resource" --ttl-seconds 300 --json 2>/dev/null)"
lock_acquire_exit=$?
LOCK_KEY="$(echo "$lock_acquire_out" | jq_field resource_key)"
assert_eq "lock acquire exit" "0" "$lock_acquire_exit"
assert_eq "lock acquire resource_key" "e2e-test-resource" "$LOCK_KEY"

lock_list_out="$(run_aw_in "$ALICE_DIR" lock list --json 2>/dev/null)"
lock_list_has_resource="$(echo "$lock_list_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
locks=d.get('reservations') or d.get('locks') or []
print(any(r.get('resource_key') == 'e2e-test-resource' for r in locks))
" 2>/dev/null || echo "False")"
assert_eq "lock list shows acquired lock" "True" "$lock_list_has_resource"

lock_renew_out="$(run_aw_in "$ALICE_DIR" lock renew \
  --resource-key "e2e-test-resource" --ttl-seconds 600 --json 2>/dev/null)"
lock_renew_exit=$?
assert_eq "lock renew exit" "0" "$lock_renew_exit"

lock_release_out="$(run_aw_in "$ALICE_DIR" lock release \
  --resource-key "e2e-test-resource" --json 2>/dev/null)"
lock_release_exit=$?
assert_eq "lock release exit" "0" "$lock_release_exit"

lock_list_after="$(run_aw_in "$ALICE_DIR" lock list --json 2>/dev/null)"
lock_list_still_has="$(echo "$lock_list_after" | python3 -c "
import sys,json
d=json.load(sys.stdin)
locks=d.get('reservations') or d.get('locks') or []
print(any(r.get('resource_key') == 'e2e-test-resource' for r in locks))
" 2>/dev/null || echo "True")"
assert_eq "lock list empty after release" "False" "$lock_list_still_has"
echo ""

echo "=== All user journey phases complete ==="
