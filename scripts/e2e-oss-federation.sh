#!/usr/bin/env bash
#
# End-to-end OSS messaging federation test.
#
# Starts one awid registry plus two isolated aweb servers. The two aweb
# servers use separate Postgres/Redis instances so a cross-server delivery
# cannot accidentally pass through shared local state.
#
# Usage:
#   ./scripts/e2e-oss-federation.sh
#
# Requirements:
#   - Docker and Docker Compose
#   - Go toolchain
#
# Environment overrides:
#   AWID_FED_E2E_PORT     awid host port (default: 8310)
#   AWEB_ALPHA_E2E_PORT   alpha aweb host port (default: 8320)
#   AWEB_BETA_E2E_PORT    beta aweb host port (default: 8330)
#   AWEB_FED_E2E_BUILD    set to 0 to skip docker compose build
#   AWEB_FED_E2E_KEEP     set to 1 to leave containers/temp dir for debugging

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

AWID_PORT="${AWID_FED_E2E_PORT:-8310}"
ALPHA_PORT="${AWEB_ALPHA_E2E_PORT:-8320}"
BETA_PORT="${AWEB_BETA_E2E_PORT:-8330}"
AWID_URL="http://localhost:$AWID_PORT"
ALPHA_URL="http://localhost:$ALPHA_PORT"
BETA_URL="http://localhost:$BETA_PORT"
ALPHA_ORIGIN="http://aweb-alpha:8000"
BETA_ORIGIN="http://aweb-beta:8000"
PROJECT="aweb-fed-e2e-$RANDOM"

E2E_ROOT="$(make_temp_dir aw-fed-e2e)"
E2E_HOME="$E2E_ROOT/home"
COMPOSE_FILE="$E2E_ROOT/docker-compose.yml"
ALICE_DIR="$E2E_ROOT/alice"
ANN_DIR="$E2E_ROOT/ann"
NED_DIR="$E2E_ROOT/ned"
BOB_DIR="$E2E_ROOT/bob"
CHARLIE_DIR="$E2E_ROOT/charlie"
DAVE_DIR="$E2E_ROOT/dave"
mkdir -p "$E2E_HOME" "$ALICE_DIR" "$ANN_DIR" "$NED_DIR" "$BOB_DIR" "$CHARLIE_DIR" "$DAVE_DIR"

pass=0
fail=0

cleanup() {
  local status=$?
  echo ""
  echo "--- Cleanup ---"
  if [[ "${AWEB_FED_E2E_KEEP:-0}" == "1" ]]; then
    echo "Keeping federation e2e artifacts for debugging:"
    echo "  project: $PROJECT"
    echo "  root:    $E2E_ROOT"
  elif [[ -f "$COMPOSE_FILE" ]]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    rm -rf "$E2E_ROOT"
  fi
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
    echo "  FAIL: $label (expected '$needle', got: ${haystack:0:180})"
    fail=$((fail + 1))
  fi
}

jq_field() {
  python3 -c "
import json, sys
text = sys.stdin.read()
start = text.find('{')
if start < 0:
    print('')
    raise SystemExit
try:
    data = json.loads(text[start:])
except json.JSONDecodeError:
    print('')
    raise SystemExit
value = data
for part in '$1'.split('.'):
    if not part:
        continue
    if isinstance(value, dict):
        value = value.get(part, '')
    else:
        value = ''
print(value if value is not None else '')
"
}

json_count_matching() {
  local key="$1" value="$2"
  python3 -c '
import json, sys
key, value = sys.argv[1], sys.argv[2]
try:
    data = json.load(sys.stdin)
except Exception:
    print(0)
    raise SystemExit
items = data.get("messages") or data.get("sessions") or data.get("pending") or []
print(sum(1 for item in items if str(item.get(key, "")) == value))
' "$key" "$value"
}

json_first_field_matching() {
  local match_key="$1" match_value="$2" out_key="$3"
  python3 -c '
import json, sys
match_key, match_value, out_key = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit
for item in data.get("messages", []):
    if str(item.get(match_key, "")) == match_value:
        print(item.get(out_key, "") or "")
        break
else:
    print("")
' "$match_key" "$match_value" "$out_key"
}

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

psql_scalar() {
  local service="$1" sql="$2"
  compose exec -T "$service" psql -U aweb -d aweb -At -c "$sql" 2>/dev/null | tr -d '[:space:]'
}

run_aw_in() {
  local workdir="$1"
  shift
  HOME="$E2E_HOME" \
  AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
  AWID_REGISTRY_URL="$AWID_URL" \
  AWID_SKIP_DNS_VERIFY=1 \
  bash -c 'cd "$1" && shift && exec "$@"' _ "$workdir" "$CLI_DIR/aw" "$@"
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

set_namespace_delivery_origin() {
  local dir="$1" label="$2" namespace="$3" origin="$4"
  local out status
  capture_success out "$label namespace delivery-origin" run_aw_in "$dir" id namespace set-delivery-origin \
    --namespace "$namespace" \
    --origin "$origin" \
    --json
  status="$(echo "$out" | jq_field status)"
  if [[ "$status" == "updated" || "$status" == "unchanged" ]]; then
    echo "  PASS: $label namespace address-route delivery origin set"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label namespace address-route delivery origin setup failed: ${out:0:180}"
    fail=$((fail + 1))
  fi
}

wait_health() {
  local label="$1" url="$2"
  for _ in $(seq 1 60); do
    if curl -sf "$url/health" >/dev/null 2>&1; then
      assert_eq "$label health" "ok" "$(curl -sf "$url/health" | jq_field status)"
      return
    fi
    sleep 2
  done
  echo "  FAIL: $label health timed out"
  fail=$((fail + 1))
}

create_identity_and_join_team() {
  local dir="$1" domain="$2" name="$3" team="$4" url="$5"
  local create_out invite_out token accept_out init_out
  capture_success create_out "create_out" run_aw_in "$dir" id create \
    --name "$name" \
    --domain "$domain" \
    --registry "$AWID_URL" \
    --skip-dns-verify \
    --json
  printf '%s\n' "$create_out" > "$dir/create.json"
  assert_not_empty "$name did_aw" "$(echo "$create_out" | jq_field did_aw)"

  if [[ "$name" == "$team" ]]; then
    :
  fi

  capture_success invite_out "invite_out" run_aw_in "$dir" id team invite \
    --team "$team" \
    --namespace "$domain" \
    --global \
    --json
  token="$(echo "$invite_out" | jq_field token)"
  assert_not_empty "$name invite token" "$token"
  capture_success accept_out "accept_out" run_aw_in "$dir" id team accept-invite "$token" --alias "$name" --json
  assert_eq "$name invite accepted" "accepted" "$(echo "$accept_out" | jq_field status)"
  capture_success init_out "$name init" run_aw_in "$dir" init --url "$url" --alias "$name" --do-not-touch-agents-md
  assert_contains "$name init connected" "$init_out" "connected"
}

echo "=== Phase 0: Build aw CLI ==="
cd "$CLI_DIR"
make build >/dev/null
echo "  aw binary: $CLI_DIR/aw"
echo ""

echo "=== Phase 1: Write and start federation compose ==="
cat > "$COMPOSE_FILE" <<EOF
services:
  redis-awid:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 2s
      retries: 30
  postgres-awid:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: awid
      POSTGRES_PASSWORD: awid-fed-e2e
      POSTGRES_DB: awid
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U awid -d awid"]
      interval: 2s
      timeout: 2s
      retries: 30
  awid:
    build:
      context: $REPO_ROOT
      dockerfile: awid/Dockerfile
    ports:
      - "$AWID_PORT:8010"
    environment:
      AWID_DATABASE_URL: postgresql://awid:awid-fed-e2e@postgres-awid:5432/awid
      AWID_REDIS_URL: redis://redis-awid:6379/0
      AWID_HOST: 0.0.0.0
      AWID_PORT: 8010
      AWID_DB_SCHEMA: awid
      AWID_RATE_LIMIT_DISABLED: "1"
      AWID_SKIP_DNS_VERIFY: "1"
      APP_ENV: development
      AWID_ALLOW_INSECURE_DELIVERY_ORIGIN: "1"
    depends_on:
      redis-awid:
        condition: service_healthy
      postgres-awid:
        condition: service_healthy

  redis-alpha:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 2s
      retries: 30
  postgres-alpha:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: aweb
      POSTGRES_PASSWORD: aweb-fed-e2e
      POSTGRES_DB: aweb
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aweb -d aweb"]
      interval: 2s
      timeout: 2s
      retries: 30
  aweb-alpha:
    build:
      context: $REPO_ROOT
      dockerfile: server/Dockerfile
    ports:
      - "$ALPHA_PORT:8000"
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:aweb-fed-e2e@postgres-alpha:5432/aweb
      AWEB_REDIS_URL: redis://redis-alpha:6379/0
      AWID_REGISTRY_URL: http://awid:8010
      AWEB_PUBLIC_ORIGIN: $ALPHA_ORIGIN
      AWEB_DISCOVERY_ORIGIN: $ALPHA_URL
      AWEB_HOST: 0.0.0.0
      AWEB_PORT: 8000
    depends_on:
      redis-alpha:
        condition: service_healthy
      postgres-alpha:
        condition: service_healthy
      awid:
        condition: service_started

  redis-beta:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 2s
      retries: 30
  postgres-beta:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: aweb
      POSTGRES_PASSWORD: aweb-fed-e2e
      POSTGRES_DB: aweb
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aweb -d aweb"]
      interval: 2s
      timeout: 2s
      retries: 30
  aweb-beta:
    build:
      context: $REPO_ROOT
      dockerfile: server/Dockerfile
    ports:
      - "$BETA_PORT:8000"
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:aweb-fed-e2e@postgres-beta:5432/aweb
      AWEB_REDIS_URL: redis://redis-beta:6379/0
      AWID_REGISTRY_URL: http://awid:8010
      AWEB_PUBLIC_ORIGIN: $BETA_ORIGIN
      AWEB_DISCOVERY_ORIGIN: $BETA_URL
      AWEB_HOST: 0.0.0.0
      AWEB_PORT: 8000
    depends_on:
      redis-beta:
        condition: service_healthy
      postgres-beta:
        condition: service_healthy
      awid:
        condition: service_started
EOF

compose down -v >/dev/null 2>&1 || true
if [[ "${AWEB_FED_E2E_BUILD:-1}" != "0" ]]; then
  compose build
fi
compose up -d
wait_health "awid" "$AWID_URL"
wait_health "alpha" "$ALPHA_URL"
wait_health "beta" "$BETA_URL"
echo ""

echo "=== Phase 2: Create alpha and beta identities/teams ==="
capture_success alice_create "alice_create" run_aw_in "$ALICE_DIR" id create --name alice --domain alpha.test.local --registry "$AWID_URL" --skip-dns-verify --json
ALICE_DID_AW="$(echo "$alice_create" | jq_field did_aw)"
ALICE_DID_KEY="$(echo "$alice_create" | jq_field did_key)"
assert_not_empty "alice did_aw" "$ALICE_DID_AW"
assert_not_empty "alice did_key" "$ALICE_DID_KEY"
capture_success alpha_team "alpha_team" run_aw_in "$ALICE_DIR" id team create --name alpha --namespace alpha.test.local --registry "$AWID_URL" --json
assert_eq "alpha team id" "alpha:alpha.test.local" "$(echo "$alpha_team" | jq_field team_id)"
capture_success alice_invite "alice_invite" run_aw_in "$ALICE_DIR" id team invite --team alpha --namespace alpha.test.local --global --json
alice_token="$(echo "$alice_invite" | jq_field token)"
run_success "alice accept invite" run_aw_in "$ALICE_DIR" id team accept-invite "$alice_token" --alias alice --global --json
run_success "alice init" run_aw_in "$ALICE_DIR" init --url "$ALPHA_URL" --alias alice --do-not-touch-agents-md

capture_success ann_create "ann_create" run_aw_in "$ANN_DIR" id create --name ann --domain alpha.test.local --registry "$AWID_URL" --skip-dns-verify --json
ANN_DID_AW="$(echo "$ann_create" | jq_field did_aw)"
assert_not_empty "ann did_aw" "$ANN_DID_AW"
capture_success ann_invite "ann_invite" run_aw_in "$ALICE_DIR" id team invite --team alpha --namespace alpha.test.local --global --json
ann_token="$(echo "$ann_invite" | jq_field token)"
run_success "ann accept invite" run_aw_in "$ANN_DIR" id team accept-invite "$ann_token" --alias ann --global --json
run_success "ann init" run_aw_in "$ANN_DIR" init --url "$ALPHA_URL" --alias ann --do-not-touch-agents-md

capture_success ned_create "ned_create" run_aw_in "$NED_DIR" id create --name ned --domain alpha.test.local --registry "$AWID_URL" --skip-dns-verify --json
NED_DID_AW="$(echo "$ned_create" | jq_field did_aw)"
assert_not_empty "ned did_aw" "$NED_DID_AW"
capture_success ned_invite "ned_invite" run_aw_in "$ALICE_DIR" id team invite --team alpha --namespace alpha.test.local --global --json
ned_token="$(echo "$ned_invite" | jq_field token)"
run_success "ned accept invite" run_aw_in "$NED_DIR" id team accept-invite "$ned_token" --alias ned --global --json
run_success "ned init" run_aw_in "$NED_DIR" init --url "$ALPHA_URL" --alias ned --do-not-touch-agents-md

capture_success bob_create "bob_create" run_aw_in "$BOB_DIR" id create --name bob --domain beta.test.local --registry "$AWID_URL" --skip-dns-verify --json
BOB_DID_AW="$(echo "$bob_create" | jq_field did_aw)"
BOB_DID_KEY="$(echo "$bob_create" | jq_field did_key)"
assert_not_empty "bob did_aw" "$BOB_DID_AW"
assert_not_empty "bob did_key" "$BOB_DID_KEY"
capture_success beta_team "beta_team" run_aw_in "$BOB_DIR" id team create --name beta --namespace beta.test.local --registry "$AWID_URL" --json
assert_eq "beta team id" "beta:beta.test.local" "$(echo "$beta_team" | jq_field team_id)"
capture_success bob_invite "bob_invite" run_aw_in "$BOB_DIR" id team invite --team beta --namespace beta.test.local --global --json
bob_token="$(echo "$bob_invite" | jq_field token)"
run_success "bob accept invite" run_aw_in "$BOB_DIR" id team accept-invite "$bob_token" --alias bob --global --json
run_success "bob init" run_aw_in "$BOB_DIR" init --url "$BETA_URL" --alias bob --do-not-touch-agents-md

capture_success dave_invite "dave_invite" run_aw_in "$BOB_DIR" id team invite --team beta --namespace beta.test.local --json
dave_token="$(echo "$dave_invite" | jq_field token)"
run_success "dave accept invite" run_aw_in "$DAVE_DIR" id team accept-invite "$dave_token" --alias dave --json
run_success "dave init" run_aw_in "$DAVE_DIR" init --url "$BETA_URL" --alias dave --do-not-touch-agents-md
capture_success dave_whoami "dave_whoami" run_aw_in "$DAVE_DIR" whoami --json
DAVE_DID_KEY="$(echo "$dave_whoami" | jq_field did)"
assert_not_empty "dave local did_key" "$DAVE_DID_KEY"

capture_success charlie_create "charlie_create" run_aw_in "$CHARLIE_DIR" id create --name charlie --domain gamma.test.local --registry "$AWID_URL" --skip-dns-verify --json
assert_not_empty "charlie did_aw" "$(echo "$charlie_create" | jq_field did_aw)"

set_namespace_delivery_origin "$ALICE_DIR" "alpha" "alpha.test.local" "$ALPHA_ORIGIN"
set_namespace_delivery_origin "$BOB_DIR" "beta" "beta.test.local" "$BETA_ORIGIN"
capture_success alice_e2ee_setup "alice_e2ee_setup" run_aw_in "$ALICE_DIR" id encryption-key setup --json
assert_not_empty "alice federation e2ee key id" "$(echo "$alice_e2ee_setup" | jq_field key_id)"
capture_success bob_e2ee_setup "bob_e2ee_setup" run_aw_in "$BOB_DIR" id encryption-key setup --json
assert_not_empty "bob federation e2ee key id" "$(echo "$bob_e2ee_setup" | jq_field key_id)"
capture_success dave_e2ee_setup "dave_e2ee_setup" run_aw_in "$DAVE_DIR" id encryption-key setup --json
assert_not_empty "dave local-only federation e2ee key id" "$(echo "$dave_e2ee_setup" | jq_field key_id)"
echo ""

echo "=== Phase 3: Same-server local alias remains local ==="
run_success "same-server local mail send" run_aw_in "$ALICE_DIR" mail send --to ann --subject "Local alias e2e" --body "hello local ann"
capture_success ann_inbox "ann_inbox" run_aw_in "$ANN_DIR" mail inbox --json --show-all
ann_local_count="$(echo "$ann_inbox" | json_count_matching subject "Local alias e2e")"
assert_eq "same-server local mail delivered" "1" "$ann_local_count"
run_success "same-server local chat send" run_aw_in "$ALICE_DIR" chat send-and-leave ann "hello local chat ann"
capture_success ann_chat "ann_chat" run_aw_in "$ANN_DIR" chat history alice --json
ann_chat_count="$(echo "$ann_chat" | json_count_matching body "hello local chat ann")"
assert_eq "same-server local chat delivered" "1" "$ann_chat_count"
echo ""

echo "=== Phase 4b: E2E cross-server mail routes ciphertext and clients decrypt ==="
fed_e2ee_subject="FED_E2EE_SUBJECT_SENTINEL_260526"
fed_e2ee_body="FED_E2EE_BODY_SENTINEL_260526"
if fed_e2ee_out="$(run_aw_in "$ALICE_DIR" mail send \
  --to-address beta.test.local/bob \
  --subject "$fed_e2ee_subject" \
  --body "$fed_e2ee_body" \
  --e2ee \
  --json 2>&1)"; then
  fed_e2ee_exit=0
else
  fed_e2ee_exit=$?
fi
assert_eq "federated e2ee mail send exit" "0" "$fed_e2ee_exit"
if [[ "$fed_e2ee_exit" != "0" ]]; then
  echo "$fed_e2ee_out"
fi
fed_e2ee_message_id="$(echo "$fed_e2ee_out" | jq_field message_id)"
fed_e2ee_conversation_id="$(echo "$fed_e2ee_out" | jq_field conversation_id)"
assert_not_empty "federated e2ee message id" "$fed_e2ee_message_id"
assert_not_empty "federated e2ee conversation id" "$fed_e2ee_conversation_id"
if bob_e2ee_inbox="$(run_aw_in "$BOB_DIR" mail inbox --json --show-all 2>&1)"; then
  bob_e2ee_inbox_exit=0
else
  bob_e2ee_inbox_exit=$?
fi
assert_eq "bob federated e2ee inbox exit" "0" "$bob_e2ee_inbox_exit"
if [[ "$bob_e2ee_inbox_exit" != "0" ]]; then
  echo "$bob_e2ee_inbox"
fi
bob_e2ee_body="$(echo "$bob_e2ee_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')==cid), ''))" "$fed_e2ee_conversation_id" 2>/dev/null || echo "")"
assert_eq "bob decrypts federated e2ee mail" "$fed_e2ee_body" "$bob_e2ee_body"
if alice_e2ee_sent="$(run_aw_in "$ALICE_DIR" mail show --conversation-id "$fed_e2ee_conversation_id" --json 2>&1)"; then
  alice_e2ee_sent_exit=0
else
  alice_e2ee_sent_exit=$?
fi
assert_eq "alice federated e2ee sent-show exit" "0" "$alice_e2ee_sent_exit"
if [[ "$alice_e2ee_sent_exit" != "0" ]]; then
  echo "$alice_e2ee_sent"
fi
alice_e2ee_self_copy="$(echo "$alice_e2ee_sent" | python3 -c "import sys,json; body=sys.argv[1]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('body')==body), ''))" "$fed_e2ee_body" 2>/dev/null || echo "")"
assert_eq "alice decrypts federated sender self-copy" "$fed_e2ee_body" "$alice_e2ee_self_copy"
fed_e2ee_reply_body="FED_E2EE_REPLY_BODY_SENTINEL_260526"
if fed_e2ee_reply_out="$(run_aw_in "$BOB_DIR" mail send \
  --conversation-id "$fed_e2ee_conversation_id" \
  --subject "FED_E2EE_REPLY_SUBJECT_SENTINEL_260526" \
  --body "$fed_e2ee_reply_body" \
  --e2ee 2>&1)"; then
  fed_e2ee_reply_exit=0
else
  fed_e2ee_reply_exit=$?
fi
assert_eq "federated e2ee reply send exit" "0" "$fed_e2ee_reply_exit"
if [[ "$fed_e2ee_reply_exit" != "0" ]]; then
  echo "$fed_e2ee_reply_out"
fi
if alice_e2ee_reply_inbox="$(run_aw_in "$ALICE_DIR" mail inbox --json --show-all 2>&1)"; then
  alice_e2ee_reply_inbox_exit=0
else
  alice_e2ee_reply_inbox_exit=$?
fi
assert_eq "alice federated e2ee reply inbox exit" "0" "$alice_e2ee_reply_inbox_exit"
if [[ "$alice_e2ee_reply_inbox_exit" != "0" ]]; then
  echo "$alice_e2ee_reply_inbox"
fi
alice_e2ee_reply_body="$(echo "$alice_e2ee_reply_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; body=sys.argv[2]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')==cid and m.get('body')==body), ''))" "$fed_e2ee_conversation_id" "$fed_e2ee_reply_body" 2>/dev/null || echo "")"
assert_eq "alice decrypts federated e2ee reply" "$fed_e2ee_reply_body" "$alice_e2ee_reply_body"
fed_e2ee_alpha_plaintext_count="$(psql_scalar "postgres-alpha" "SELECT COUNT(*) FROM aweb.messages WHERE COALESCE(subject, '') LIKE '%FED_E2EE_%' OR COALESCE(body, '') LIKE '%FED_E2EE_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_%';")"
fed_e2ee_beta_plaintext_count="$(psql_scalar "postgres-beta" "SELECT COUNT(*) FROM aweb.messages WHERE COALESCE(subject, '') LIKE '%FED_E2EE_%' OR COALESCE(body, '') LIKE '%FED_E2EE_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_%';")"
assert_eq "federated e2ee plaintext absent from alpha DB" "0" "$fed_e2ee_alpha_plaintext_count"
assert_eq "federated e2ee plaintext absent from beta DB" "0" "$fed_e2ee_beta_plaintext_count"
echo ""

echo "=== Phase 4b.1: E2E cross-server local-only sender replies via learned assertion ==="
fed_local_subject="FED_E2EE_LOCAL_ONLY_SUBJECT_SENTINEL_260526"
fed_local_body="FED_E2EE_LOCAL_ONLY_BODY_SENTINEL_260526"
if fed_local_out="$(run_aw_in "$DAVE_DIR" mail send \
  --to-address alpha.test.local/alice \
  --subject "$fed_local_subject" \
  --body "$fed_local_body" \
  --e2ee \
  --json 2>&1)"; then
  fed_local_exit=0
else
  fed_local_exit=$?
fi
assert_eq "local-only federated e2ee mail send exit" "0" "$fed_local_exit"
if [[ "$fed_local_exit" != "0" ]]; then
  echo "$fed_local_out"
fi
fed_local_conversation_id="$(echo "$fed_local_out" | jq_field conversation_id)"
assert_not_empty "local-only federated e2ee conversation id" "$fed_local_conversation_id"
capture_success alice_local_inbox "alice_local_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
alice_local_body="$(echo "$alice_local_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; body=sys.argv[2]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')==cid and m.get('body')==body), ''))" "$fed_local_conversation_id" "$fed_local_body" 2>/dev/null || echo "")"
assert_eq "alice decrypts local-only federated e2ee mail" "$fed_local_body" "$alice_local_body"
fed_local_reply_body="FED_E2EE_LOCAL_ONLY_REPLY_SENTINEL_260526"
if fed_local_reply_out="$(run_aw_in "$ALICE_DIR" mail send \
  --conversation-id "$fed_local_conversation_id" \
  --subject "FED_E2EE_LOCAL_ONLY_REPLY_SUBJECT_SENTINEL_260526" \
  --body "$fed_local_reply_body" \
  --e2ee 2>&1)"; then
  fed_local_reply_exit=0
else
  fed_local_reply_exit=$?
fi
assert_eq "local-only federated e2ee learned-key reply send exit" "0" "$fed_local_reply_exit"
if [[ "$fed_local_reply_exit" != "0" ]]; then
  echo "$fed_local_reply_out"
fi
capture_success dave_local_reply_inbox "dave_local_reply_inbox" run_aw_in "$DAVE_DIR" mail inbox --json --show-all
dave_local_reply_body="$(echo "$dave_local_reply_inbox" | python3 -c "import sys,json; cid=sys.argv[1]; body=sys.argv[2]; msgs=json.load(sys.stdin).get('messages',[]); print(next((m.get('body','') for m in msgs if m.get('conversation_id')==cid and m.get('body')==body), ''))" "$fed_local_conversation_id" "$fed_local_reply_body" 2>/dev/null || echo "")"
assert_eq "dave decrypts learned-key e2ee mail reply" "$fed_local_reply_body" "$dave_local_reply_body"
fed_local_plaintext_count="$(psql_scalar "postgres-alpha" "SELECT COUNT(*) FROM aweb.messages WHERE COALESCE(subject, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(body, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_%';")"
assert_eq "local-only e2ee mail plaintext absent from alpha DB" "0" "$fed_local_plaintext_count"
fed_local_beta_plaintext_count="$(psql_scalar "postgres-beta" "SELECT COUNT(*) FROM aweb.messages WHERE COALESCE(subject, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(body, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_LOCAL_ONLY_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_%';")"
assert_eq "local-only e2ee mail plaintext absent from beta DB" "0" "$fed_local_beta_plaintext_count"
echo ""

echo "=== Phase 4c: E2E cross-server chat routes ciphertext and clients decrypt ==="
fed_e2ee_chat_body="FED_E2EE_CHAT_BODY_SENTINEL_260526"
if fed_e2ee_chat_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave beta.test.local/bob \
  "$fed_e2ee_chat_body" \
  --start-conversation \
  --e2ee 2>&1)"; then
  fed_e2ee_chat_exit=0
else
  fed_e2ee_chat_exit=$?
fi
assert_eq "federated e2ee chat send exit" "0" "$fed_e2ee_chat_exit"
if [[ "$fed_e2ee_chat_exit" != "0" ]]; then
  echo "$fed_e2ee_chat_out"
fi
if bob_e2ee_chat="$(run_aw_in "$BOB_DIR" chat history alpha.test.local/alice --json 2>&1)"; then
  bob_e2ee_chat_exit=0
else
  bob_e2ee_chat_exit=$?
fi
assert_eq "bob federated e2ee chat history exit" "0" "$bob_e2ee_chat_exit"
if [[ "$bob_e2ee_chat_exit" != "0" ]]; then
  echo "$bob_e2ee_chat"
fi
bob_e2ee_chat_body="$(echo "$bob_e2ee_chat" | json_count_matching body "$fed_e2ee_chat_body")"
assert_eq "bob decrypts federated e2ee chat" "1" "$bob_e2ee_chat_body"
if alice_e2ee_chat="$(run_aw_in "$ALICE_DIR" chat history beta.test.local/bob --json 2>&1)"; then
  alice_e2ee_chat_exit=0
else
  alice_e2ee_chat_exit=$?
fi
assert_eq "alice federated e2ee chat sent-history exit" "0" "$alice_e2ee_chat_exit"
if [[ "$alice_e2ee_chat_exit" != "0" ]]; then
  echo "$alice_e2ee_chat"
fi
alice_e2ee_chat_body="$(echo "$alice_e2ee_chat" | json_count_matching body "$fed_e2ee_chat_body")"
assert_eq "alice decrypts federated e2ee chat sender self-copy" "1" "$alice_e2ee_chat_body"
fed_e2ee_chat_reply_body="FED_E2EE_CHAT_REPLY_SENTINEL_260526"
if fed_e2ee_chat_reply_out="$(run_aw_in "$BOB_DIR" chat send-and-leave alpha.test.local/alice \
  "$fed_e2ee_chat_reply_body" \
  --e2ee 2>&1)"; then
  fed_e2ee_chat_reply_exit=0
else
  fed_e2ee_chat_reply_exit=$?
fi
assert_eq "federated e2ee chat reply send exit" "0" "$fed_e2ee_chat_reply_exit"
if [[ "$fed_e2ee_chat_reply_exit" != "0" ]]; then
  echo "$fed_e2ee_chat_reply_out"
fi
capture_success alice_e2ee_chat_reply "alice_e2ee_chat_reply" run_aw_in "$ALICE_DIR" chat history beta.test.local/bob --json
alice_e2ee_chat_reply_count="$(echo "$alice_e2ee_chat_reply" | json_count_matching body "$fed_e2ee_chat_reply_body")"
assert_eq "alice decrypts federated e2ee chat reply" "1" "$alice_e2ee_chat_reply_count"
fed_e2ee_chat_alpha_plaintext_count="$(psql_scalar "postgres-alpha" "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_CHAT_%';")"
fed_e2ee_chat_beta_plaintext_count="$(psql_scalar "postgres-beta" "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_CHAT_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_CHAT_%';")"
assert_eq "federated e2ee chat plaintext absent from alpha DB" "0" "$fed_e2ee_chat_alpha_plaintext_count"
assert_eq "federated e2ee chat plaintext absent from beta DB" "0" "$fed_e2ee_chat_beta_plaintext_count"
echo ""

echo "=== Phase 4c.1: E2E cross-server local-only chat reply via learned assertion ==="
fed_local_chat_body="FED_E2EE_LOCAL_ONLY_CHAT_SENTINEL_260526"
if fed_local_chat_out="$(run_aw_in "$DAVE_DIR" chat send-and-leave alpha.test.local/alice \
  "$fed_local_chat_body" \
  --start-conversation \
  --e2ee \
  --json 2>&1)"; then
  fed_local_chat_exit=0
else
  fed_local_chat_exit=$?
fi
assert_eq "local-only federated e2ee chat send exit" "0" "$fed_local_chat_exit"
if [[ "$fed_local_chat_exit" != "0" ]]; then
  echo "$fed_local_chat_out"
fi
fed_local_chat_session_id="$(echo "$fed_local_chat_out" | jq_field session_id)"
assert_not_empty "local-only federated e2ee chat session id" "$fed_local_chat_session_id"
capture_success alice_local_chat "alice_local_chat" run_aw_in "$ALICE_DIR" chat history --session-id "$fed_local_chat_session_id" --json
alice_local_chat_count="$(echo "$alice_local_chat" | json_count_matching body "$fed_local_chat_body")"
assert_eq "alice decrypts local-only federated e2ee chat" "1" "$alice_local_chat_count"
fed_local_chat_reply_body="FED_E2EE_LOCAL_ONLY_CHAT_REPLY_SENTINEL_260526"
if fed_local_chat_reply_out="$(run_aw_in "$ALICE_DIR" chat send-and-leave "$DAVE_DID_KEY" \
  "$fed_local_chat_reply_body" \
  --e2ee 2>&1)"; then
  fed_local_chat_reply_exit=0
else
  fed_local_chat_reply_exit=$?
fi
assert_eq "local-only federated e2ee chat learned-key reply send exit" "0" "$fed_local_chat_reply_exit"
if [[ "$fed_local_chat_reply_exit" != "0" ]]; then
  echo "$fed_local_chat_reply_out"
fi
capture_success dave_local_chat_reply "dave_local_chat_reply" run_aw_in "$DAVE_DIR" chat history --session-id "$fed_local_chat_session_id" --json
dave_local_chat_reply_count="$(echo "$dave_local_chat_reply" | json_count_matching body "$fed_local_chat_reply_body")"
assert_eq "dave decrypts learned-key e2ee chat reply" "1" "$dave_local_chat_reply_count"
fed_local_chat_plaintext_count="$(psql_scalar "postgres-alpha" "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%';")"
assert_eq "local-only e2ee chat plaintext absent from alpha DB" "0" "$fed_local_chat_plaintext_count"
fed_local_chat_beta_plaintext_count="$(psql_scalar "postgres-beta" "SELECT COUNT(*) FROM aweb.chat_messages WHERE COALESCE(body, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(signature, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(signed_payload, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_envelope::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_ciphertext, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%' OR COALESCE(encrypted_key_wraps::text, '') LIKE '%FED_E2EE_LOCAL_ONLY_CHAT_%';")"
assert_eq "local-only e2ee chat plaintext absent from beta DB" "0" "$fed_local_chat_beta_plaintext_count"
echo ""

echo "=== Phase 4: Public cross-server first contact and replies ==="
run_success "public federated mail send" run_aw_in "$ALICE_DIR" mail send --plaintext --to-address beta.test.local/bob --subject "Public federated mail" --body "hello beta bob"
capture_success bob_inbox "bob_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
public_mail_count="$(echo "$bob_inbox" | json_count_matching subject "Public federated mail")"
public_conversation_id="$(echo "$bob_inbox" | json_first_field_matching subject "Public federated mail" conversation_id)"
assert_eq "public federated mail delivered to beta" "1" "$public_mail_count"
assert_not_empty "public federated mail conversation id" "$public_conversation_id"

run_success "public federated reply send" run_aw_in "$BOB_DIR" mail send --plaintext --conversation-id "$public_conversation_id" --subject "Public federated reply" --body "reply from beta bob"
capture_success alice_inbox "alice_inbox" run_aw_in "$ALICE_DIR" mail inbox --json --show-all
reply_count="$(echo "$alice_inbox" | json_count_matching subject "Public federated reply")"
assert_eq "public federated mail reply delivered to alpha" "1" "$reply_count"

run_success "public federated chat send" run_aw_in "$ALICE_DIR" chat send-and-leave --plaintext beta.test.local/bob "public federated chat"
capture_success bob_chat "bob_chat" run_aw_in "$BOB_DIR" chat history alpha.test.local/alice --json
public_chat_count="$(echo "$bob_chat" | json_count_matching body "public federated chat")"
assert_eq "public federated chat delivered to beta" "1" "$public_chat_count"
capture_success public_chat_reply "public_chat_reply" run_aw_in "$BOB_DIR" chat send-and-leave --plaintext alpha.test.local/alice "public federated chat reply" --json
public_chat_reply_session_id="$(echo "$public_chat_reply" | jq_field session_id)"
assert_not_empty "public federated chat reply session id" "$public_chat_reply_session_id"
capture_success alice_chat "alice_chat" run_aw_in "$ALICE_DIR" chat history --session-id "$public_chat_reply_session_id" --json
chat_reply_count="$(echo "$alice_chat" | json_count_matching body "public federated chat reply")"
assert_eq "public federated chat reply delivered to alpha" "1" "$chat_reply_count"
echo ""

echo "=== Phase 5: Global federation fail-closed cases ==="
run_success "global federated mail send" run_aw_in "$NED_DIR" mail send --to-address beta.test.local/bob --subject "Global federated mail" --body "global sender reaches beta bob"
capture_success bob_global_inbox "bob_global_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
global_mail_count="$(echo "$bob_global_inbox" | json_count_matching subject "Global federated mail")"
assert_eq "global federated mail delivered" "1" "$global_mail_count"
run_success "global federated chat send" run_aw_in "$NED_DIR" chat send-and-leave beta.test.local/bob "global sender reaches beta chat"
capture_success bob_global_chat "bob_global_chat" run_aw_in "$BOB_DIR" chat history alpha.test.local/ned --json
global_chat_count="$(echo "$bob_global_chat" | json_count_matching body "global sender reaches beta chat")"
assert_eq "global federated chat delivered" "1" "$global_chat_count"

if missing_origin_out="$(run_aw_in "$ALICE_DIR" mail send --to-address gamma.test.local/charlie --subject "Missing origin" --body "must fail" 2>&1)"; then
  missing_origin_exit=0
else
  missing_origin_exit=$?
fi
if [[ "$missing_origin_exit" != "0" ]]; then
  echo "  PASS: identity without delivery origin fails closed"
  pass=$((pass + 1))
else
  echo "  FAIL: identity without delivery origin unexpectedly succeeded: ${missing_origin_out:0:180}"
  fail=$((fail + 1))
fi
echo ""

echo "=== Phase 6: Direct federation replay/idempotency ==="
replay_result="$(
  cd "$SERVER_DIR"
  ALICE_KEY="$ALICE_DIR/.aw/signing.key" \
  ALICE_DID_KEY="$ALICE_DID_KEY" \
  ALICE_DID_AW="$ALICE_DID_AW" \
  BOB_DID_KEY="$BOB_DID_KEY" \
  BOB_DID_AW="$BOB_DID_AW" \
  BETA_URL="$BETA_URL" \
  ALPHA_ORIGIN="$ALPHA_ORIGIN" \
  BETA_ORIGIN="$BETA_ORIGIN" \
  uv run python - <<'PY'
import base64
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4

from awid.signing import canonical_json_bytes, sign_message


def load_seed(path: str) -> bytes:
    text = open(path, "r", encoding="utf-8").read()
    body = "".join(line.strip() for line in text.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


seed = load_seed(os.environ["ALICE_KEY"])
message_id = str(uuid4())
conversation_id = str(uuid4())
timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
signed_fields = {
    "body": "replay body",
    "conversation_id": conversation_id,
    "from": "alpha.test.local/alice",
    "from_did": os.environ["ALICE_DID_KEY"],
    "from_stable_id": os.environ["ALICE_DID_AW"],
    "message_id": message_id,
    "subject": "Replay federated mail",
    "timestamp": timestamp,
    "to": "beta.test.local/bob",
    "to_did": os.environ["BOB_DID_KEY"],
    "to_stable_id": os.environ["BOB_DID_AW"],
    "type": "mail",
}
signed_payload = canonical_json_bytes(signed_fields).decode()
payload = {
    "envelope": {
        "version": 1,
        "type": "mail",
        "sender_did_aw": os.environ["ALICE_DID_AW"],
        "sender_current_did_key": os.environ["ALICE_DID_KEY"],
        "sender_address": "alpha.test.local/alice",
        "sender_delivery_origin": os.environ["ALPHA_ORIGIN"],
        "target_address": "beta.test.local/bob",
        "target_did_aw": os.environ["BOB_DID_AW"],
        "target_current_did_key": os.environ["BOB_DID_KEY"],
        "target_delivery_origin": os.environ["BETA_ORIGIN"],
        "body": "replay body",
        "message_id": message_id,
        "timestamp": timestamp,
        "signed_payload": signed_payload,
        "conversation_id": conversation_id,
        "subject": "Replay federated mail",
        "priority": "normal",
    },
    "signature": sign_message(seed, signed_payload.encode()),
}
body = json.dumps(payload).encode()
statuses = []
for _ in range(2):
    req = urllib.request.Request(
        os.environ["BETA_URL"] + "/v1/federation/messages",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            statuses.append(resp.status)
            resp.read()
    except urllib.error.HTTPError as exc:
        statuses.append(exc.code)
        exc.read()
print(",".join(str(status) for status in statuses))
PY
)"
assert_eq "direct federation replay returns stable success" "200,200" "$replay_result"
capture_success bob_replay_inbox "bob_replay_inbox" run_aw_in "$BOB_DIR" mail inbox --json --show-all
replay_count="$(echo "$bob_replay_inbox" | json_count_matching subject "Replay federated mail")"
assert_eq "direct federation replay stores one message" "1" "$replay_count"
echo ""
