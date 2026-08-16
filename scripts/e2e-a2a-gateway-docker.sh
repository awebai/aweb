#!/usr/bin/env bash
#
# End-to-end A2A gateway Docker journey.
#
# This is intentionally production-shaped:
#   1. Build the local aw CLI and A2A gateway image.
#   2. Start the real aweb + AWID Docker Compose backend.
#   3. Create real global identities and a real team against that backend.
#   4. Run the A2A gateway container.
#   5. Drive SendMessage -> real aweb mail -> agent reply -> GetTask.

set -euo pipefail

canonicalize_dir() {
  local dir="$1"
  bash -c 'cd "$1" && pwd -P' _ "$dir"
}

make_temp_dir() {
  local prefix="$1"
  local dir
  dir="$(mktemp -d "$DOCKER_BIND_ROOT/${prefix}.XXXXXX")"
  canonicalize_dir "$dir"
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CLI_DIR="$REPO_ROOT/cli/go"
COMPOSE_FILE="$REPO_ROOT/server/docker-compose.yml"
DOCKER_BIND_ROOT="${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}"
[[ "$DOCKER_BIND_ROOT" == /* && -d "$DOCKER_BIND_ROOT" ]] \
  || { echo "AWEB_DOCKER_BIND_ROOT must be an existing absolute directory" >&2; exit 2; }
DOCKER_PUBLISHED_HOST="${AWEB_DOCKER_PUBLISHED_HOST:-127.0.0.1}"
case "$DOCKER_PUBLISHED_HOST" in
  127.0.0.1|localhost) DOCKER_PUBLISH_BIND=127.0.0.1 ;;
  aweb-docker.test) DOCKER_PUBLISH_BIND=0.0.0.0 ;;
  *) echo "unsupported AWEB_DOCKER_PUBLISHED_HOST: $DOCKER_PUBLISHED_HOST" >&2; exit 2 ;;
esac

PROJECT="a2agw-e2e-$$"
TMP_ROOT="$(make_temp_dir a2a-gw-e2e)"
E2E_HOME="$TMP_ROOT/home"
E2E_CWD="$TMP_ROOT/cwd"
GATEWAY_DIR="$E2E_CWD/gateway"
PERSONAL_DIR="$E2E_CWD/personal"
CONFIG_PATH="$TMP_ROOT/gateway.yaml"
ENV_FILE="$TMP_ROOT/compose.env"
GATEWAY_CONTAINER="a2a-gw-e2e-$$"
GATEWAY_IMAGE="a2a-gateway:e2e-$$"

mkdir -p "$E2E_HOME/.config/aw" "$GATEWAY_DIR" "$PERSONAL_DIR" "$TMP_ROOT/audit"

AWEB_PORT="${AWEB_A2A_E2E_PORT:-$(free_port)}"
AWID_PORT="${AWID_A2A_E2E_PORT:-$(free_port)}"
REDIS_PORT="${AWEB_A2A_E2E_REDIS:-$(free_port)}"
PG_PORT="${AWEB_A2A_E2E_PG:-$(free_port)}"
GATEWAY_PORT="${A2A_GW_E2E_PORT:-$(free_port)}"

AWEB_URL="http://$DOCKER_PUBLISHED_HOST:$AWEB_PORT"
AWID_URL="http://$DOCKER_PUBLISHED_HOST:$AWID_PORT"
AWEB_DOCKER_URL="http://host.docker.internal:$AWEB_PORT"
AWID_DOCKER_URL="http://host.docker.internal:$AWID_PORT"
GATEWAY_URL="http://$DOCKER_PUBLISHED_HOST:$GATEWAY_PORT"

pass=0
fail=0

cleanup() {
  local status=$?
  echo ""
  echo "--- Cleanup ---"
  if [[ $fail -gt 0 || $status -ne 0 ]]; then
    if [[ -f "$TMP_ROOT/audit/a2a.jsonl" ]]; then
      echo "--- A2A gateway audit ---"
      cat "$TMP_ROOT/audit/a2a.jsonl" || true
    fi
    docker logs "$GATEWAY_CONTAINER" 2>/dev/null || true
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --no-color aweb awid 2>/dev/null || true
  fi
  docker rm -f "$GATEWAY_CONTAINER" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down -v --rmi local >/dev/null 2>&1 || true
  docker image rm "$GATEWAY_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$TMP_ROOT"
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
  if grep -q -- "$needle" <<<"$haystack"; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected '$needle', got: ${haystack:0:180})"
    fail=$((fail + 1))
  fi
}

json_field() {
  local field="$1"
  python3 -c '
import json, sys
text = sys.stdin.read()
field = sys.argv[1]
decoder = json.JSONDecoder()
for idx, char in enumerate(text):
    if char != "{":
        continue
    try:
        data, _ = decoder.raw_decode(text[idx:])
    except json.JSONDecodeError:
        continue
    if isinstance(data, dict) and field in data:
        print(data.get(field, ""))
        break
' "$field"
}

run_aw_in() {
  local workdir="$1"
  shift
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --add-host=host.docker.internal:host-gateway \
    -e HOME="$E2E_HOME" \
    -e AW_CONFIG_PATH="$E2E_HOME/.config/aw/config.yaml" \
    -e AWID_REGISTRY_URL="$AWID_DOCKER_URL" \
    -e AWID_SKIP_DNS_VERIFY=1 \
    -e AW_NO_UPDATE_CHECK=1 \
    -v "$TMP_ROOT:$TMP_ROOT" \
    -w "$workdir" \
    "$GATEWAY_IMAGE" /aw "$@"
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
  if [[ "$status" != "0" ]]; then
    echo "$output"
  fi
  printf -v "$output_var" "%s" "$output"
}

wait_for_http() {
  local label="$1" url="$2"
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  PASS: $label"
      pass=$((pass + 1))
      return 0
    fi
    sleep 1
  done
  echo "  FAIL: $label (timed out waiting for $url)"
  fail=$((fail + 1))
  return 1
}

rpc_post() {
  local body="$1"
  local token_header=()
  if [[ -n "${A2A_TASK_TOKEN:-}" ]]; then
    token_header=(-H "X-A2A-Task-Token: $A2A_TASK_TOKEN")
  fi
  curl -fsS \
    -H 'Content-Type: application/json' \
    -H 'X-A2A-Caller-ID: docker-e2e' \
    -H 'X-Request-ID: docker-e2e-request' \
    "${token_header[@]}" \
    -d "$body" \
    "$GATEWAY_URL/a2a/agents/personal/rpc"
}

echo "=== Build local binaries and gateway image ==="
(
  cd "$CLI_DIR"
  CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=e2e -X main.releaseTag=a2a-gw-e2e -X main.commit=$(git -C "$REPO_ROOT" rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o "$TMP_ROOT/aw" ./cmd/aw
  CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=e2e -X main.releaseTag=a2a-gw-e2e -X main.commit=$(git -C "$REPO_ROOT" rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o "$TMP_ROOT/aweb-a2a-gw" ./cmd/aweb-a2a-gw
)
cat > "$TMP_ROOT/Dockerfile.a2a-gw.e2e" <<'EOF'
FROM scratch
COPY aw /aw
COPY aweb-a2a-gw /aweb-a2a-gw
EOF
docker build --load -f "$TMP_ROOT/Dockerfile.a2a-gw.e2e" -t "$GATEWAY_IMAGE" "$TMP_ROOT"
assert_eq "gateway image built" "0" "0"
echo ""

echo "=== Start real aweb + AWID backend in Docker ==="
cat > "$ENV_FILE" <<EOF
POSTGRES_USER=aweb
POSTGRES_PASSWORD=aweb-a2a-gateway-e2e
POSTGRES_DB=aweb
AWEB_PORT=$AWEB_PORT
AWID_PORT=$AWID_PORT
REDIS_PORT=$REDIS_PORT
PG_PORT=$PG_PORT
AWEB_PUBLIC_ORIGIN=$AWEB_DOCKER_URL
AWID_REGISTRY_URL=http://awid:8010
AWID_PUBLIC_REGISTRY_URL=$AWID_DOCKER_URL
AWEB_LOG_JSON=true
AWID_LOG_JSON=true
AWID_RATE_LIMIT_BACKEND=redis
AWID_RATE_LIMIT_DISABLED=1
AWID_SKIP_DNS_VERIFY=1
EOF
docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up --build -d
wait_for_http "aweb health" "$AWEB_URL/health"
wait_for_http "awid health" "$AWID_URL/health"
echo ""

echo "=== Create real AWID identities and team ==="
capture_success gateway_create "gateway id create" run_aw_in "$GATEWAY_DIR" id create \
  --name gateway \
  --domain a2a.test.local \
  --registry "$AWID_DOCKER_URL" \
  --skip-dns-verify \
  --json
capture_success personal_create "personal id create" run_aw_in "$PERSONAL_DIR" id create \
  --name personal \
  --domain a2a.test.local \
  --registry "$AWID_DOCKER_URL" \
  --skip-dns-verify \
  --json
gateway_address="$(echo "$gateway_create" | json_field address)"
personal_address="$(echo "$personal_create" | json_field address)"
assert_eq "gateway address" "a2a.test.local/gateway" "$gateway_address"
assert_eq "personal address" "a2a.test.local/personal" "$personal_address"

capture_success team_create "team create" run_aw_in "$GATEWAY_DIR" id team create \
  --name demo \
  --namespace a2a.test.local \
  --registry "$AWID_DOCKER_URL" \
  --json
team_id="$(echo "$team_create" | json_field team_id)"
assert_eq "team id" "demo:a2a.test.local" "$team_id"

capture_success gateway_invite "gateway invite" run_aw_in "$GATEWAY_DIR" id team invite \
  --team demo \
  --namespace a2a.test.local \
  --global \
  --json
gateway_token="$(echo "$gateway_invite" | json_field token)"
capture_success gateway_accept "gateway accept invite" run_aw_in "$GATEWAY_DIR" id team accept-invite "$gateway_token" \
  --alias gateway \
  --global \
  --json
capture_success personal_invite "personal invite" run_aw_in "$GATEWAY_DIR" id team invite \
  --team demo \
  --namespace a2a.test.local \
  --global \
  --json
personal_token="$(echo "$personal_invite" | json_field token)"
capture_success personal_accept "personal accept invite" run_aw_in "$PERSONAL_DIR" id team accept-invite "$personal_token" \
  --alias personal \
  --global \
  --json
capture_success gateway_init "gateway aw init" run_aw_in "$GATEWAY_DIR" init --url "$AWEB_DOCKER_URL"
capture_success personal_init "personal aw init" run_aw_in "$PERSONAL_DIR" init --url "$AWEB_DOCKER_URL"
capture_success personal_open "personal inbound open" run_aw_in "$PERSONAL_DIR" inbound-mode open --json
echo ""

echo "=== Start A2A gateway container ==="
python3 - "$GATEWAY_DIR" "$AWEB_URL" "$AWEB_DOCKER_URL" "$AWID_URL" "$AWID_DOCKER_URL" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1]) / ".aw"
replacements = {
    sys.argv[2]: sys.argv[3],
    sys.argv[4]: sys.argv[5],
}
for path in root.rglob("*"):
    if not path.is_file():
        continue
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        continue
    updated = text
    for old, new in replacements.items():
        updated = updated.replace(old, new)
    if updated != text:
        path.write_text(updated)
PY

cat > "$CONFIG_PATH" <<EOF
listen: ":8080"
host: "a2a.test.local"
workspace_dir: "/workspace"
team_id: "demo:a2a.test.local"
root_card_mode: "router"
gateway_identity: "a2a.test.local/gateway"
registry_url: "$AWID_DOCKER_URL"
poll_interval: "250ms"
poll_timeout: "20s"
require_verified_replies: true
allow_unverified_local_reply: false
audit:
  jsonl: "/audit/a2a.jsonl"

router_card:
  name: "A2A Docker Test Gateway"
  description: "Docker e2e router card for real aweb backend testing."
  provider:
    organization: "aweb"
    url: "https://aweb.ai"
  version: "1.0.0"
  default_input_modes: ["text/plain"]
  default_output_modes: ["text/plain"]
  skills:
    - id: "route-to-agent"
      name: "Route to test agent"
      description: "Routes A2A tasks to the configured test agent."
      tags: ["router"]

routes:
  - route_id: "personal"
    address: "a2a.test.local/personal"
    response_timeout: "20s"
    auth:
      mode: "none"
    limits:
      max_message_bytes: 65536
      rate_limit: "600/min"
      max_concurrent_tasks: 5
      task_ttl: "10m"
    card:
      name: "A2A Docker Personal"
      description: "Personal route backed by a real aweb agent in the Docker backend."
      provider:
        organization: "aweb"
        url: "https://aweb.ai"
      version: "1.0.0"
      default_input_modes: ["text/plain"]
      default_output_modes: ["text/plain"]
      skills:
        - id: "answer"
          name: "Answer test messages"
          description: "Replies to Docker e2e test tasks."
          tags: ["test"]
EOF

capture_success gateway_check "gateway config/workspace check" docker run --rm \
  --user "$(id -u):$(id -g)" \
  --add-host=host.docker.internal:host-gateway \
  -v "$GATEWAY_DIR:/workspace:ro" \
  -v "$CONFIG_PATH:/config/gateway.yaml:ro" \
  -v "$TMP_ROOT/audit:/audit" \
  "$GATEWAY_IMAGE" /aweb-a2a-gw -config /config/gateway.yaml -workspace-dir /workspace -check

docker run -d --rm \
  --name "$GATEWAY_CONTAINER" \
  --user "$(id -u):$(id -g)" \
  --add-host=host.docker.internal:host-gateway \
  -p "$DOCKER_PUBLISH_BIND:$GATEWAY_PORT:8080" \
  -v "$GATEWAY_DIR:/workspace:ro" \
  -v "$CONFIG_PATH:/config/gateway.yaml:ro" \
  -v "$TMP_ROOT/audit:/audit" \
  "$GATEWAY_IMAGE" /aweb-a2a-gw -config /config/gateway.yaml -listen 0.0.0.0:8080 >/dev/null
wait_for_http "gateway health" "$GATEWAY_URL/health"
gateway_health="$(curl -fsS "$GATEWAY_URL/health")"
gateway_health_status="$(echo "$gateway_health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')"
gateway_health_tag="$(echo "$gateway_health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("build",{}).get("release_tag",""))')"
gateway_health_registry="$(echo "$gateway_health" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("awid_registry",{}).get("reachable", False)).lower())')"
gateway_health_registry_compatible="$(echo "$gateway_health" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("awid_registry",{}).get("compatible", False)).lower())')"
gateway_health_registry_minimum="$(echo "$gateway_health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("awid_registry",{}).get("minimum_version",""))')"
gateway_health_registry_version="$(echo "$gateway_health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("awid_registry",{}).get("version",""))')"
assert_eq "gateway health status" "healthy" "$gateway_health_status"
assert_eq "gateway health release tag" "a2a-gw-e2e" "$gateway_health_tag"
assert_eq "gateway health reaches awid registry" "true" "$gateway_health_registry"
assert_eq "gateway health awid registry compatible" "true" "$gateway_health_registry_compatible"
assert_eq "gateway health awid registry minimum" "0.5.11" "$gateway_health_registry_minimum"
assert_not_empty "gateway health awid registry version" "$gateway_health_registry_version"

root_card="$(curl -fsS "$GATEWAY_URL/.well-known/agent-card.json")"
personal_card="$(curl -fsS "$GATEWAY_URL/a2a/agents/personal/agent-card.json")"
assert_contains "root router card served" "$root_card" "A2A Docker Test Gateway"
assert_contains "per-address card served" "$personal_card" "A2A Docker Personal"
echo ""

echo "=== Send A2A task through gateway and real aweb mail ==="
send_payload='{"jsonrpc":"2.0","id":"send-1","method":"SendMessage","params":{"message":{"messageId":"msg-1","contextId":"ctx-1","role":"ROLE_USER","parts":[{"text":"Please complete the Docker A2A journey.","mediaType":"text/plain"}]},"configuration":{"returnImmediately":true}}}'
send_resp="$(rpc_post "$send_payload")"
send_error="$(echo "$send_resp" | python3 -c 'import json,sys; data=json.load(sys.stdin); err=data.get("error") or {}; print(err.get("message",""))')"
if [[ -n "$send_error" ]]; then
  echo "  FAIL: SendMessage RPC error: $send_error"
  echo "  response: $send_resp"
  fail=$((fail + 1))
  exit 1
fi
task_id="$(echo "$send_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["task"]["id"])')"
task_token="$(echo "$send_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["task"]["metadata"]["task_bearer_token"])')"
initial_state="$(echo "$send_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["task"]["status"]["state"])')"
assert_not_empty "a2a task id" "$task_id"
assert_not_empty "a2a public task bearer token" "$task_token"
assert_eq "a2a send enters working state" "TASK_STATE_WORKING" "$initial_state"

conversation_id=""
last_inbox=""
for _ in $(seq 1 80); do
  inbox="$(run_aw_in "$PERSONAL_DIR" mail inbox --json --show-all 2>/dev/null || true)"
  last_inbox="$inbox"
  conversation_id="$(INBOX_JSON="$inbox" python3 - "$task_id" <<'PY' 2>/dev/null || true
import json, os, sys
task_id = sys.argv[1]
try:
    messages = json.loads(os.environ.get("INBOX_JSON", "{}")).get("messages", [])
except Exception:
    messages = []
for msg in messages:
    if task_id in json.dumps(msg, sort_keys=True):
        print(msg.get("conversation_id", ""))
        break
PY
)"
  if [[ -n "$conversation_id" ]]; then
    break
  fi
  sleep 0.5
done
assert_not_empty "personal received bridge mail conversation" "$conversation_id"
if [[ -z "$conversation_id" ]]; then
  echo "  inbox sample: ${last_inbox:0:2400}"
  exit 1
fi

reply_body="$(cat <<EOF
\`\`\`a2a-reply
{"task_id":"$task_id","context_id":"ctx-1","state":"completed","text":"Docker A2A e2e completed through the real aweb backend."}
\`\`\`
EOF
)"
capture_success reply_send "personal sends a2a reply" run_aw_in "$PERSONAL_DIR" mail send \
  --plaintext \
  --conversation-id "$conversation_id" \
  --subject "A2A reply" \
  --body "$reply_body" \
  --json

completed_resp=""
completed_state=""
for _ in $(seq 1 80); do
  get_payload="{\"jsonrpc\":\"2.0\",\"id\":\"get-1\",\"method\":\"GetTask\",\"params\":{\"id\":\"$task_id\"}}"
  completed_resp="$(A2A_TASK_TOKEN="$task_token" rpc_post "$get_payload")"
  completed_state="$(echo "$completed_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["status"]["state"])' 2>/dev/null || true)"
  if [[ "$completed_state" == "TASK_STATE_COMPLETED" ]]; then
    break
  fi
  sleep 0.5
done
assert_eq "a2a task completes from real mail reply" "TASK_STATE_COMPLETED" "$completed_state"
if [[ "$completed_state" != "TASK_STATE_COMPLETED" ]]; then
  echo "  GetTask response: ${completed_resp:0:2400}"
  exit 1
fi
answer_text="$(echo "$completed_resp" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["result"]["artifacts"][0]["parts"][0]["text"])')"
assert_eq "a2a completed answer text" "Docker A2A e2e completed through the real aweb backend." "$answer_text"

list_payload='{"jsonrpc":"2.0","id":"list-1","method":"ListTasks","params":{"includeArtifacts":true}}'
list_resp="$(rpc_post "$list_payload")"
list_error_code="$(echo "$list_resp" | python3 -c 'import json,sys; data=json.load(sys.stdin); print((data.get("error") or {}).get("data", {}).get("code", ""))')"
assert_eq "anonymous ListTasks is disabled" "list_tasks_scope_required" "$list_error_code"
echo ""
