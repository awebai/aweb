#!/usr/bin/env bash
# Disposable two-AWID/two-aweb CLI mail+chat journey for foreign-domain discovery.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROJECT="${AWEB_CROSS_REGISTRY_PROJECT:-aweb-cross-reg-$RANDOM-$$}"
BIND_ROOT="${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}"
[[ "$BIND_ROOT" = /* && -d "$BIND_ROOT" ]] || { echo "AWEB_DOCKER_BIND_ROOT must be an existing absolute directory" >&2; exit 2; }
RUNTIME="$(mktemp -d "$BIND_ROOT/aweb-cross-reg.XXXXXX")"
COMPOSE_FILE="$RUNTIME/docker-compose.yml"
DNS_DIR="$RUNTIME/dns"
WORK_DIR="$RUNTIME/work"
AWID_A_PORT="${AWEB_CROSS_REGISTRY_AWID_A_PORT:-18510}"
AWID_B_PORT="${AWEB_CROSS_REGISTRY_AWID_B_PORT:-18520}"
AWEB_A_PORT="${AWEB_CROSS_REGISTRY_AWEB_A_PORT:-18530}"
AWEB_B_PORT="${AWEB_CROSS_REGISTRY_AWEB_B_PORT:-18540}"
PUBLISHED_HOST="${AWEB_DOCKER_PUBLISHED_HOST:-127.0.0.1}"
mkdir -p "$DNS_DIR" "$WORK_DIR/home" "$WORK_DIR/alice" "$WORK_DIR/bob"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ $status -ne 0 && -f "$COMPOSE_FILE" ]]; then
    compose logs --tail 120 --no-color federation-dns awid-a awid-b aweb-a aweb-b >&2 || true
  fi
  if [[ "${AWEB_CROSS_REGISTRY_KEEP:-0}" == "1" ]]; then
    echo "Keeping $PROJECT at $RUNTIME" >&2
    return "$status"
  fi
  if [[ -f "$COMPOSE_FILE" ]]; then
    compose down -v --rmi local --remove-orphans >/dev/null 2>&1 || status=1
    for kind in container volume network image; do
      case "$kind" in
        container) leftovers="$(docker ps -aq --filter label=com.docker.compose.project="$PROJECT")" ;;
        volume) leftovers="$(docker volume ls -q --filter label=com.docker.compose.project="$PROJECT")" ;;
        network) leftovers="$(docker network ls -q --filter label=com.docker.compose.project="$PROJECT")" ;;
        image) leftovers="$(docker images -q --filter label=com.docker.compose.project="$PROJECT")" ;;
      esac
      if [[ -n "$leftovers" ]]; then
        echo "teardown left $kind resources for $PROJECT" >&2
        status=1
      fi
    done
  fi
  rm -rf "$RUNTIME"
  exit "$status"
}
trap cleanup EXIT

[[ "$PROJECT" =~ ^aweb-cross-reg-[a-zA-Z0-9_-]+$ ]] || { echo "invalid Compose project: $PROJECT" >&2; exit 2; }
case "$PUBLISHED_HOST" in
  127.0.0.1|aweb-docker.test) ;;
  *) echo "unsupported AWEB_DOCKER_PUBLISHED_HOST: $PUBLISHED_HOST" >&2; exit 2 ;;
esac
for port in "$AWID_A_PORT" "$AWID_B_PORT" "$AWEB_A_PORT" "$AWEB_B_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 )) || { echo "invalid host port: $port" >&2; exit 2; }
done
[[ "$(printf '%s\n' "$AWID_A_PORT" "$AWID_B_PORT" "$AWEB_A_PORT" "$AWEB_B_PORT" | sort -u | wc -l | tr -d ' ')" == "4" ]] \
  || { echo "cross-registry host ports must be distinct" >&2; exit 2; }

wait_health() {
  local label="$1" url="$2" service="$3"
  for _ in $(seq 1 90); do
    if curl -fsS "$url/health" >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  compose logs --tail 80 --no-color "$service" >&2 || true
  echo "$label did not become healthy" >&2
  return 1
}

json_field() {
  local field="$1"
  python3 -c '
import json,sys
text=sys.stdin.read(); start=text.find("{")
if start < 0: raise SystemExit("missing JSON object")
value=json.loads(text[start:])
for part in sys.argv[1].split("."):
    value=value.get(part, "") if isinstance(value, dict) else ""
print(value if value is not None else "")
' "$field"
}

run_cli() {
  local identity="$1"
  shift
  compose run --rm -T --no-deps -w "/work/$identity" cli "$@"
}

# who_json prints the identity's verified `aw who` result in a stable form,
# so later observations compare byte for byte.
who_json() {
  run_cli "$1" who --json | python3 -c '
import json,sys
text=sys.stdin.read(); start=text.find("{")
if start < 0: raise SystemExit("missing JSON object")
value=json.loads(text[start:])
assert value["identity_valid"] is True and value["reason"] == "verified", value
print(json.dumps(value, sort_keys=True))
'
}

assert_inbox_message() {
  local json="$1" subject="$2" body="$3"
  printf '%s' "$json" | python3 -c '
import json,sys
subject,body=sys.argv[1:]
data=json.load(sys.stdin)
assert any(item.get("subject")==subject and item.get("body")==body for item in data.get("messages", [])), data
' "$subject" "$body"
}

assert_chat_message() {
  local json="$1" body="$2"
  printf '%s' "$json" | python3 -c '
import json,sys
body=sys.argv[1]; data=json.load(sys.stdin)
items=data.get("messages") or data.get("sessions") or []
assert any(item.get("body")==body for item in items), data
' "$body"
}

cat > "$DNS_DIR/Corefile" <<'EOF'
example.com:53 {
  errors
  file /zones/example.com.zone example.com { reload 1s }
}
example.net:53 {
  errors
  file /zones/example.net.zone example.net { reload 1s }
}
.:53 {
  errors
  forward . 127.0.0.11
}
EOF
cat > "$DNS_DIR/example.com.zone" <<'EOF'
$ORIGIN example.com.
$TTL 1
@ IN SOA ns.example.com. hostmaster.example.com. (1 1 1 1 1)
@ IN NS ns.example.com.
ns IN A 127.0.0.1
EOF
cat > "$DNS_DIR/example.net.zone" <<'EOF'
$ORIGIN example.net.
$TTL 1
@ IN SOA ns.example.net. hostmaster.example.net. (1 1 1 1 1)
@ IN NS ns.example.net.
ns IN A 127.0.0.1
EOF

cat > "$COMPOSE_FILE" <<EOF
services:
  federation-dns:
    image: coredns/coredns:1.11.3
    command: ["-conf", "/Corefile"]
    volumes:
      - "$DNS_DIR/Corefile:/Corefile:ro"
      - "$DNS_DIR:/zones:ro"
  postgres-a:
    image: postgres:16-alpine
    environment: {POSTGRES_USER: aweb, POSTGRES_PASSWORD: disposable, POSTGRES_DB: aweb}
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U aweb -d aweb"], interval: 2s, timeout: 2s, retries: 45}
  postgres-b:
    image: postgres:16-alpine
    environment: {POSTGRES_USER: aweb, POSTGRES_PASSWORD: disposable, POSTGRES_DB: aweb}
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U aweb -d aweb"], interval: 2s, timeout: 2s, retries: 45}
  redis-a:
    image: redis:7-alpine
    healthcheck: {test: ["CMD", "redis-cli", "ping"], interval: 2s, timeout: 2s, retries: 45}
  redis-b:
    image: redis:7-alpine
    healthcheck: {test: ["CMD", "redis-cli", "ping"], interval: 2s, timeout: 2s, retries: 45}
  awid-a:
    build: {context: "$ROOT", dockerfile: awid/Dockerfile}
    ports: ["$AWID_A_PORT:8010"]
    environment:
      AWID_DATABASE_URL: postgresql://aweb:disposable@postgres-a:5432/aweb
      AWID_REDIS_URL: redis://redis-a:6379/0
      AWID_DB_SCHEMA: awid
      AWID_HOST: 0.0.0.0
      AWID_PORT: 8010
      AWID_PUBLIC_ORIGINS: http://awid-a:8010
      AWID_RATE_LIMIT_DISABLED: "1"
      AWID_SERVICE_TOKEN: cross-registry-messaging-service-token-32-bytes
      AWID_ALLOW_INSECURE_DELIVERY_ORIGIN: "1"
      APP_ENV: development
    # FEDERATION_DNS_AWID_A
    depends_on:
      postgres-a: {condition: service_healthy}
      redis-a: {condition: service_healthy}
  awid-b:
    build: {context: "$ROOT", dockerfile: awid/Dockerfile}
    ports: ["$AWID_B_PORT:8010"]
    environment:
      AWID_DATABASE_URL: postgresql://aweb:disposable@postgres-b:5432/aweb
      AWID_REDIS_URL: redis://redis-b:6379/0
      AWID_DB_SCHEMA: awid
      AWID_HOST: 0.0.0.0
      AWID_PORT: 8010
      AWID_PUBLIC_ORIGINS: http://awid-b:8010
      AWID_RATE_LIMIT_DISABLED: "1"
      AWID_SERVICE_TOKEN: cross-registry-messaging-service-token-32-bytes
      AWID_ALLOW_INSECURE_DELIVERY_ORIGIN: "1"
      APP_ENV: development
    # FEDERATION_DNS_AWID_B
    depends_on:
      postgres-b: {condition: service_healthy}
      redis-b: {condition: service_healthy}
  aweb-a:
    build: {context: "$ROOT", dockerfile: server/Dockerfile}
    ports: ["$AWEB_A_PORT:8000"]
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:disposable@postgres-a:5432/aweb
      AWEB_REDIS_URL: redis://redis-a:6379/1
      AWID_REGISTRY_URL: http://awid-a:8010
      AWID_SERVICE_TOKEN: cross-registry-messaging-service-token-32-bytes
      AWEB_PUBLIC_ORIGIN: http://aweb-a:8000
      AWEB_HOST: 0.0.0.0
      AWEB_PORT: 8000
      AWEB_FEDERATION_TEST: "1"
      APP_ENV: development
    # FEDERATION_DNS_A
    depends_on:
      postgres-a: {condition: service_healthy}
      redis-a: {condition: service_healthy}
      awid-a: {condition: service_started}
      federation-dns: {condition: service_started}
  aweb-b:
    build: {context: "$ROOT", dockerfile: server/Dockerfile}
    ports: ["$AWEB_B_PORT:8000"]
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:disposable@postgres-b:5432/aweb
      AWEB_REDIS_URL: redis://redis-b:6379/1
      AWID_REGISTRY_URL: http://awid-b:8010
      AWID_SERVICE_TOKEN: cross-registry-messaging-service-token-32-bytes
      AWEB_PUBLIC_ORIGIN: http://aweb-b:8000
      AWEB_HOST: 0.0.0.0
      AWEB_PORT: 8000
      AWEB_FEDERATION_TEST: "1"
      APP_ENV: development
    # FEDERATION_DNS_B
    depends_on:
      postgres-b: {condition: service_healthy}
      redis-b: {condition: service_healthy}
      awid-b: {condition: service_started}
      federation-dns: {condition: service_started}
  cli:
    build: {context: "$ROOT", dockerfile: scripts/federation-cli.Dockerfile}
    # GNOME Keyring locks its memory and drops this capability after startup.
    cap_add: [IPC_LOCK]
    environment:
      HOME: /work/home
      APP_ENV: development
      AWEB_CROSS_REGISTRY_CSR: "${AWEB_CROSS_REGISTRY_CSR:-1}"
    volumes:
      - "$WORK_DIR:/work"
    # FEDERATION_DNS_CLI
volumes:
  postgres-a-data:
  postgres-b-data:
EOF

compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build awid-a awid-b aweb-a aweb-b cli
compose up -d federation-dns postgres-a postgres-b redis-a redis-b
DNS_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(compose ps -q federation-dns)")"
[[ -n "$DNS_IP" ]]
python3 - "$COMPOSE_FILE" "$DNS_IP" <<'PY'
from pathlib import Path
import ipaddress,sys
path=Path(sys.argv[1]); ip=str(ipaddress.ip_address(sys.argv[2])); text=path.read_text()
for marker in ("A", "B", "CLI", "AWID_A", "AWID_B"):
    source=f"    # FEDERATION_DNS_{marker}\n"
    assert text.count(source)==1, source
    text=text.replace(source, f'    dns:\n      - "{ip}"\n')
path.write_text(text)
PY
compose up -d awid-a awid-b
wait_health awid-a "http://$PUBLISHED_HOST:$AWID_A_PORT" awid-a
wait_health awid-b "http://$PUBLISHED_HOST:$AWID_B_PORT" awid-b
compose up -d aweb-a aweb-b
wait_health aweb-a "http://$PUBLISHED_HOST:$AWEB_A_PORT" aweb-a
wait_health aweb-b "http://$PUBLISHED_HOST:$AWEB_B_PORT" aweb-b

echo "Preparing DNS controllers without creating identities"
alice_controller="$(run_cli alice id namespace prepare-controller --domain alpha.example.com --registry http://awid-a:8010 --json)"
bob_controller="$(run_cli bob id namespace prepare-controller --domain beta.example.net --registry http://awid-b:8010 --json)"
ALICE_CONTROLLER="$(printf '%s' "$alice_controller" | json_field controller_did)"
BOB_CONTROLLER="$(printf '%s' "$bob_controller" | json_field controller_did)"
[[ -n "$ALICE_CONTROLLER" && -n "$BOB_CONTROLLER" && "$ALICE_CONTROLLER" != "$BOB_CONTROLLER" ]]

# Both products consume these exact-domain records from the same authority.
DNS_SERIAL=1
publish_dns() {
  local alpha_controller="$1" beta_controller="$2"
  DNS_SERIAL=$((DNS_SERIAL + 1))
  cat > "$DNS_DIR/example.com.zone.tmp" <<EOF
\$ORIGIN example.com.
\$TTL 1
@ IN SOA ns.example.com. hostmaster.example.com. ($DNS_SERIAL 1 1 1 1)
@ IN NS ns.example.com.
ns IN A 127.0.0.1
_awid IN TXT "awid=v1; controller=$ALICE_CONTROLLER; registry=http://awid-a:8010;"
_awid.alpha IN TXT "awid=v1; controller=$alpha_controller; registry=http://awid-a:8010;"
EOF
  cat > "$DNS_DIR/example.net.zone.tmp" <<EOF
\$ORIGIN example.net.
\$TTL 1
@ IN SOA ns.example.net. hostmaster.example.net. ($DNS_SERIAL 1 1 1 1)
@ IN NS ns.example.net.
ns IN A 127.0.0.1
_awid IN TXT "awid=v1; controller=$BOB_CONTROLLER; registry=http://awid-b:8010;"
_awid.beta IN TXT "awid=v1; controller=$beta_controller; registry=http://awid-b:8010;"
EOF
  mv "$DNS_DIR/example.com.zone.tmp" "$DNS_DIR/example.com.zone"
  mv "$DNS_DIR/example.net.zone.tmp" "$DNS_DIR/example.net.zone"
}

# The namespace remains absent when the real AWID resolver sees a different key.
# Poll on the product's 403, so CoreDNS file reload speed is not a test input.
publish_dns "$BOB_CONTROLLER" "$BOB_CONTROLLER"
awid_refused=0
for _ in $(seq 1 30); do
  if refused="$(run_cli alice id create --name alice --domain alpha.example.com --registry http://awid-a:8010 --json 2>&1)"; then
    echo "AWID accepted a namespace whose DNS controller is another key" >&2
    exit 1
  fi
  if [[ "$refused" == *"Signing key does not match DNS controller"* ]]; then awid_refused=1; break; fi
  sleep 1
done
[[ "$awid_refused" == 1 ]] || { printf '%s\n' "$refused" >&2; exit 1; }
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://$PUBLISHED_HOST:$AWID_A_PORT/v1/namespaces/alpha.example.com")" == 404 ]]
if run_cli alice id namespace check-txt --domain alpha.example.com --json > "$RUNTIME/cli-wrong-controller.json" 2>&1; then
  echo "CLI accepted a DNS controller that differs from its prepared key" >&2
  exit 1
fi
[[ "$(cat "$RUNTIME/cli-wrong-controller.json")" == *"DNS controller $BOB_CONTROLLER does not match local controller $ALICE_CONTROLLER"* ]] \
  || { cat "$RUNTIME/cli-wrong-controller.json" >&2; exit 1; }

publish_dns "$ALICE_CONTROLLER" "$BOB_CONTROLLER"
for identity in alice bob; do
  if [[ "$identity" == alice ]]; then domain=alpha.example.com; expected_controller="$ALICE_CONTROLLER";
  else domain=beta.example.net; expected_controller="$BOB_CONTROLLER"; fi
  matched=0
  for _ in $(seq 1 30); do
    if checked="$(run_cli "$identity" id namespace check-txt --domain "$domain" --json 2>/dev/null)"; then
      [[ "$(printf '%s' "$checked" | json_field status)" == matched ]]
      [[ "$(printf '%s' "$checked" | json_field dns_controller)" == "$expected_controller" ]]
      matched=1
      break
    fi
    sleep 1
  done
  [[ "$matched" == 1 ]] || { echo "CLI never verified exact DNS for $domain" >&2; exit 1; }
done

echo "Creating human and agent chains through real DNS, Secret Service and PTY"
compose run --rm -T --no-deps --entrypoint dbus-run-session cli -- \
  python3 /usr/local/bin/cross-registry-human-journey.py &
human_job=$!
requester_job=""
if [[ "${AWEB_CROSS_REGISTRY_CSR:-1}" == 1 ]]; then
  mkdir -p "$WORK_DIR/csr" "$WORK_DIR/requester-home"
  compose run --rm -T --no-deps -e HOME=/work/requester-home --entrypoint dbus-run-session cli -- \
    python3 /usr/local/bin/cross-registry-human-journey.py --csr-requester &
  requester_job=$!
fi
# The PTY driver signals actual progress. Service changes happen only here,
# against this journey's own Compose project, with no Docker socket in CLI.
for _ in $(seq 1 600); do
  if [[ -f "$WORK_DIR/stop-awid-request" && ! -f "$WORK_DIR/stop-awid-complete" ]]; then
    compose stop awid-a
    touch "$WORK_DIR/stop-awid-complete"
  fi
  if [[ -f "$WORK_DIR/start-awid-request" && ! -f "$WORK_DIR/start-awid-complete" ]]; then
    compose start awid-a
    wait_health awid-a "http://$PUBLISHED_HOST:$AWID_A_PORT" awid-a
    touch "$WORK_DIR/start-awid-complete"
  fi
  if ! kill -0 "$human_job" 2>/dev/null; then break; fi
  sleep 1
done
if kill -0 "$human_job" 2>/dev/null; then
  kill "$human_job"
  wait "$human_job" || true
  echo "human constructor journey timed out" >&2
  exit 1
fi
wait "$human_job"
if [[ -n "$requester_job" ]]; then wait "$requester_job"; fi
alice_create="$(cat "$WORK_DIR/alice-create.json")"
bob_create="$(cat "$WORK_DIR/bob-create.json")"
ALICE_DID_AW="$(printf '%s' "$alice_create" | json_field did_aw)"
BOB_DID_AW="$(printf '%s' "$bob_create" | json_field did_aw)"
compose run --rm -T --no-deps --entrypoint id-tree-verifier cli
compose cp "$ROOT/scripts/cross-registry-python-verifier.py" awid-b:/tmp/cross-registry-python-verifier.py
compose exec -T awid-b python /tmp/cross-registry-python-verifier.py < "$WORK_DIR/journey-public.json"
# Membership and connection are not ancestry: joining a team, connecting to
# aweb and later leaving the team keep each identity and its exact chain.
ALICE_WHO="$(who_json alice)"
BOB_WHO="$(who_json bob)"
[[ "$(printf '%s' "$ALICE_WHO" | json_field outcome)" == nearest_human && "$(printf '%s' "$ALICE_WHO" | json_field id)" == "$ALICE_DID_AW" ]]
[[ "$(printf '%s' "$BOB_WHO" | json_field outcome)" == no_human && "$(printf '%s' "$BOB_WHO" | json_field id)" == "$BOB_DID_AW" ]]
run_cli alice id team create --name alpha --namespace alpha.example.com --registry http://awid-a:8010 --json >/dev/null
alice_invite="$(run_cli alice id team invite --team alpha --namespace alpha.example.com --member-global --json)"
run_cli alice id team accept-invite "$(printf '%s' "$alice_invite" | json_field token)" --name alice --global --json >/dev/null
[[ "$(who_json alice)" == "$ALICE_WHO" ]]
run_cli alice init --url http://aweb-a:8000 --name alice --do-not-touch-agents-md >/dev/null
[[ "$(who_json alice)" == "$ALICE_WHO" ]]

run_cli bob id team create --name beta --namespace beta.example.net --registry http://awid-b:8010 --json >/dev/null
bob_invite="$(run_cli bob id team invite --team beta --namespace beta.example.net --member-global --json)"
run_cli bob id team accept-invite "$(printf '%s' "$bob_invite" | json_field token)" --name bob --global --json >/dev/null
[[ "$(who_json bob)" == "$BOB_WHO" ]]
run_cli bob init --url http://aweb-b:8000 --name bob --do-not-touch-agents-md >/dev/null
[[ "$(who_json bob)" == "$BOB_WHO" ]]
echo "PASS: team join and aweb connection keep each identity's exact aw who chain"

[[ -n "$ALICE_DID_AW" && -n "$BOB_DID_AW" && -n "$ALICE_CONTROLLER" && -n "$BOB_CONTROLLER" ]]
# Control: each home registry lacks the foreign address.
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://$PUBLISHED_HOST:$AWID_A_PORT/v1/namespaces/beta.example.net/addresses/bob")" == "404" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://$PUBLISHED_HOST:$AWID_B_PORT/v1/namespaces/alpha.example.com/addresses/alice")" == "404" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://$PUBLISHED_HOST:$AWID_A_PORT/v1/namespaces/alpha.example.com/addresses/alice")" == "200" ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://$PUBLISHED_HOST:$AWID_B_PORT/v1/namespaces/beta.example.net/addresses/bob")" == "200" ]]

run_cli alice id namespace set-delivery-origin --namespace alpha.example.com --origin http://aweb-a:8000 --json >/dev/null
run_cli bob id namespace set-delivery-origin --namespace beta.example.net --origin http://aweb-b:8000 --json >/dev/null

echo "Proving CLI mail delivery across two registries"
mail_out="$(run_cli alice mail send --plaintext --to-address beta.example.net/bob --subject 'two registry mail' --body 'alice to bob' --json)"
CONVERSATION_ID="$(printf '%s' "$mail_out" | json_field conversation_id)"
[[ -n "$(printf '%s' "$mail_out" | json_field message_id)" && -n "$CONVERSATION_ID" ]]
bob_inbox="$(run_cli bob mail inbox --show-all --json)"
assert_inbox_message "$bob_inbox" "two registry mail" "alice to bob"
run_cli bob mail send --plaintext --conversation-id "$CONVERSATION_ID" --subject "two registry reply" --body "bob to alice" --json >/dev/null
alice_inbox="$(run_cli alice mail inbox --show-all --json)"
assert_inbox_message "$alice_inbox" "two registry reply" "bob to alice"

echo "Proving CLI chat delivery across two registries"
run_cli alice chat send-and-leave --plaintext beta.example.net/bob "two registry chat" --json >/dev/null
bob_chat="$(run_cli bob chat history alpha.example.com/alice --json)"
assert_chat_message "$bob_chat" "two registry chat"
run_cli bob chat send-and-leave --plaintext alpha.example.com/alice "two registry chat reply" --json >/dev/null
alice_chat="$(run_cli alice chat history beta.example.net/bob --json)"
assert_chat_message "$alice_chat" "two registry chat reply"

echo "Proving team membership removal is not ID revocation"
removed="$(run_cli alice id team remove-member --team alpha --namespace alpha.example.com --member alpha.example.com/alice --json)"
removed_certificate="$(printf '%s' "$removed" | json_field certificate_id)"
[[ -n "$removed_certificate" ]]
[[ "$(curl -sS "http://$PUBLISHED_HOST:$AWID_A_PORT/v1/namespaces/alpha.example.com/teams/alpha/certificates/$removed_certificate/status" | json_field status)" == revoked ]]
[[ "$(who_json alice)" == "$ALICE_WHO" ]]
echo "PASS: removing alice from team alpha revokes her team certificate and leaves her ID chain verified"

echo "PASS: real DNS, Secret Service, PTY, constructor chains, unchanged resume, outsider verification, mail and chat across disjoint registries"
