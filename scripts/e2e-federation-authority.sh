#!/usr/bin/env bash
# Disposable two-registry/two-receiver/four-process inactive-core conformance.
# This harness never calls federation ingress. TLS keys exist only below its
# temporary directory and are removed after `docker compose down -v`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROJECT="${AWEB_FED_AUTH_PROJECT:-aweb-fed-auth-$RANDOM-$$}"
DOCKER_BIND_ROOT="${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}"
[[ "$DOCKER_BIND_ROOT" = /* && -d "$DOCKER_BIND_ROOT" ]] \
  || { echo "AWEB_DOCKER_BIND_ROOT must be an existing absolute directory" >&2; exit 2; }
RUNTIME="$(mktemp -d "$DOCKER_BIND_ROOT/aweb-fed-auth.XXXXXX")"
COMPOSE_FILE="$RUNTIME/docker-compose.yml"
TLS_DIR="$RUNTIME/tls"
ARTIFACT_DIR="${AWEB_FED_AUTH_ARTIFACT_DIR:-$ROOT/.cache/federation-authority}"
AWID_A_PORT="${AWEB_FED_AUTH_AWID_A_PORT:-18410}"
AWID_B_PORT="${AWEB_FED_AUTH_AWID_B_PORT:-18420}"
AWEB_A1_PORT="${AWEB_FED_AUTH_AWEB_A1_PORT:-18431}"
AWEB_A2_PORT="${AWEB_FED_AUTH_AWEB_A2_PORT:-18432}"
AWEB_B1_PORT="${AWEB_FED_AUTH_AWEB_B1_PORT:-18441}"
AWEB_B2_PORT="${AWEB_FED_AUTH_AWEB_B2_PORT:-18442}"
POSTGRES_A_PORT="${AWEB_FED_AUTH_POSTGRES_A_PORT:-58431}"
POSTGRES_B_PORT="${AWEB_FED_AUTH_POSTGRES_B_PORT:-58432}"
DOCKER_PUBLISHED_HOST="${AWEB_DOCKER_PUBLISHED_HOST:-127.0.0.1}"
case "$DOCKER_PUBLISHED_HOST" in
  127.0.0.1|aweb-docker.test) ;;
  *) echo "unsupported AWEB_DOCKER_PUBLISHED_HOST: $DOCKER_PUBLISHED_HOST" >&2; exit 2 ;;
esac
mkdir -p "$TLS_DIR" "$ARTIFACT_DIR"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ $status -ne 0 && -f "$COMPOSE_FILE" ]]; then
    compose logs --tail 120 --no-color awid-a awid-b aweb-a-1 aweb-a-2 aweb-b-1 aweb-b-2 >&2 || true
  fi
  if [[ "${AWEB_FED_AUTH_KEEP:-0}" == "1" ]]; then
    echo "Keeping disposable harness project $PROJECT at $RUNTIME" >&2
    return "$status"
  fi
  if [[ -f "$COMPOSE_FILE" ]]; then
    compose down -v --rmi local --remove-orphans >/dev/null 2>&1 || status=1
    if docker ps -aq --filter label=com.docker.compose.project="$PROJECT" | grep -q .; then
      echo "teardown left containers for $PROJECT" >&2
      status=1
    fi
    if docker volume ls -q --filter label=com.docker.compose.project="$PROJECT" | grep -q .; then
      echo "teardown left volumes for $PROJECT" >&2
      status=1
    fi
    if docker network ls -q --filter label=com.docker.compose.project="$PROJECT" | grep -q .; then
      echo "teardown left networks for $PROJECT" >&2
      status=1
    fi
    if docker images -q --filter label=com.docker.compose.project="$PROJECT" | grep -q .; then
      echo "teardown left images for $PROJECT" >&2
      status=1
    fi
  fi
  rm -rf "$RUNTIME"
  exit "$status"
}
trap cleanup EXIT

wait_http() {
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

wait_service_health() {
  local service="$1"
  for _ in $(seq 1 90); do
    if [[ "$(compose ps --format json "$service" | python3 -c 'import json,sys; x=json.load(sys.stdin); print((x[0] if isinstance(x,list) else x).get("Health", ""))' 2>/dev/null || true)" == "healthy" ]]; then
      return
    fi
    sleep 2
  done
  compose logs --tail 80 --no-color "$service" >&2 || true
  echo "$service did not become healthy" >&2
  return 1
}

json_field() {
  local field="$1"
  python3 -c 'import json,sys; value=json.load(sys.stdin); print(value.get(sys.argv[1], ""))' "$field"
}

generate_tls() {
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=aweb federation disposable CA" \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" >/dev/null 2>&1
  local name
  for name in registry-a.test registry-b.test; do
    openssl req -new -newkey rsa:2048 -nodes -sha256 \
      -subj "/CN=$name" \
      -keyout "$TLS_DIR/$name.key" -out "$TLS_DIR/$name.csr" >/dev/null 2>&1
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$name" > "$TLS_DIR/$name.ext"
    openssl x509 -req -sha256 -days 1 \
      -in "$TLS_DIR/$name.csr" \
      -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
      -extfile "$TLS_DIR/$name.ext" \
      -out "$TLS_DIR/$name.crt" >/dev/null 2>&1
  done
}

generate_tls
cat > "$RUNTIME/registry-a.conf" <<'EOF'
events {}
http {
  access_log /dev/stdout combined;
  error_log /dev/stderr notice;
  server {
    listen 443 ssl;
    server_name registry-a.test;
    ssl_certificate /runtime-tls/registry-a.test.crt;
    ssl_certificate_key /runtime-tls/registry-a.test.key;
    location / { proxy_set_header Host $host; proxy_pass http://awid-a:8010; }
  }
}
EOF
cat > "$RUNTIME/registry-b.conf" <<'EOF'
events {}
http {
  access_log /dev/stdout combined;
  error_log /dev/stderr notice;
  server {
    listen 443 ssl;
    server_name registry-b.test;
    ssl_certificate /runtime-tls/registry-b.test.crt;
    ssl_certificate_key /runtime-tls/registry-b.test.key;
    location / { proxy_set_header Host $host; proxy_pass http://awid-b:8010; }
  }
}
EOF

cat > "$COMPOSE_FILE" <<EOF
services:
  postgres-a:
    image: postgres:16-alpine
    environment: {POSTGRES_USER: aweb, POSTGRES_PASSWORD: disposable, POSTGRES_DB: aweb}
    ports: ["$POSTGRES_A_PORT:5432"]
    volumes: [postgres-a-data:/var/lib/postgresql/data]
    healthcheck: {test: ["CMD-SHELL", "pg_isready -U aweb -d aweb"], interval: 2s, timeout: 2s, retries: 45}
  postgres-b:
    image: postgres:16-alpine
    environment: {POSTGRES_USER: aweb, POSTGRES_PASSWORD: disposable, POSTGRES_DB: aweb}
    ports: ["$POSTGRES_B_PORT:5432"]
    volumes: [postgres-b-data:/var/lib/postgresql/data]
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
      AWID_RATE_LIMIT_DISABLED: "1"
      AWID_SERVICE_TOKEN: aweb-federation-authority-e2e-service-token-32-bytes
      AWID_SKIP_DNS_VERIFY: "1"
      APP_ENV: development
      AWID_ALLOW_INSECURE_DELIVERY_ORIGIN: "1"
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
      AWID_RATE_LIMIT_DISABLED: "1"
      AWID_SERVICE_TOKEN: aweb-federation-authority-e2e-service-token-32-bytes
      AWID_SKIP_DNS_VERIFY: "1"
      APP_ENV: development
      AWID_ALLOW_INSECURE_DELIVERY_ORIGIN: "1"
    depends_on:
      postgres-b: {condition: service_healthy}
      redis-b: {condition: service_healthy}
  registry-a:
    image: nginx:1.27-alpine
    volumes:
      - "$TLS_DIR:/runtime-tls:ro"
      - "$RUNTIME/registry-a.conf:/etc/nginx/nginx.conf:ro"
    networks: {default: {aliases: [registry-a.test]}}
    depends_on: [awid-a]
  registry-b:
    image: nginx:1.27-alpine
    volumes:
      - "$TLS_DIR:/runtime-tls:ro"
      - "$RUNTIME/registry-b.conf:/etc/nginx/nginx.conf:ro"
    networks: {default: {aliases: [registry-b.test]}}
    depends_on: [awid-b]
  aweb-a-1: &aweb_a
    build: {context: "$ROOT", dockerfile: server/Dockerfile}
    ports: ["$AWEB_A1_PORT:8000"]
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:disposable@postgres-a:5432/aweb
      AWEB_REDIS_URL: redis://redis-a:6379/1
      AWID_REGISTRY_URL: http://awid-a:8010
      AWID_SERVICE_TOKEN: aweb-federation-authority-e2e-service-token-32-bytes
      AWEB_PUBLIC_ORIGIN: http://aweb-a:8000
      APP_ENV: development
    volumes:
      - "$ROOT/scripts/federation-authority-worker.py:/harness/federation-authority-worker.py:ro"
      - "$TLS_DIR:/runtime-tls:ro"
    depends_on:
      postgres-a: {condition: service_healthy}
      redis-a: {condition: service_healthy}
      awid-a: {condition: service_started}
      registry-a: {condition: service_started}
  aweb-a-2:
    <<: *aweb_a
    ports: ["$AWEB_A2_PORT:8000"]
  aweb-b-1: &aweb_b
    build: {context: "$ROOT", dockerfile: server/Dockerfile}
    ports: ["$AWEB_B1_PORT:8000"]
    environment:
      AWEB_DATABASE_URL: postgresql://aweb:disposable@postgres-b:5432/aweb
      AWEB_REDIS_URL: redis://redis-b:6379/1
      AWID_REGISTRY_URL: http://awid-b:8010
      AWID_SERVICE_TOKEN: aweb-federation-authority-e2e-service-token-32-bytes
      AWEB_PUBLIC_ORIGIN: http://aweb-b:8000
      APP_ENV: development
    volumes:
      - "$ROOT/scripts/federation-authority-worker.py:/harness/federation-authority-worker.py:ro"
      - "$TLS_DIR:/runtime-tls:ro"
    depends_on:
      postgres-b: {condition: service_healthy}
      redis-b: {condition: service_healthy}
      awid-b: {condition: service_started}
      registry-b: {condition: service_started}
  aweb-b-2:
    <<: *aweb_b
    ports: ["$AWEB_B2_PORT:8000"]
volumes:
  postgres-a-data:
  postgres-b-data:
EOF

compose down -v --remove-orphans >/dev/null 2>&1 || true
if [[ "${AWEB_FED_AUTH_BUILD:-1}" != "0" ]]; then
  compose build
fi
compose up -d postgres-a postgres-b redis-a redis-b awid-a awid-b registry-a registry-b
wait_http awid-a "http://$DOCKER_PUBLISHED_HOST:$AWID_A_PORT" awid-a
wait_http awid-b "http://$DOCKER_PUBLISHED_HOST:$AWID_B_PORT" awid-b
# Serialize first migration ownership per side, then start the second process
# against the already-migrated shared schema. This avoids mistaking pgdbm's
# first-table creation race for an authority-core worker race.
compose up -d aweb-a-1 aweb-b-1
wait_http aweb-a-1 "http://$DOCKER_PUBLISHED_HOST:$AWEB_A1_PORT" aweb-a-1
wait_http aweb-b-1 "http://$DOCKER_PUBLISHED_HOST:$AWEB_B1_PORT" aweb-b-1
compose up -d aweb-a-2 aweb-b-2
wait_http aweb-a-2 "http://$DOCKER_PUBLISHED_HOST:$AWEB_A2_PORT" aweb-a-2
wait_http aweb-b-2 "http://$DOCKER_PUBLISHED_HOST:$AWEB_B2_PORT" aweb-b-2

seed_registry() {
  local postgres_service="$1" identity_file="$2" domain="$3" name="$4" delivery="$5"
  python3 - "$identity_file" "$domain" "$name" "$delivery" <<'PY' | compose exec -T "$postgres_service" psql -v ON_ERROR_STOP=1 -U aweb -d aweb >/dev/null
import json,sys
vector_path,domain,name,delivery=sys.argv[1:]
vector=json.load(open(vector_path))
mapping=vector["mapping"]
def q(value):
    if value is None: return "NULL"
    return "'" + str(value).replace("'", "''") + "'"
print("BEGIN;")
print("INSERT INTO awid.did_aw_mappings (did_aw,current_did_key) VALUES (%s,%s);" % (q(mapping["did_aw"]),q(mapping["rotated_did_key"])))
for item in vector["entries"]:
    entry=item["entry_payload"]
    values=[entry["did_aw"],entry["seq"],entry["operation"],entry["previous_did_key"],entry["new_did_key"],entry["prev_entry_hash"],item["entry_hash"],entry["state_hash"],entry["authorized_by"],item["signature_b64"],entry["timestamp"]]
    rendered=",".join(str(value) if isinstance(value,int) else q(value) for value in values)
    print("INSERT INTO awid.did_aw_log (did_aw,seq,operation,previous_did_key,new_did_key,prev_entry_hash,entry_hash,state_hash,authorized_by,signature,timestamp) VALUES ("+rendered+");")
print("INSERT INTO awid.dns_namespaces (domain,controller_did,verification_status,last_verified_at,default_delivery_origin) VALUES (%s,%s,'verified',clock_timestamp(),%s);" % (q(domain),q(mapping["initial_did_key"]),q(delivery)))
print("INSERT INTO awid.public_addresses (namespace_id,name,did_aw) SELECT namespace_id,%s,%s FROM awid.dns_namespaces WHERE domain=%s AND deleted_at IS NULL;" % (q(name),q(mapping["did_aw"]),q(domain)))
print("COMMIT;")
PY
}
ALPHA_IDENTITY="$ROOT/docs/vectors/identity-log-v1.json"
BETA_IDENTITY="$RUNTIME/beta-identity.json"
compose exec -T aweb-b-1 python /harness/federation-authority-worker.py identity > "$BETA_IDENTITY"
seed_registry postgres-a "$ALPHA_IDENTITY" alpha.test.local alice http://aweb-a:8000
seed_registry postgres-b "$BETA_IDENTITY" beta.test.local bob http://aweb-b:8000

identity_field() {
  local file="$1" field="$2"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mapping"][sys.argv[2]])' "$file" "$field"
}
ALPHA_DID_AW="$(identity_field "$ALPHA_IDENTITY" did_aw)"
ALPHA_DID_KEY="$(identity_field "$ALPHA_IDENTITY" rotated_did_key)"
ALPHA_CONTROLLER="$(identity_field "$ALPHA_IDENTITY" initial_did_key)"
BETA_DID_AW="$(identity_field "$BETA_IDENTITY" did_aw)"
BETA_DID_KEY="$(identity_field "$BETA_IDENTITY" rotated_did_key)"
BETA_CONTROLLER="$(identity_field "$BETA_IDENTITY" initial_did_key)"
[[ "$ALPHA_DID_AW" != "$BETA_DID_AW" ]]

worker() {
  local service="$1" domain="$2" address="$3" did_aw="$4" did_key="$5" controller="$6" registry="$7" delivery="$8"
  shift 8
  compose exec -T \
    -e HARNESS_DOMAIN="$domain" \
    -e HARNESS_ADDRESS="$address" \
    -e HARNESS_DID_AW="$did_aw" \
    -e HARNESS_DID_KEY="$did_key" \
    -e HARNESS_CONTROLLER_DID="$controller" \
    -e HARNESS_REGISTRY_ORIGIN="$registry" \
    -e HARNESS_DELIVERY_ORIGIN="$delivery" \
    -e HARNESS_CA_FILE=/runtime-tls/ca.crt \
    "$service" python /harness/federation-authority-worker.py "$@"
}
worker_a() { local service="$1"; shift; worker "$service" alpha.test.local alpha.test.local/alice "$ALPHA_DID_AW" "$ALPHA_DID_KEY" "$ALPHA_CONTROLLER" https://registry-a.test http://aweb-a:8000 "$@"; }
worker_b() { local service="$1"; shift; worker "$service" beta.test.local beta.test.local/bob "$BETA_DID_AW" "$BETA_DID_KEY" "$BETA_CONTROLLER" https://registry-b.test http://aweb-b:8000 "$@"; }

worker_a aweb-a-1 resolve --generation 1 > "$RUNTIME/alpha-resolve.json"
worker_a aweb-a-2 verify > "$RUNTIME/alpha-verify.json"
worker_b aweb-b-1 resolve --generation 1 > "$RUNTIME/beta-resolve.json"
worker_b aweb-b-2 verify > "$RUNTIME/beta-verify.json"

# Two distinct receiver processes leave one Redis-only test barrier together,
# while PostgreSQL remains the sole lease/result authority. Exactly one process
# performs the real strict DNS/TLS/AWID chain; both consume its shared evidence.
worker_a aweb-a-1 singleflight --barrier evidence-race --role wrong-worker \
  --claim wrong --scope evidence:harness-real-chain --generation 7 > "$RUNTIME/singleflight-wrong.json" &
singleflight_wrong_pid=$!
worker_a aweb-a-2 singleflight --barrier evidence-race --role correct-worker \
  --claim correct --scope evidence:harness-real-chain --generation 7 > "$RUNTIME/singleflight-correct.json" &
singleflight_correct_pid=$!
wait "$singleflight_wrong_pid"
wait "$singleflight_correct_pid"
python3 - "$RUNTIME/singleflight-wrong.json" "$RUNTIME/singleflight-correct.json" <<'PY'
import json,sys
wrong,correct=(json.load(open(path)) for path in sys.argv[1:])
assert wrong["status"] == "claim_rejected"
assert wrong["reason"] == "sender_address_did_mismatch"
assert correct["status"] == "claim_authorized"
assert sum(int(item["lease_leader"]) for item in (wrong,correct)) == 1
assert sum(item["authority_chain_count"] for item in (wrong,correct)) == 1
PY

# Fill each exact reviewed ceiling to N-1, then release two distinct processes
# together for N and N+1. PostgreSQL admits exactly one at 32/2/4.
run_permit_race() {
  local label="$1" kind="$2" key="$3" limit="$4" prefill="$5"
  worker_a aweb-a-1 permit-fill --kind "$kind" --key "$key" --limit "$limit" \
    --count "$prefill" > "$RUNTIME/permit-$label-fill.json"
  worker_a aweb-a-1 permit-race --barrier "permit-$label" --role left \
    --kind "$kind" --key "$key" --limit "$limit" > "$RUNTIME/permit-$label-left.json" &
  local left_pid=$!
  worker_a aweb-a-2 permit-race --barrier "permit-$label" --role right \
    --kind "$kind" --key "$key" --limit "$limit" > "$RUNTIME/permit-$label-right.json" &
  local right_pid=$!
  wait "$left_pid"
  wait "$right_pid"
  python3 - "$RUNTIME/permit-$label-left.json" "$RUNTIME/permit-$label-right.json" "$limit" <<'PY'
import json,sys
left,right=(json.load(open(path)) for path in sys.argv[1:3])
assert sorted(item["status"] for item in (left,right)) == ["permit_admitted","permit_rejected"]
rejected=left if left["status"] == "permit_rejected" else right
assert rejected["reason"] == "federation_resolver_busy"
limit=int(sys.argv[3])
assert {left["limit"],right["limit"]} == {limit}
assert {left["active_count"],right["active_count"]} == {limit}
PY
}
run_permit_race global global receiver-exact-32 32 31
run_permit_race domain domain alpha-exact-2.test 2 1
run_permit_race origin origin https://registry-exact-4.test 4 3
worker_a aweb-a-2 permit-atomic --key receiver-exact-32 > "$RUNTIME/permit-atomic.json"
[[ "$(json_field reason < "$RUNTIME/permit-atomic.json")" == "federation_resolver_busy" ]]
[[ "$(json_field partial_permits < "$RUNTIME/permit-atomic.json")" == "0" ]]

# A process barrier releases two N+1 forks against one shared PostgreSQL row.
RACE_DID_AW="did:aw:2CiZ88hVF4JuQim8nnSuyeiV2Race"
race_worker() {
  local service="$1"; shift
  worker "$service" alpha.test.local alpha.test.local/Race "$RACE_DID_AW" "$ALPHA_DID_KEY" "$ALPHA_CONTROLLER" https://registry-a.test http://aweb-a:8000 "$@"
}
race_worker aweb-a-1 seed > "$RUNTIME/race-seed.json"
set +e
race_worker aweb-a-1 fork --variant left > "$RUNTIME/race-left.json" &
race_left_pid=$!
race_worker aweb-a-2 fork --variant right > "$RUNTIME/race-right.json" &
race_right_pid=$!
wait "$race_left_pid"; race_left_status=$?
wait "$race_right_pid"; race_right_status=$?
set -e
if [[ $race_left_status -eq 0 && $race_right_status -eq 2 ]]; then
  race_loser=right
elif [[ $race_left_status -eq 2 && $race_right_status -eq 0 ]]; then
  race_loser=left
else
  echo "fork race did not produce one winner: left=$race_left_status right=$race_right_status" >&2
  exit 1
fi
race_loser_reason="$(json_field reason < "$RUNTIME/race-$race_loser.json")"
[[ "$race_loser_reason" == "sender_did_log_split_view" || "$race_loser_reason" == "federation_authority_cas_conflict" ]]

# Cross-process shared token bucket: five successes and one exact 429 failure.
for index in 1 2 3 4 5; do
  service=aweb-a-1; [[ $((index % 2)) == 0 ]] && service=aweb-a-2
  worker_a "$service" token --burst 5 > "$RUNTIME/token-$index.json"
done
set +e
worker_a aweb-a-2 token --burst 5 > "$RUNTIME/token-6.json"
token_status=$?
set -e
[[ "$token_status" == "2" ]]
[[ "$(json_field reason < "$RUNTIME/token-6.json")" == "federation_rate_limited" ]]

# A held PostgreSQL advisory lock forces the production repository's one-second
# query timeout. The production core observes no cohort and neither result nor
# lease state is published.
worker_b aweb-b-1 lock-timeout --scope harness-blocked-lock > "$RUNTIME/beta-lock-timeout.json"
[[ "$(json_field reason < "$RUNTIME/beta-lock-timeout.json")" == "federation_authority_coordination_unavailable" ]]
[[ "$(json_field http_status < "$RUNTIME/beta-lock-timeout.json")" == "503" ]]
[[ "$(json_field authorized < "$RUNTIME/beta-lock-timeout.json")" == "False" ]]

# Real coordination outage: the worker opens its pool, waits at a process
# barrier, then reads only after PostgreSQL stops. No process-local or Redis
# fallback authorizes.
worker_b aweb-b-2 outage --delay 3 > "$RUNTIME/beta-outage.json" &
outage_pid=$!
sleep 1
compose stop postgres-b >/dev/null
wait "$outage_pid"
[[ "$(json_field reason < "$RUNTIME/beta-outage.json")" == "federation_authority_coordination_unavailable" ]]
[[ "$(json_field http_status < "$RUNTIME/beta-outage.json")" == "503" ]]
compose start postgres-b >/dev/null
wait_service_health postgres-b
worker_a aweb-a-1 state > "$RUNTIME/alpha-state.json"
worker_b aweb-b-1 state > "$RUNTIME/beta-state.json"

compose logs --no-color registry-a > "$RUNTIME/registry-a.log" 2>&1
compose logs --no-color registry-b > "$RUNTIME/registry-b.log" 2>&1
for path in \
  /v1/namespaces/alpha.test.local \
  /v1/namespaces/alpha.test.local/addresses/alice \
  "/v1/did/${ALPHA_DID_AW//:/%3A}/key" \
  "/v1/did/${ALPHA_DID_AW//:/%3A}/log"; do
  grep -F "$path" "$RUNTIME/registry-a.log" >/dev/null
done
for path in \
  /v1/namespaces/beta.test.local \
  /v1/namespaces/beta.test.local/addresses/bob \
  "/v1/did/${BETA_DID_AW//:/%3A}/key" \
  "/v1/did/${BETA_DID_AW//:/%3A}/log"; do
  grep -F "$path" "$RUNTIME/registry-b.log" >/dev/null
done

ARTIFACT="$ARTIFACT_DIR/$PROJECT.json"
python3 - "$RUNTIME" "$TLS_DIR" "$ARTIFACT" "$PROJECT" "$ALPHA_DID_AW" "$BETA_DID_AW" <<'PY'
import hashlib,json,pathlib,sys
runtime,tls,out,project=map(pathlib.Path,sys.argv[1:5])
alpha_did_aw,beta_did_aw=sys.argv[5:]
def load(name): return json.loads((runtime/name).read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
artifact={
 "schema":"aweb.federation-authority-harness-artifact.v1",
 "project":project.name,
 "topology":{"awid":["awid-a","awid-b"],"identities":{"alice":alpha_did_aw,"bob":beta_did_aw},"receivers":["aweb-a","aweb-b"],"processes":["aweb-a-1","aweb-a-2","aweb-b-1","aweb-b-2"],"postgres":["postgres-a","postgres-b"]},
 "strict_ingress_calls":False,
 "results":{name:load(name+".json") for name in (
   "alpha-resolve","alpha-verify","beta-resolve","beta-verify",
   "singleflight-wrong","singleflight-correct",
   "permit-global-left","permit-global-right","permit-domain-left","permit-domain-right",
   "permit-origin-left","permit-origin-right","permit-atomic",
   "token-1","token-2","token-3","token-4","token-5","token-6",
   "race-seed","race-left","race-right","beta-lock-timeout","beta-outage",
   "alpha-state","beta-state")},
 "runtime_public_certificate_sha256":{"ca":digest(tls/"ca.crt"),"registry-a":digest(tls/"registry-a.test.crt"),"registry-b":digest(tls/"registry-b.test.crt")},
 "registry_log_sha256":{"registry-a":digest(runtime/"registry-a.log"),"registry-b":digest(runtime/"registry-b.log")},
 "teardown":"docker compose down -v --remove-orphans with project container/volume absence checks"
}
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(artifact,sort_keys=True,separators=(",",":"))+"\n")
print(out)
print(hashlib.sha256(out.read_bytes()).hexdigest())
PY

echo "Disposable inactive-core topology passed; cleanup will now verify absence."
