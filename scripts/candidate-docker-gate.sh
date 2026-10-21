#!/usr/bin/env bash
# Complete local Docker gate for one exact OSS candidate commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE_SHA="${CANDIDATE_SOURCE_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
refuse() { printf 'candidate gate refused: %s\n' "$*" >&2; exit 2; }
LIBRARY_E2E_LIBRARY_CONTEXT="${LIBRARY_E2E_LIBRARY_CONTEXT:-$ROOT/naapp/library}"
LIBRARY_E2E_BLUEPRINT_SRC="${LIBRARY_E2E_BLUEPRINT_SRC:-$ROOT/naapp/library/test-vectors/blueprints/team}"
canonical_git_input() {
  local name="$1" path="$2" top canonical
  top="$(git -C "$path" rev-parse --show-toplevel 2>/dev/null)" \
    || refuse "$name input is not a git checkout"
  top="$(cd "$top" && pwd -P)"
  canonical="$(cd "$path" && pwd -P)"
  case "$canonical" in
    "$top"|"$top"/*) ;;
    *) refuse "$name input escapes its git checkout" ;;
  esac
  printf '%s\n' "$canonical"
}
LIBRARY_E2E_LIBRARY_CONTEXT="$(canonical_git_input library "$LIBRARY_E2E_LIBRARY_CONTEXT")"
LIBRARY_E2E_BLUEPRINT_SRC="$(canonical_git_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC")"
LOG_DIR="/tmp/aweb-candidate-gate-$SOURCE_SHA"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || refuse "CANDIDATE_SOURCE_SHA must be a full lowercase SHA"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] \
  || refuse "source checkout is dirty or has untracked files"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$SOURCE_SHA" ]] \
  || refuse "source checkout HEAD differs from selected SHA"
# Focused pre-landing proof uses the same stages and ledger. Release candidates
# always request the complete list and retain the origin/main requirement.
STAGES="${AWEB_CANDIDATE_STAGES:-}"
REQUESTED="${STAGES:-checks unit artifacts integration}"
if [[ -z "$STAGES" ]]; then
  git -C "$ROOT" fetch --quiet origin main
  git -C "$ROOT" merge-base --is-ancestor "$SOURCE_SHA" origin/main \
    || refuse "source SHA is not on the synchronized origin/main history"
fi
[[ -d "$LIBRARY_E2E_LIBRARY_CONTEXT" ]] || refuse "Library input is missing"
[[ -d "$LIBRARY_E2E_BLUEPRINT_SRC" ]] || refuse "blueprint input is missing"
CLI_VERSION="${CLI_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" aw-v)}"
A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" a2a-gw-v)}"

# Port of Cloud's entry-point ledger: all callers share one tree lock and
# stage history. Version defaults depend on tags, so their effective values
# are external inputs even when the caller did not supply an override.
TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
external_inputs="CLI_VERSION=$CLI_VERSION"$'\n'"A2A_GATEWAY_VERSION=$A2A_GATEWAY_VERSION"$'\n'
input_identity() {
  local name="$1" path="$2" default="$3" repo sha relative
  repo="$(git -C "$path" rev-parse --show-toplevel)"
  repo="$(cd "$repo" && pwd -P)"
  [[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] \
    || refuse "$name input checkout is dirty"
  sha="$(git -C "$repo" rev-parse HEAD)"
  relative="${path#"$repo"}"
  printf -v "${name}_input_sha" '%s' "$sha"
  if [[ "$repo" != "$ROOT" ]]; then
    external_inputs+="$name=$sha$relative"$'\n'
  elif [[ "$path" != "$ROOT/$default" ]]; then
    external_inputs+="$name=source$relative"$'\n'
  fi
}
input_identity library "$LIBRARY_E2E_LIBRARY_CONTEXT" naapp/library
input_identity blueprints "$LIBRARY_E2E_BLUEPRINT_SRC" naapp/library/test-vectors/blueprints/team
gate_setting() {
  local name="$1" default="$2" value
  value="${!name:-$default}"
  printf -v "$name" '%s' "$value"
  [[ "$value" == "$default" ]] || external_inputs+="$name=$value"$'\n'
}
gate_setting AWEB_CANDIDATE_RUNNER_CPUS 2
gate_setting AWEB_CANDIDATE_RUNNER_MEMORY 8g
gate_setting AWEB_CANDIDATE_RUNNER_PIDS 2048
gate_setting AWEB_CANDIDATE_BUILDER_CPUS 2
gate_setting AWEB_CANDIDATE_BUILDER_MEMORY 6g
gate_setting AWEB_CANDIDATE_BUILDER_MEMORY_SWAP "$AWEB_CANDIDATE_BUILDER_MEMORY"
gate_setting AWEB_CANDIDATE_BUILDER_PIDS 2048
gate_setting AWEB_CANDIDATE_SERVICE_CPUS 1
gate_setting AWEB_CANDIDATE_SERVICE_MEMORY 1g
gate_setting AWEB_CANDIDATE_SERVICE_PIDS 512
gate_setting AWEB_CANDIDATE_REDIS_CPUS 0.5
gate_setting AWEB_CANDIDATE_REDIS_MEMORY 256m
gate_setting AWEB_CANDIDATE_REDIS_PIDS 256
gate_setting AWEB_CANDIDATE_SIBLING_CPUS 2
gate_setting AWEB_CANDIDATE_SIBLING_MEMORY 4g
gate_setting AWEB_CANDIDATE_SIBLING_PIDS 1024
KEY="$TREE-$(printf '%s' "$external_inputs" | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
LEDGER="${AWEB_GATE_LEDGER:-$HOME/.cache/aweb-oss/candidate-gate-ledger.tsv}"
LEDGER_LOGS="${AWEB_GATE_LOG_DIR:-$(dirname "$LEDGER")/gate-logs}"
OWNER="${GATE_OWNER:-${OATS_INSTANCE:-$(id -un)}}"
mkdir -p "$(dirname "$LEDGER")/gate-locks" "$LEDGER_LOGS"
touch "$LEDGER"
# Hold through cleanup and recording, including concurrent direct/RC calls.
exec 9>>"$(dirname "$LEDGER")/gate-locks/$TREE.lock"
python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null \
  || refuse "tree $TREE is already being gated"
recorded() {
  awk -F'\t' -v key="$KEY" -v stage="$1" '$1 == key && $2 == stage' "$LEDGER" | tail -1
}
failed="$(awk -F'\t' -v key="$KEY" '$1 == key && $3 == "failed"' "$LEDGER" | tail -1)"
if [[ -n "$failed" ]]; then
  printf 'gate: tree %s already FAILED %s (log %s).\n' "$TREE" "$(cut -f2 <<<"$failed")" "$(cut -f6 <<<"$failed")" >&2
  printf '%s\n' "Fix the code and gate the changed tree. For infrastructure failures only, the coordinator removes the failed ledger line and uses GATE_RERUN_REASON='<reason>'." >&2
  exit 1
fi
pending=""
for stage in $REQUESTED; do
  case "$stage" in checks|unit|artifacts|integration) ;; *) refuse "unknown stage '$stage'" ;; esac
  if [[ "$(recorded "$stage" | cut -f3)" == passed ]]; then
    printf 'gate: tree %s already passed %s; original log %s\n' "$TREE" "$stage" "$(recorded "$stage" | cut -f6)"
  elif [[ " $pending " != *" $stage "* ]]; then
    pending="${pending:+$pending }$stage"
  fi
done
if [[ -z "$pending" ]]; then
  printf 'gate: tree %s passed %s; no stages run\n' "$TREE" "$REQUESTED"
  exit 0
fi

run_candidate() (
set -euo pipefail
command -v docker >/dev/null || refuse "docker is unavailable"
docker info >/dev/null || refuse "docker daemon is unavailable"

if ! work="$(mktemp -d "/tmp/aweb-candidate-work.XXXXXX")"; then
  refuse "could not allocate the candidate work directory"
fi
work="$(cd "$work" && pwd -P)"
go_mod_cache="$work/go-mod"
mkdir -p "$go_mod_cache"
run_suffix="$(printf '%s' "${work##*.}" | tr '[:upper:]' '[:lower:]')"
gate_run_id="aweb-candidate-${SOURCE_SHA:0:12}-${run_suffix}"
resource_label="$gate_run_id"
runner_name="$gate_run_id-runner"
seed_name="$gate_run_id-seed"
workspace_volume="$gate_run_id-workspace"
IMAGE="aweb-candidate-gate:$gate_run_id"
builder_name="$gate_run_id"
buildx_config="$work/buildx"
docker_bind_root="$work/docker-bind"
runner_cpus="${AWEB_CANDIDATE_RUNNER_CPUS:-2}"
runner_memory="${AWEB_CANDIDATE_RUNNER_MEMORY:-8g}"
runner_pids="${AWEB_CANDIDATE_RUNNER_PIDS:-2048}"
builder_cpus="${AWEB_CANDIDATE_BUILDER_CPUS:-2}"
builder_memory="${AWEB_CANDIDATE_BUILDER_MEMORY:-6g}"
builder_memory_swap="${AWEB_CANDIDATE_BUILDER_MEMORY_SWAP:-$builder_memory}"
builder_pids="${AWEB_CANDIDATE_BUILDER_PIDS:-2048}"
service_cpus="${AWEB_CANDIDATE_SERVICE_CPUS:-1}"
service_memory="${AWEB_CANDIDATE_SERVICE_MEMORY:-1g}"
postgres_memory="${AWEB_CANDIDATE_POSTGRES_MEMORY:-6g}"
postgres_tmpfs="${AWEB_CANDIDATE_POSTGRES_TMPFS:-4g}"
service_pids="${AWEB_CANDIDATE_SERVICE_PIDS:-512}"
redis_cpus="${AWEB_CANDIDATE_REDIS_CPUS:-0.5}"
redis_memory="${AWEB_CANDIDATE_REDIS_MEMORY:-256m}"
redis_pids="${AWEB_CANDIDATE_REDIS_PIDS:-256}"
sibling_cpus="${AWEB_CANDIDATE_SIBLING_CPUS:-2}"
sibling_memory="${AWEB_CANDIDATE_SIBLING_MEMORY:-4g}"
sibling_pids="${AWEB_CANDIDATE_SIBLING_PIDS:-1024}"
suite_projects=(
  "$gate_run_id-channel"
  "$gate_run_id-user"
  "$gate_run_id-fed-auth"
  "aweb-fed-e2e-${SOURCE_SHA:0:12}${run_suffix}"
  "$gate_run_id-library"
)
# Install cleanup before the first Docker allocation. Logs outlive the run.
[[ "$LOG_DIR" == "/tmp/aweb-candidate-gate-$SOURCE_SHA" ]] || refuse "unsafe log directory"
rm -rf -- "$LOG_DIR"
mkdir -p "$LOG_DIR"
: > "$LOG_DIR/owned-resources.tsv"
printf '%s\n' "$run_id" > "$LOG_DIR/run-id"
source "$ROOT/scripts/candidate-cleanup.sh"
trap 'cleanup "$?"' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
checkout="$work/aweb"
git clone --local --no-hardlinks "$ROOT" "$checkout" >/dev/null
git -C "$checkout" checkout --detach "$SOURCE_SHA" >/dev/null
git -C "$checkout" remote set-url origin "$checkout"
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$SOURCE_SHA" ]] || refuse "clone selected the wrong SHA"
git -C "$checkout" diff --quiet && git -C "$checkout" diff --cached --quiet \
  || refuse "cloned checkout is not clean"
[[ -z "$(git -C "$checkout" status --porcelain --untracked-files=all)" ]] \
  || refuse "cloned checkout contains untracked input"

record_input() {
  local name="$1" path="$2" repo sha tree
  repo="$(git -C "$path" rev-parse --show-toplevel 2>/dev/null)" \
    || refuse "$name input is not a git checkout"
  [[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] \
    || refuse "$name input checkout is dirty"
  sha="$(git -C "$repo" rev-parse HEAD)"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || refuse "$name input has no exact SHA"
  local selected="${name}_input_sha"
  [[ "$sha" == "${!selected}" ]] || refuse "$name input changed after the ledger lookup"
  printf '%s\n' "$sha" > "$LOG_DIR/$name-sha"
  repo="$(cd "$repo" && pwd -P)"
  tree="$sha"
  [[ "$path" == "$repo" ]] || tree="$sha:${path#"$repo"/}"
  mkdir -p "$work/inputs/$name"
  git -C "$repo" archive "$tree" | tar -xf - -C "$work/inputs/$name"
}
record_input library "$LIBRARY_E2E_LIBRARY_CONTEXT"
record_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC"
LIBRARY_E2E_LIBRARY_CONTEXT="$work/inputs/library"
LIBRARY_E2E_BLUEPRINT_SRC="$work/inputs/blueprints"
printf '%s\n' "$SOURCE_SHA" > "$LOG_DIR/source-sha"
printf 'NOT RELEVANT: OSS packages do not bundle Library; this input is used only by its activation journey.\n' \
  > "$LOG_DIR/compatibility.txt"

python3 "$ROOT/scripts/candidate-host-pressure.py" capture "$LOG_DIR/host-before.json"
mkdir -p "$buildx_config"
printf 'builder\t%s\n' "$builder_name" >> "$LOG_DIR/owned-resources.tsv"
BUILDX_CONFIG="$buildx_config" docker buildx create \
  --name "$builder_name" --driver docker-container \
  "unix:///var/run/docker.sock" --bootstrap >/dev/null \
  || refuse "could not provision the run-owned release builder"
builder_container="buildx_buildkit_${builder_name}0"
docker update --cpus "$builder_cpus" --memory "$builder_memory" --memory-swap "$builder_memory_swap" --pids-limit "$builder_pids" \
  "$builder_container" >/dev/null \
  || refuse "could not apply candidate builder resource limits"

BUILDX_CONFIG="$buildx_config" docker buildx build --builder "$builder_name" --load --pull \
  --label "aweb.candidate-gate=$resource_label" \
  -f "$checkout/candidate-gate/Dockerfile" -t "$IMAGE" "$checkout/candidate-gate" \
  2>&1 | tee "$LOG_DIR/docker-build.log"

# Record the run's mutable inputs in the evidence (adoption compares them):
# the resolved base-image digest and the tracked lock-set hash. Package
# manager fetches inside the build are not recorded and adoption names that.
base_ref="$(awk '/^FROM /{print $2; exit}' "$checkout/candidate-gate/Dockerfile")"
base_digest="$(docker image inspect "$base_ref" --format '{{join .RepoDigests ","}}' 2>/dev/null || echo unresolved)"
locks_digest="$(git -C "$checkout" ls-files -s -- '*uv.lock' | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())')"
printf 'base\t%s\t%s\nlocks\t%s\n' "$base_ref" "$base_digest" "$locks_digest" > "$LOG_DIR/inputs.tsv"
printf 'runner\tcpus=%s\tmemory=%s\tpids=%s\nbuilder\tcpus=%s\tmemory=%s\tmemory_swap=%s\tpids=%s\nservice\tcpus=%s\tmemory=%s\tpids=%s\nredis\tcpus=%s\tmemory=%s\tpids=%s\nsibling\tcpus=%s\tmemory=%s\tpids=%s\n' \
  "$runner_cpus" "$runner_memory" "$runner_pids" \
  "$builder_cpus" "$builder_memory" "$builder_memory_swap" "$builder_pids" \
  "$service_cpus" "$service_memory" "$service_pids" \
  "$redis_cpus" "$redis_memory" "$redis_pids" \
  "$sibling_cpus" "$sibling_memory" "$sibling_pids" > "$LOG_DIR/resource-limits.tsv"
printf 'postgres\tmemory=%s\tmemory_swap=%s\ttmpfs=%s\n' "$postgres_memory" "$postgres_memory" "$postgres_tmpfs" >> "$LOG_DIR/resource-limits.tsv"
owned_network="$gate_run_id-network"
docker network create --label "aweb.candidate-gate=$resource_label" "$owned_network" >/dev/null
pg_name="${owned_network}-postgres"
redis_name="${owned_network}-redis"
docker volume create --label "aweb.candidate-gate=$resource_label" "$redis_name-data" >/dev/null
pg_id="$(docker run --detach --network "$owned_network" --name "$pg_name" \
  --label "aweb.candidate-gate=$resource_label" \
  --cpus "$service_cpus" --memory "$postgres_memory" --memory-swap "$postgres_memory" --pids-limit "$service_pids" \
  --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,size=$postgres_tmpfs" \
  --env POSTGRES_USER=postgres --env POSTGRES_PASSWORD=postgres --env POSTGRES_DB=postgres \
  --health-cmd "$(cat "$ROOT/scripts/test-postgres-storage.sh")" \
  --health-interval 2s --health-timeout 5s --health-retries 45 postgres:17)"
redis_id="$(docker run --detach --network "$owned_network" --name "$redis_name" \
  --label "aweb.candidate-gate=$resource_label" \
  --cpus "$redis_cpus" --memory "$redis_memory" --pids-limit "$redis_pids" \
  -v "$redis_name-data:/data" \
  --health-cmd 'redis-cli ping' --health-interval 2s --health-timeout 5s --health-retries 45 redis:7)"
for container in "$pg_id" "$redis_id"; do
  for _ in $(seq 1 60); do
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == healthy ]] && break
    sleep 1
  done
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == healthy ]] \
    || refuse "gate service failed health: $container"
done

# Production parity: the app role there carries search_path=pg_catalog as its
# role default; the gate's role must too, or an unqualified reference passes
# locally and fails in production. Applied and read back; refuse if unset.
docker exec "$pg_id" psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c 'ALTER ROLE postgres SET search_path = pg_catalog' >/dev/null \
  || refuse "could not apply the production search_path role default"
# Verified BY CONNECTING: a fresh session must report the default with
# source='user' - a statement applied to a role that exists but is not the
# connecting one succeeds and changes nothing.
applied="$(docker exec "$pg_id" psql -At -U postgres -d postgres \
  -c "SELECT setting || '|' || source FROM pg_settings WHERE name = 'search_path'")"
[[ "$applied" == "pg_catalog|user" ]] \
  || refuse "search_path role default not in effect for the connecting role: $applied"

# Pre-provision pgcrypto in public in template1 and the default database:
# per-test databases are created fresh and inherit template1, and migration
# 001's unqualified CREATE EXTENSION IF NOT EXISTS then no-ops instead of
# colliding with pg_catalog's built-in gen_random_uuid under the pinned
# search_path - matching production, where the extension already exists.
for db in postgres template1; do
  docker exec "$pg_id" psql -v ON_ERROR_STOP=1 -U postgres -d "$db" \
    -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public' >/dev/null \
    || refuse "could not pre-provision pgcrypto in $db"
  ext_schema="$(docker exec "$pg_id" psql -At -U postgres -d "$db" \
    -c "SELECT extnamespace::regnamespace::text FROM pg_extension WHERE extname = 'pgcrypto'")"
  [[ "$ext_schema" == "public" ]] \
    || refuse "pgcrypto pre-provision did not land in public for $db: '$ext_schema'"
done
mkdir -p "$docker_bind_root" "$checkout/.candidate-home"
socket_gid="$(docker run --rm \
  --label "aweb.candidate-gate=$resource_label" \
  --cpus "$redis_cpus" --memory "$redis_memory" --pids-limit "$redis_pids" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE" stat -c '%g' /var/run/docker.sock)"
read -r a2a_aweb_port a2a_awid_port a2a_redis_port a2a_pg_port a2a_gateway_port fed_awid_port fed_alpha_port fed_beta_port < <(
  python3 - <<'PY'
import socket
sockets=[]
try:
    for _ in range(8):
        sock=socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)

# Copy the exact checkout and inputs through the Docker API. The host checkout
# is never mounted into a container; extracted dependency trees stay in Docker.
docker volume create --label "aweb.candidate-gate=$resource_label" "$workspace_volume" >/dev/null
docker create --name "$seed_name" --label "aweb.candidate-gate=$resource_label" \
  --cpus "$runner_cpus" --memory "$runner_memory" --pids-limit "$runner_pids" \
  -v "$workspace_volume:$work" "$IMAGE" chown -R "$(id -u):$(id -g)" "$work" >/dev/null
docker cp "$work/." "$seed_name:$work"
docker start --attach "$seed_name"
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$seed_name")" == 0 ]] \
  || refuse "could not initialize Docker-owned workspace permissions"
docker rm -v "$seed_name" >/dev/null

set +e
docker run --rm --init \
  --name "$runner_name" \
  --label "aweb.candidate-gate=$resource_label" \
  --cpus "$runner_cpus" \
  --memory "$runner_memory" \
  --pids-limit "$runner_pids" \
  --network "$owned_network" \
  --user "$(id -u):$(id -g)" \
  --group-add "$socket_gid" \
  --add-host aweb-docker.test:host-gateway \
  -e HOME="$checkout/.candidate-home" \
  -e PATH="$checkout/candidate-gate/bin:/usr/local/go/bin:/opt/uv:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  -e AWEB_CANDIDATE_REAL_DOCKER=/usr/bin/docker \
  -e AWEB_CANDIDATE_RESOURCE_LABEL="$resource_label" \
  -e AWEB_CANDIDATE_SIBLING_CPUS="$sibling_cpus" \
  -e AWEB_CANDIDATE_SIBLING_MEMORY="$sibling_memory" \
  -e AWEB_CANDIDATE_SIBLING_PIDS="$sibling_pids" \
  -e DOCKER_BUILDKIT=1 \
  -e COMPOSE_DOCKER_CLI_BUILD=1 \
  -e COMPOSE_BAKE=true \
  -e CANDIDATE_SOURCE_SHA="$SOURCE_SHA" \
  -e CANDIDATE_RUNNER_NAME="$runner_name" \
  -e CANDIDATE_CHECKOUT_ROOT="$checkout" \
  -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0="$checkout" \
  -e CLI_VERSION="${CLI_VERSION:-}" \
  -e A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-}" \
  -e LIBRARY_E2E_LIBRARY_CONTEXT="$LIBRARY_E2E_LIBRARY_CONTEXT" \
  -e LIBRARY_E2E_BLUEPRINT_SRC="$LIBRARY_E2E_BLUEPRINT_SRC" \
  -e CANDIDATE_LOG_DIR="$LOG_DIR" \
  -e CANDIDATE_RESOURCE_MANIFEST="$LOG_DIR/owned-resources.tsv" \
  -e BUILDX_CONFIG="$buildx_config" \
  -e BUILDX_BUILDER="$builder_name" \
  -e UV_CACHE_DIR=/tmp/uv-cache \
  -e UV_LINK_MODE=copy \
  -e GOCACHE=/tmp/go-build \
  -e GOMODCACHE="$go_mod_cache" \
  -e GOFLAGS=-modcacherw \
  -e NPM_CONFIG_CACHE=/tmp/npm-cache \
  -e AWEB_DOCKER_BIND_ROOT="$docker_bind_root" \
  -e AWEB_DOCKER_PUBLISHED_HOST=aweb-docker.test \
  -e AWEB_A2A_E2E_PORT="$a2a_aweb_port" \
  -e AWID_A2A_E2E_PORT="$a2a_awid_port" \
  -e AWEB_A2A_E2E_REDIS="$a2a_redis_port" \
  -e AWEB_A2A_E2E_PG="$a2a_pg_port" \
  -e A2A_GW_E2E_PORT="$a2a_gateway_port" \
  -e AWID_FED_E2E_PORT="$fed_awid_port" \
  -e AWEB_ALPHA_E2E_PORT="$fed_alpha_port" \
  -e AWEB_BETA_E2E_PORT="$fed_beta_port" \
  -e AWEB_SKEW_PROJECT_TOKEN="${suite_projects[0]}" \
  -e AWEB_E2E_PROJECT="${suite_projects[1]}" \
  -e AWEB_FED_AUTH_PROJECT="${suite_projects[2]}" \
  -e AWEB_FED_E2E_PROJECT="${suite_projects[3]}" \
  -e LIBRARY_E2E_PROJECT="${suite_projects[4]}" \
  -e TEST_DB_HOST="$pg_name" \
  -e TEST_DB_PORT=5432 \
  -e TEST_DB_USER=postgres \
  -e TEST_DB_PASSWORD=postgres \
  -e PGHOST="$pg_name" \
  -e PGPORT=5432 \
  -e PGUSER=postgres \
  -e PGPASSWORD=postgres \
  -e PGDATABASE=postgres \
  -e REDIS_URL="redis://$redis_name:6379/0" \
  -e CANDIDATE_GATE_IMAGE="$IMAGE" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$workspace_volume:$work" \
  -v "$docker_bind_root:$docker_bind_root" \
  -v "$LOG_DIR:$LOG_DIR" \
  -w "$checkout" \
  "$IMAGE" \
  bash scripts/candidate-suite.sh "$pending" \
  2>&1 | tee "$LOG_DIR/gate.log"
status="${PIPESTATUS[0]}"
set -e

if [[ "$status" -ne 0 ]]; then
  printf 'candidate gate FAILED; logs: %s\n' "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log" >&2
  exit "$status"
fi
printf 'candidate gate PASSED at %s; logs: %s\n' \
  "$SOURCE_SHA" "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log"

)

# The child owns Docker cleanup. A stage is recorded only after it exits, and
# only from this invocation's logs; stale logs cannot supply a missing result.
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_log="$LEDGER_LOGS/${KEY:0:12}-run-$run_id.log"
set +e
run_candidate 2>&1 | tee "$run_log"
status="${PIPESTATUS[0]}"
set -e
finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[[ "$status" != 130 && "$status" != 143 ]] || exit "$status"
if [[ ! -f "$LOG_DIR/run-id" || "$(cat "$LOG_DIR/run-id")" != "$run_id" ]]; then
  printf 'gate: stopped before allocation; nothing recorded\n' >&2
  exit "$status"
fi
record() {
  local stage="$1" result="$2" source="$3" log note=""
  log="$LEDGER_LOGS/${KEY:0:12}-$stage-$run_id.log"
  cp "$source" "$log"
  [[ -z "${GATE_RERUN_REASON:-}" ]] || note="rerun after $GATE_RERUN_REASON"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$KEY" "$stage" "$result" "$SOURCE_SHA" "" "$log" "$OWNER" "$started" "$finished" "$note" >>"$LEDGER"
}
for stage in $pending; do
  if [[ -f "$LOG_DIR/summary.tsv" ]] && grep -q "^$stage"$'\tPASSED\t' "$LOG_DIR/summary.tsv"; then
    record "$stage" passed "$LOG_DIR/$stage.log"
  elif [[ -f "$LOG_DIR/$stage.log" ]]; then
    record "$stage" failed "$LOG_DIR/$stage.log"
    status=1
    break
  else
    record setup failed "$run_log"
    status=1
    break
  fi
done
if [[ ! -f "$LOG_DIR/wrapper-verdict.log" ]] \
   || ! grep -q '^candidate gate cleanup PASSED$' "$LOG_DIR/wrapper-verdict.log"; then
  record cleanup failed "$run_log"
  status=1
fi
exit "$status"
