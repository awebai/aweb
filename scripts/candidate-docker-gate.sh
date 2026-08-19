#!/usr/bin/env bash
# Complete local Docker gate for one exact OSS candidate commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
IMAGE="aweb-candidate-gate:${SOURCE_SHA:0:12}"

# Persistent caches, shared across gate runs. Determinism is carried by the
# committed lockfiles (uv.lock, go.sum, package-lock.json), whose hashes are
# recorded in inputs.tsv; every store here is content-addressed or checksum
# verified against those locks, so a warm hit yields the same bytes as a cold
# fetch. The uv and go paths match the ones the Makefile targets already pin.
CACHE_ROOT="${AWEB_CANDIDATE_CACHE:-/tmp/aweb-candidate-cache}"
mkdir -p "$CACHE_ROOT/uv" "$CACHE_ROOT/go-build" "$CACHE_ROOT/go-mod" "$CACHE_ROOT/npm"

[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || refuse "CANDIDATE_SOURCE_SHA must be a full lowercase SHA"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] \
  || refuse "source checkout is dirty or has untracked files"
git -C "$ROOT" fetch --quiet origin main
git -C "$ROOT" merge-base --is-ancestor "$SOURCE_SHA" origin/main \
  || refuse "source SHA is not on the synchronized origin/main history"
[[ -d "$LIBRARY_E2E_LIBRARY_CONTEXT" ]] || refuse "Library input is missing"
[[ -d "$LIBRARY_E2E_BLUEPRINT_SRC" ]] || refuse "blueprint input is missing"
command -v docker >/dev/null || refuse "docker is unavailable"
docker info >/dev/null || refuse "docker daemon is unavailable"
CLI_VERSION="${CLI_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" aw-v)}"
A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" a2a-gw-v)}"

if ! work="$(mktemp -d "/tmp/aweb-candidate-work.XXXXXX")"; then
  refuse "could not allocate the candidate work directory"
fi
work="$(cd "$work" && pwd -P)"
owned_containers=()
owned_network=""
# The builder and its layer cache persist across gate runs; the suite bounds
# the cache with a keep-storage prune after the largest build.
builder_name="aweb-candidate-gate"
buildx_config="${AWEB_CANDIDATE_BUILDX:-/tmp/aweb-candidate-buildx}"
docker_bind_root=""
gate_run_id="aweb-candidate-suite-${SOURCE_SHA:0:12}-$$"
suite_projects=(
  "$gate_run_id-channel"
  "$gate_run_id-user"
  "$gate_run_id-fed-auth"
  "aweb-fed-e2e-${SOURCE_SHA:0:12}$$"
  "$gate_run_id-library"
)
cleanup() {
  local original_status=$? cleanup_status=0 project resource ids
  local -a list remove
  trap - EXIT
  set +e
  for project in "${suite_projects[@]}"; do
    for resource in container network volume image; do
      case "$resource" in
        container) list=(docker ps -aq); remove=(docker rm -f) ;;
        network) list=(docker network ls -q); remove=(docker network rm) ;;
        volume) list=(docker volume ls -q); remove=(docker volume rm -f) ;;
        image) list=(docker images -q); remove=(docker image rm -f) ;;
      esac
      ids="$("${list[@]}" --filter "label=com.docker.compose.project=$project" | sort -u)" \
        || cleanup_status=1
      [[ -z "$ids" ]] || "${remove[@]}" $ids >/dev/null 2>&1 || cleanup_status=1
      ids="$("${list[@]}" --filter "label=com.docker.compose.project=$project")" \
        || cleanup_status=1
      if [[ -n "$ids" ]]; then
        printf 'candidate gate cleanup residue: %s %s\n' "$project" "$resource" >&2
        cleanup_status=1
      fi
    done
  done
  [[ "${#owned_containers[@]}" -eq 0 ]] \
    || docker rm -f "${owned_containers[@]}" >/dev/null 2>&1 \
    || cleanup_status=1
  [[ -z "$owned_network" ]] || docker network rm "$owned_network" >/dev/null 2>&1 \
    || cleanup_status=1
  # Bound the persistent builder's layer cache on every invocation, whatever
  # tests ran. Best-effort: a failed cleanup prune is not this run's residue.
  BUILDX_CONFIG="$buildx_config" docker buildx prune --all --force \
    --keep-storage=10GB --builder "$builder_name" >/dev/null 2>&1 \
    || printf 'candidate gate: builder cache prune skipped\n' >&2
  docker image rm "$IMAGE" >/dev/null 2>&1 || true
  for ids in "${owned_containers[@]}"; do
    ! docker container inspect "$ids" >/dev/null 2>&1 || cleanup_status=1
  done
  [[ -z "$owned_network" ]] || ! docker network inspect "$owned_network" >/dev/null 2>&1 \
    || cleanup_status=1
  ! docker image inspect "$IMAGE" >/dev/null 2>&1 || cleanup_status=1
  case "$work" in
    /|"$ROOT"|"$ROOT"/*) cleanup_status=1 ;;
    */aweb-candidate-work.*) rm -rf -- "$work" || cleanup_status=1 ;;
    *) cleanup_status=1 ;;
  esac
  if [[ "$cleanup_status" -ne 0 ]]; then
    printf 'candidate gate cleanup FAILED\n' | tee -a "$LOG_DIR/wrapper-verdict.log" >&2
  else
    printf 'candidate gate cleanup PASSED\n' | tee -a "$LOG_DIR/wrapper-verdict.log"
  fi
  [[ "$original_status" -ne 0 ]] && exit "$original_status"
  exit "$cleanup_status"
}
trap cleanup EXIT
checkout="$work/aweb"
git clone --local --no-hardlinks "$ROOT" "$checkout" >/dev/null
git -C "$checkout" checkout --detach "$SOURCE_SHA" >/dev/null
git -C "$checkout" remote set-url origin "$checkout"
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$SOURCE_SHA" ]] || refuse "clone selected the wrong SHA"
git -C "$checkout" diff --quiet && git -C "$checkout" diff --cached --quiet \
  || refuse "cloned checkout is not clean"
[[ -z "$(git -C "$checkout" status --porcelain --untracked-files=all)" ]] \
  || refuse "cloned checkout contains untracked input"

[[ "$LOG_DIR" == "/tmp/aweb-candidate-gate-$SOURCE_SHA" && "$LOG_DIR" != / && "$LOG_DIR" != "$ROOT" ]] \
  || refuse "unsafe candidate log directory: $LOG_DIR"
rm -rf -- "$LOG_DIR"
mkdir -p "$LOG_DIR"
record_input() {
  local name="$1" path="$2" repo sha
  repo="$(git -C "$path" rev-parse --show-toplevel 2>/dev/null)" \
    || refuse "$name input is not a git checkout"
  [[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] \
    || refuse "$name input checkout is dirty"
  sha="$(git -C "$repo" rev-parse HEAD)"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || refuse "$name input has no exact SHA"
  printf '%s\n' "$sha" > "$LOG_DIR/$name-sha"
}
record_input library "$LIBRARY_E2E_LIBRARY_CONTEXT"
record_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC"
printf '%s\n' "$SOURCE_SHA" > "$LOG_DIR/source-sha"
printf 'NOT RELEVANT: OSS packages do not bundle Library; this input is used only by its activation journey.\n' \
  > "$LOG_DIR/compatibility.txt"

docker build --pull -f "$checkout/candidate-gate/Dockerfile" -t "$IMAGE" "$checkout/candidate-gate" \
  2>&1 | tee "$LOG_DIR/docker-build.log"

# Record the run's mutable inputs in the evidence (adoption compares them):
# the resolved base-image digest and the tracked lock-set hash. Package
# manager fetches inside the build are not recorded and adoption names that.
base_ref="$(awk '/^FROM /{print $2; exit}' "$checkout/candidate-gate/Dockerfile")"
base_digest="$(docker image inspect "$base_ref" --format '{{join .RepoDigests ","}}' 2>/dev/null || echo unresolved)"
locks_digest="$(git -C "$checkout" ls-files -s -- '*uv.lock' | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())')"
printf 'base\t%s\t%s\nlocks\t%s\n' "$base_ref" "$base_digest" "$locks_digest" > "$LOG_DIR/inputs.tsv"
owned_network="aweb-candidate-gate-${SOURCE_SHA:0:12}-$$"
docker network create "$owned_network" >/dev/null
pg_name="${owned_network}-postgres"
redis_name="${owned_network}-redis"
pg_id="$(docker run --detach --network "$owned_network" --name "$pg_name" \
  --env POSTGRES_USER=postgres --env POSTGRES_PASSWORD=postgres --env POSTGRES_DB=postgres \
  --health-cmd 'pg_isready -U postgres -d postgres' \
  --health-interval 2s --health-timeout 5s --health-retries 45 postgres:17)"
owned_containers+=("$pg_id")
redis_id="$(docker run --detach --network "$owned_network" --name "$redis_name" \
  --health-cmd 'redis-cli ping' --health-interval 2s --health-timeout 5s --health-retries 45 redis:7)"
owned_containers+=("$redis_id")
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
docker_bind_root="$checkout/.candidate-docker-bind"
mkdir -p "$buildx_config" "$docker_bind_root" "$checkout/.candidate-home"
# Reuse the persistent builder when it is healthy; recreate it when its
# container or state has been removed since the last run. Gate invocations are
# expected not to overlap on one host (they share this builder and the cache
# root); a lost creation race is tolerated below, and the final inspect is the
# authority either way.
if ! BUILDX_CONFIG="$buildx_config" docker buildx inspect --bootstrap "$builder_name" >/dev/null 2>&1; then
  BUILDX_CONFIG="$buildx_config" docker buildx rm "$builder_name" >/dev/null 2>&1 || true
  BUILDX_CONFIG="$buildx_config" docker buildx create \
    --name "$builder_name" --driver docker-container \
    "unix:///var/run/docker.sock" --bootstrap >/dev/null 2>&1 || true
  BUILDX_CONFIG="$buildx_config" docker buildx inspect --bootstrap "$builder_name" >/dev/null \
    || refuse "could not provision the persistent release builder"
fi
socket_gid="$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE" stat -c '%g' /var/run/docker.sock)"
read -r a2a_aweb_port a2a_awid_port a2a_redis_port a2a_pg_port a2a_gateway_port < <(
  python3 - <<'PY'
import socket
sockets=[]
try:
    for _ in range(5):
        sock=socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)

set +e
docker run --rm --init \
  --network "$owned_network" \
  --user "$(id -u):$(id -g)" \
  --group-add "$socket_gid" \
  --add-host aweb-docker.test:host-gateway \
  -e HOME="$checkout/.candidate-home" \
  -e CANDIDATE_SOURCE_SHA="$SOURCE_SHA" \
  -e CANDIDATE_CHECKOUT_ROOT="$checkout" \
  -e CLI_VERSION="${CLI_VERSION:-}" \
  -e A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-}" \
  -e LIBRARY_E2E_LIBRARY_CONTEXT="$LIBRARY_E2E_LIBRARY_CONTEXT" \
  -e LIBRARY_E2E_BLUEPRINT_SRC="$LIBRARY_E2E_BLUEPRINT_SRC" \
  -e CANDIDATE_LOG_DIR="$LOG_DIR" \
  -e BUILDX_CONFIG="$buildx_config" \
  -e BUILDX_BUILDER="$builder_name" \
  -e UV_CACHE_DIR=/tmp/uv-cache \
  -e UV_LINK_MODE=copy \
  -e GOCACHE=/tmp/go-build \
  -e GOMODCACHE=/tmp/go-mod \
  -e NPM_CONFIG_CACHE=/tmp/npm-cache \
  -e AWEB_DOCKER_BIND_ROOT="$docker_bind_root" \
  -e AWEB_DOCKER_PUBLISHED_HOST=aweb-docker.test \
  -e AWEB_A2A_E2E_PORT="$a2a_aweb_port" \
  -e AWID_A2A_E2E_PORT="$a2a_awid_port" \
  -e AWEB_A2A_E2E_REDIS="$a2a_redis_port" \
  -e AWEB_A2A_E2E_PG="$a2a_pg_port" \
  -e A2A_GW_E2E_PORT="$a2a_gateway_port" \
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
  -v "$buildx_config:$buildx_config" \
  -v "$CACHE_ROOT/uv:/tmp/uv-cache" \
  -v "$CACHE_ROOT/go-build:/tmp/go-build" \
  -v "$CACHE_ROOT/go-mod:/tmp/go-mod" \
  -v "$CACHE_ROOT/npm:/tmp/npm-cache" \
  -v "$checkout:$checkout" \
  -v "$LOG_DIR:$LOG_DIR" \
  -v "$LIBRARY_E2E_LIBRARY_CONTEXT:$LIBRARY_E2E_LIBRARY_CONTEXT:ro" \
  -v "$LIBRARY_E2E_BLUEPRINT_SRC:$LIBRARY_E2E_BLUEPRINT_SRC:ro" \
  -w "$checkout" \
  "$IMAGE" \
  bash scripts/candidate-suite.sh \
  2>&1 | tee "$LOG_DIR/gate.log"
status="${PIPESTATUS[0]}"
set -e

if [[ "$status" -ne 0 ]]; then
  printf 'candidate gate FAILED; logs: %s\n' "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log" >&2
  exit "$status"
fi
printf 'candidate gate PASSED at %s; logs: %s\n' \
  "$SOURCE_SHA" "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log"
