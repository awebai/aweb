#!/usr/bin/env bash
# Internal clean-Docker gate invoked by release preparation; not an operator command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_REPO="$(cd "$(dirname "$(git -C "$ROOT" rev-parse --git-common-dir)")" && pwd)"
SOURCE_SHA="${RELEASE_SOURCE_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
RELEASE_BASE_SHA="${RELEASE_BASE_SHA:-$(git -C "$ROOT" merge-base "$SOURCE_SHA" origin/main)}"
LIBRARY_E2E_LIBRARY_CONTEXT="${LIBRARY_E2E_LIBRARY_CONTEXT:-$COMMON_REPO/../library}"
LIBRARY_E2E_BLUEPRINT_SRC="${LIBRARY_E2E_BLUEPRINT_SRC:-$COMMON_REPO/../blueprints/team}"
LOG_DIR="${RELEASE_GATE_LOG_DIR:-/tmp/aweb-release-gate-$SOURCE_SHA}"
IMAGE="aweb-release-gate:${SOURCE_SHA:0:12}"

refuse() { printf 'release gate refused: %s\n' "$*" >&2; exit 2; }
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || refuse "RELEASE_SOURCE_SHA must be a full lowercase SHA"
[[ "$RELEASE_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || refuse "RELEASE_BASE_SHA must be a full lowercase SHA"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] \
  || refuse "source checkout is dirty or has untracked files"
git -C "$ROOT" cat-file -e "$SOURCE_SHA^{commit}" || refuse "source SHA is unavailable"
git -C "$ROOT" merge-base --is-ancestor "$RELEASE_BASE_SHA" "$SOURCE_SHA" \
  || refuse "comparison base is not an ancestor of the source SHA"
[[ -d "$LIBRARY_E2E_LIBRARY_CONTEXT" ]] || refuse "Library input is missing"
[[ -d "$LIBRARY_E2E_BLUEPRINT_SRC" ]] || refuse "blueprint input is missing"
command -v docker >/dev/null || refuse "docker is unavailable"
docker info >/dev/null || refuse "docker daemon is unavailable"

work="$(mktemp -d)"
owned_containers=()
owned_network=""
cleanup() {
  if [[ "${#owned_containers[@]}" -gt 0 ]]; then
    docker rm -f "${owned_containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$owned_network" ]]; then
    docker network rm "$owned_network" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
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

rm -rf "$LOG_DIR"
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
printf '%s\n' "$RELEASE_BASE_SHA" > "$LOG_DIR/comparison-base-sha"
printf 'NOT RELEVANT: this slice changes only the release gate mechanism, not a released runtime boundary.\n' \
  > "$LOG_DIR/compatibility.txt"

docker build --pull -f "$checkout/release-gate/Dockerfile" -t "$IMAGE" "$checkout/release-gate" \
  2>&1 | tee "$LOG_DIR/docker-build.log"

owned_network="aweb-release-gate-${SOURCE_SHA:0:12}-$$"
docker network create "$owned_network" >/dev/null
pg_name="${owned_network}-postgres"
redis_name="${owned_network}-redis"
pg_id="$(docker run --detach --network "$owned_network" --name "$pg_name" \
  --env POSTGRES_USER=postgres --env POSTGRES_PASSWORD=postgres --env POSTGRES_DB=postgres \
  --health-cmd 'pg_isready -U postgres -d postgres' \
  --health-interval 2s --health-timeout 5s --health-retries 45 postgres:17)"
redis_id="$(docker run --detach --network "$owned_network" --name "$redis_name" \
  --health-cmd 'redis-cli ping' --health-interval 2s --health-timeout 5s --health-retries 45 redis:7)"
owned_containers+=("$pg_id" "$redis_id")
for container in "$pg_id" "$redis_id"; do
  for _ in $(seq 1 60); do
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == healthy ]] && break
    sleep 1
  done
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == healthy ]] \
    || refuse "gate service failed health: $container"
done
mkdir -p "$checkout/.release-home"

set +e
docker run --rm --init \
  --network "$owned_network" \
  -e HOME="$checkout/.release-home" \
  -e RELEASE_BASE_SHA="$RELEASE_BASE_SHA" \
  -e LIBRARY_E2E_LIBRARY_CONTEXT="$LIBRARY_E2E_LIBRARY_CONTEXT" \
  -e LIBRARY_E2E_BLUEPRINT_SRC="$LIBRARY_E2E_BLUEPRINT_SRC" \
  -e RELEASE_GATE_LOG_DIR="$LOG_DIR" \
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
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$checkout:$checkout" \
  -v "$LOG_DIR:$LOG_DIR" \
  -v "$LIBRARY_E2E_LIBRARY_CONTEXT:$LIBRARY_E2E_LIBRARY_CONTEXT:ro" \
  -v "$LIBRARY_E2E_BLUEPRINT_SRC:$LIBRARY_E2E_BLUEPRINT_SRC:ro" \
  -w "$checkout" \
  "$IMAGE" \
  python3 scripts/release_gate_runner.py \
    --map release-gate/suite-map.tsv --log-dir "$LOG_DIR" \
  2>&1 | tee "$LOG_DIR/gate.log"
status="${PIPESTATUS[0]}"
set -e

[[ -f "$LOG_DIR/summary.tsv" ]] || refuse "gate produced no summary"
if grep -q $'\tNOT RUN\t' "$LOG_DIR/summary.tsv"; then status=1; fi
if grep -q $'\tFAILED\t' "$LOG_DIR/summary.tsv"; then status=1; fi
if [[ "$status" -ne 0 ]]; then
  printf 'release gate FAILED; logs: %s\n' "$LOG_DIR" >&2
  exit "$status"
fi
printf 'release gate PASSED at %s; logs: %s\n' "$SOURCE_SHA" "$LOG_DIR"
