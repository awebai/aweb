#!/usr/bin/env bash
# Complete local Docker gate for one exact OSS candidate commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE_SHA="${CANDIDATE_SOURCE_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
refuse() { printf 'candidate gate refused: %s\n' "$*" >&2; exit 2; }

# Probe the backing host filesystem without pulling an image or starting a
# container. Desktop's Linux DockerRootDir lives inside its sparse disk image.
# Keep the critical floor free after this gate's measured peak allocation.
wait_for_disk() {
  local mode="${1:-wait}"
  local floor="${AWEB_GATE_MIN_FREE_GB:-50}" reserve="${AWEB_GATE_RESERVE_GB:-30}" path available
  [[ "$floor" =~ ^[0-9]+$ ]] || refuse "AWEB_GATE_MIN_FREE_GB must be a nonnegative integer"
  [[ "$reserve" =~ ^[0-9]+$ ]] || refuse "AWEB_GATE_RESERVE_GB must be a nonnegative integer"
  path="$(docker info --format '{{.DockerRootDir}}')" || refuse "docker daemon is unavailable"
  if [[ "$(uname -s)" == Darwin ]]; then
    path="$(python3 - <<'PY'
import json
from pathlib import Path

settings = Path.home() / 'Library/Group Containers/group.com.docker/settings-store.json'
config = json.loads(settings.read_text()) if settings.exists() else {}
directory = Path(config.get('dataFolder') or Path.home() / 'Library/Containers/com.docker.docker/Data/vms/0/data').expanduser()
disk = directory / 'Docker.raw'
if not disk.is_file():
    raise SystemExit('Docker Desktop backing disk is unavailable: ' + str(disk))
print(disk.resolve())
PY
)" || refuse "could not locate Docker Desktop's data volume"
  fi
  while :; do
    available="$(df -Pk "$path" | awk 'NR == 2 {print $4}')" \
      || refuse "could not measure Docker's data volume"
    [[ "$available" =~ ^[0-9]+$ ]] || refuse "could not measure Docker's data volume"
    if awk -v free="$available" -v floor="$floor" -v reserve="$reserve" 'BEGIN {exit !(free >= (floor + reserve) * 1024 * 1024)}'; then
      return
    fi
    if [[ "$mode" == check ]]; then
      refuse "$(awk -v free="$available" -v floor="$floor" -v reserve="$reserve" -v path="$path" \
        'BEGIN {printf "Docker data volume %s has %.1f GiB free; need %.0f GiB (%s critical + %s gate reserve). Free space before retrying.", path, free / 1024 / 1024, floor + reserve, floor, reserve}')"
    fi
    awk -v free="$available" -v floor="$floor" -v reserve="$reserve" -v path="$path" \
      'BEGIN {printf "candidate gate waiting: Docker data volume %s has %.1f GiB free; need %.0f GiB (%s critical + %s gate reserve); retrying in 60s\n", path, free / 1024 / 1024, floor + reserve, floor, reserve}'
    sleep 60
  done
}

# Release prerequisites refuse immediately rather than timing out inside a
# nested self-test. Direct gates retain their operator-visible waiting mode.
if [[ "${1:-}" == --check-disk && "$#" == 1 ]]; then
  wait_for_disk check
  exit 0
fi
# The direct waiting probe uses the same floor and measurement.
if [[ "${1:-}" == --wait-for-disk && "$#" == 1 ]]; then
  wait_for_disk
  exit 0
fi
# Library builds from the candidate checkout, with its awid and naapp-lib.
[[ -z "${LIBRARY_E2E_LIBRARY_CONTEXT:-}" ]] \
  || refuse "LIBRARY_E2E_LIBRARY_CONTEXT is not an input: Library builds from the candidate checkout"
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
LIBRARY_E2E_BLUEPRINT_SRC="$(canonical_git_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC")"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
log_root="${AWEB_GATE_RUN_LOG_ROOT:-/tmp}"
[[ "$log_root" == /* && -d "$log_root" ]] || refuse "AWEB_GATE_RUN_LOG_ROOT must be an existing absolute directory"
LOG_DIR="${log_root%/}/aweb-candidate-gate-$SOURCE_SHA-$run_id"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || refuse "CANDIDATE_SOURCE_SHA must be a full lowercase SHA"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] \
  || refuse "source checkout is dirty or has untracked files"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$SOURCE_SHA" ]] \
  || refuse "source checkout HEAD differs from selected SHA"
# Focused pre-landing proof uses the same stages and ledger. Release candidates
# always request the complete list and retain the origin/main requirement.
CANDIDATE_STAGES="static checks user-paths unit artifacts integration"
STAGES="${AWEB_CANDIDATE_STAGES:-}"
REQUESTED="${STAGES:-$CANDIDATE_STAGES}"
if [[ -z "$STAGES" ]]; then
  git -C "$ROOT" fetch --quiet origin main
  git -C "$ROOT" merge-base --is-ancestor "$SOURCE_SHA" origin/main \
    || refuse "source SHA is not on the synchronized origin/main history"
fi
# The synchronized main the candidate is checked against. Focused callers
# supply this ref during preparation.
SYNCHRONIZED_MAIN_SHA="$(git -C "$ROOT" rev-parse --verify 'refs/remotes/origin/main^{commit}')" \
  || refuse "synchronized origin/main is missing. Synchronize main and start a new gate invocation."
[[ -d "$LIBRARY_E2E_BLUEPRINT_SRC" ]] || refuse "blueprint input is missing"
CLI_VERSION="${CLI_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" aw-v)}"
A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-$(python3 "$ROOT/scripts/next_tag_version.py" a2a-gw-v)}"

# Port of Cloud's entry-point ledger: all callers share one tree lock and
# stage history. Version defaults depend on tags, so their effective values
# are external inputs even when the caller did not supply an override.
TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
LEDGER="${AWEB_GATE_LEDGER:-$HOME/.cache/aweb-oss/candidate-gate-ledger.tsv}"
external_inputs="CLI_VERSION=$CLI_VERSION"$'\n'"A2A_GATEWAY_VERSION=$A2A_GATEWAY_VERSION"$'\n'
# The same tree must be requalified when the released client changes. Resolve
# latest exactly once here, for every stage selection. Focused and full callers
# must share a key so the full gate can reuse their completed stages.
resolve_started=$SECONDS
USER_PATHS_LATEST_METADATA="$(python3 "$ROOT/scripts/fetch_released_aw.py" --freeze-latest "$(dirname "$LEDGER")/released-aw-inputs")"
USER_PATHS_RESOLVE_SECONDS=$((SECONDS - resolve_started))
released_identity="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$USER_PATHS_LATEST_METADATA")"
USER_PATHS_LATEST_SHA256="$released_identity"
# Main's commit is not itself a gate input: the product-table check reads only
# main's reviewed ceilings, so an unchanged tree reuses its pass until they change.
REVIEWED_PRODUCT_TABLE_CEILINGS="$(python3 "$ROOT/scripts/product_table_writes.py" --root "$ROOT" --reviewed-identity)" \
  || refuse "cannot read synchronized main's product-table ceilings. Synchronize main and start a new gate invocation."
external_inputs+="REVIEWED_PRODUCT_TABLE_CEILINGS=$REVIEWED_PRODUCT_TABLE_CEILINGS"$'\n'
external_inputs+="RELEASED_AW=$released_identity"$'\n'
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
input_identity blueprints "$LIBRARY_E2E_BLUEPRINT_SRC" naapp/library/test-vectors/blueprints/team
gate_setting() {
  local name="$1" default="$2" value
  value="${!name:-$default}"
  printf -v "$name" '%s' "$value"
  [[ "$value" == "$default" ]] || external_inputs+="$name=$value"$'\n'
}
# The budget (GATE_CPUS, GATE_MEMORY_MIB, else the Docker engine's own size)
# sizes the run. It is not a gate input: a pass at one size is the same pass at
# another, so it stays out of the key and goes into the run's evidence.
budget_assignments="$(python3 "$ROOT/scripts/gate_budget.py")" \
  || refuse "the gate budget is invalid or unreadable"
while IFS='=' read -r name value; do
  case "$name" in
    GATE_CPUS|GATE_MEMORY_MIB|GATE_BUDGET_SOURCE|GATE_RUNNER_CPUS|GATE_BUILDER_CPUS|GATE_SIBLING_CPUS|CANDIDATE_SERVER_WORKERS)
      printf -v "$name" '%s' "$value" ;;
    *) refuse "unexpected gate budget output: $name" ;;
  esac
done <<<"$budget_assignments"
gate_setting AWEB_CANDIDATE_RUNNER_CPUS "$GATE_RUNNER_CPUS"
gate_setting AWEB_CANDIDATE_RUNNER_MEMORY 8g
gate_setting AWEB_CANDIDATE_RUNNER_PIDS 2048
gate_setting AWEB_CANDIDATE_BUILDER_CPUS "$GATE_BUILDER_CPUS"
gate_setting AWEB_CANDIDATE_BUILDER_MEMORY 6g
gate_setting AWEB_CANDIDATE_BUILDER_MEMORY_SWAP "$AWEB_CANDIDATE_BUILDER_MEMORY"
gate_setting AWEB_CANDIDATE_BUILDER_PIDS 2048
gate_setting AWEB_CANDIDATE_SERVICE_CPUS "$GATE_CPUS"
gate_setting AWEB_CANDIDATE_SERVICE_MEMORY 1g
gate_setting AWEB_CANDIDATE_SERVICE_PIDS 512
gate_setting AWEB_CANDIDATE_REDIS_CPUS "$GATE_CPUS"
gate_setting AWEB_CANDIDATE_REDIS_MEMORY 256m
gate_setting AWEB_CANDIDATE_REDIS_PIDS 256
gate_setting AWEB_CANDIDATE_SIBLING_CPUS "$GATE_SIBLING_CPUS"
gate_setting AWEB_CANDIDATE_SIBLING_MEMORY 4g
gate_setting AWEB_CANDIDATE_SIBLING_PIDS 1024
KEY="$TREE-$(printf '%s' "$external_inputs" | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
LEDGER_LOGS="${AWEB_GATE_LOG_DIR:-$(dirname "$LEDGER")/gate-logs}"
# The runner uses the host UID without requiring a container passwd entry.
# Owner is a ledger label, so its numeric UID is sufficient in that case.
OWNER="${GATE_OWNER:-${OATS_INSTANCE:-}}"
if [[ -z "$OWNER" ]]; then
  # GNU id may print a numeric UID before failing its name lookup. Assign each
  # attempt separately so that failed stdout cannot enter the ledger field.
  OWNER="$(id -un 2>/dev/null)" || OWNER="$(id -u)"
fi
mkdir -p "$(dirname "$LEDGER")/gate-locks" "$LEDGER_LOGS"
touch "$LEDGER"
# Hold through cleanup and recording, including concurrent direct/RC calls.
exec 9>>"$(dirname "$LEDGER")/gate-locks/$TREE.lock"
python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null \
  || refuse "tree $TREE is already being gated"
recorded() {
  awk -F'\t' -v key="$KEY" -v stage="$1" '$1 == key && $2 == stage' "$LEDGER" | tail -1
}
failed="$(awk -F'\t' -v key="$KEY" -v tree="$TREE" '
  $1 == key && $3 == "failed" && index($2, "/") == 0 {
    printf "gate: tree %s already FAILED %s (log %s).\n", tree, $2, $6
  }
' "$LEDGER")"
if [[ -n "$failed" ]]; then
  printf '%s\n' "$failed" >&2
  printf '%s\n' "Fix the code and gate the changed tree. For infrastructure failures only, the coordinator removes the failed ledger line and uses GATE_RERUN_REASON='<reason>'." >&2
  exit 1
fi
pending=""
for stage in $REQUESTED; do
  [[ " $CANDIDATE_STAGES " == *" $stage "* ]] || refuse "unknown stage '$stage'"
  if [[ "$(recorded "$stage" | cut -f3)" == passed ]]; then
    printf 'gate: tree %s already passed %s; original log %s\n' "$TREE" "$stage" "$(recorded "$stage" | cut -f6)"
    if [[ "$stage" == user-paths ]]; then
      # Reusing the proof must not hide its coverage gap in an otherwise green gate.
      grep -E 'NOT COVERED: pending aweb-actu$|^incomplete: human paths not covered$' "$(recorded "$stage" | cut -f6)" || true
    fi
  elif [[ " $pending " != *" $stage "* ]]; then
    pending="${pending:+$pending }$stage"
  fi
done
if [[ -z "$pending" ]]; then
  printf 'gate: tree %s passed %s; no stages run\n' "$TREE" "$REQUESTED"
  exit 0
fi

run_candidate() {
set -euo pipefail
command -v docker >/dev/null || refuse "docker is unavailable"

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
# gate_setting assigned every limit above, from the budget or an override.
runner_cpus="$AWEB_CANDIDATE_RUNNER_CPUS"
runner_memory="$AWEB_CANDIDATE_RUNNER_MEMORY"
runner_pids="$AWEB_CANDIDATE_RUNNER_PIDS"
builder_cpus="$AWEB_CANDIDATE_BUILDER_CPUS"
builder_memory="$AWEB_CANDIDATE_BUILDER_MEMORY"
builder_memory_swap="$AWEB_CANDIDATE_BUILDER_MEMORY_SWAP"
builder_pids="$AWEB_CANDIDATE_BUILDER_PIDS"
service_cpus="$AWEB_CANDIDATE_SERVICE_CPUS"
service_memory="$AWEB_CANDIDATE_SERVICE_MEMORY"
service_pids="$AWEB_CANDIDATE_SERVICE_PIDS"
redis_cpus="$AWEB_CANDIDATE_REDIS_CPUS"
redis_memory="$AWEB_CANDIDATE_REDIS_MEMORY"
redis_pids="$AWEB_CANDIDATE_REDIS_PIDS"
sibling_cpus="$AWEB_CANDIDATE_SIBLING_CPUS"
sibling_memory="$AWEB_CANDIDATE_SIBLING_MEMORY"
sibling_pids="$AWEB_CANDIDATE_SIBLING_PIDS"
suite_projects=(
  "$gate_run_id-channel"
  "$gate_run_id-user"
  "$gate_run_id-fed-auth"
  "aweb-fed-e2e-${SOURCE_SHA:0:12}${run_suffix}"
  "$gate_run_id-library"
)
# Install cleanup before the first Docker allocation. Logs outlive the run.
: > "$LOG_DIR/owned-resources.tsv"
printf '%s\n' "$run_id" > "$LOG_DIR/run-id"
printf '%s\n' "$SYNCHRONIZED_MAIN_SHA" > "$LOG_DIR/synchronized-main-sha"
printf 'cpus\t%s\nmemory_mib\t%s\nsource\t%s\nserver_workers\t%s\n' \
  "$GATE_CPUS" "$GATE_MEMORY_MIB" "$GATE_BUDGET_SOURCE" "$CANDIDATE_SERVER_WORKERS" > "$LOG_DIR/budget.tsv"
source "$ROOT/scripts/candidate-cleanup.sh"
trap 'cleanup "$?"' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
# The content-addressed input lives outside the resettable run logs. Retain a
# checked copy in the mounted logs so the runner consumes the ledger's bytes.
if [[ -n "${USER_PATHS_LATEST_METADATA:-}" ]]; then
  cp "$USER_PATHS_LATEST_METADATA" "$LOG_DIR/released-aw.json"
  USER_PATHS_LATEST_METADATA="$LOG_DIR/released-aw.json"
  [[ "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$USER_PATHS_LATEST_METADATA")" == "$USER_PATHS_LATEST_SHA256" ]] \
    || refuse "released aw metadata changed after the ledger lookup"
fi
checkout="$work/aweb"
[[ "$(git -C "$ROOT" rev-parse --verify 'refs/remotes/origin/main^{commit}')" == "$SYNCHRONIZED_MAIN_SHA" ]] \
  || refuse "synchronized origin/main changed or disappeared. Synchronize main and start a new gate invocation."
# Tracked source is also mounted into services running as other UIDs (notably
# Library's PostgreSQL initdb). Materialize its Git modes independently of the
# operator's private umask; keep the work parent and later runtime files private.
(
  umask 0022
  git clone --local --no-hardlinks "$ROOT" "$checkout" >/dev/null
  git -C "$checkout" checkout --detach "$SOURCE_SHA" >/dev/null
)
# Local clone does not copy the source's remote-tracking refs. Bind the checked
# baseline explicitly; all its objects were copied locally, with no fetch here.
git -C "$checkout" update-ref refs/remotes/origin/main "$SYNCHRONIZED_MAIN_SHA" \
  || refuse "could not install synchronized main. Synchronize main and start a new gate invocation."
[[ "$(git -C "$checkout" rev-parse --verify 'refs/remotes/origin/main^{commit}')" == "$SYNCHRONIZED_MAIN_SHA" ]] \
  || refuse "cloned main does not match the admitted baseline. Synchronize main and start a new gate invocation."
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
  chmod 0755 "$work/inputs" "$work/inputs/$name"
  (
    umask 0022
    # Drain Git padding on BSD/GNU tar; pipefail still reports archive errors.
    git -C "$repo" archive "$tree" | tar --ignore-zeros -xf - -C "$work/inputs/$name"
  )
}
record_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC"
LIBRARY_E2E_BLUEPRINT_SRC="$work/inputs/blueprints"
printf '%s\n' "$SOURCE_SHA" > "$LOG_DIR/source-sha"
printf 'NOT RELEVANT: OSS packages do not bundle Library; it is built only for its activation journey.\n' \
  > "$LOG_DIR/compatibility.txt"

python3 "$ROOT/scripts/candidate-host-pressure.py" capture "$LOG_DIR/host-before.json"
# The published socket belongs to the Docker host, not the bridge runner.
host_port_status=0
if [[ " $pending " == *" checks "* ]]; then
  AWEB_CANDIDATE_RESOURCE_LABEL="$resource_label" python3 \
    "$checkout/scripts/e2e/test_candidate_gate_docker_boundaries.py" \
    --image unused HostPublishedPortTests -v > "$LOG_DIR/host-published-port.log" 2>&1 \
    || host_port_status=$?
fi
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
  --build-arg USER_PATHS_SOURCE_TREE="$TREE" \
  --build-arg USER_PATHS_SOURCE_SHA="$SOURCE_SHA" \
  --build-arg USER_PATHS_CLI_VERSION="$CLI_VERSION" \
  --label "aweb.candidate-gate=$resource_label" \
  -f "$checkout/candidate-gate/Dockerfile" -t "$IMAGE" "$checkout" \
  2>&1 | tee "$LOG_DIR/docker-build.log"

# Record the run's mutable inputs in the evidence (adoption compares them):
# the resolved base-image digest and the tracked lock-set hash. Package
# manager fetches inside the build are not recorded and adoption names that.
base_ref="$(awk '/^FROM /{print $2; exit}' "$checkout/candidate-gate/Dockerfile")"
base_digest="$(docker image inspect "$base_ref" --format '{{join .RepoDigests ","}}' 2>/dev/null || echo unresolved)"
locks_digest="$(git -C "$checkout" ls-files -s -- '*uv.lock' | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())')"
printf 'base\t%s\t%s\nlocks\t%s\n' "$base_ref" "$base_digest" "$locks_digest" > "$LOG_DIR/inputs.tsv"
printf 'synchronized-main\t%s\n' "$SYNCHRONIZED_MAIN_SHA" >> "$LOG_DIR/inputs.tsv"
printf 'runner\tcpus=%s\tmemory=%s\tpids=%s\nbuilder\tcpus=%s\tmemory=%s\tmemory_swap=%s\tpids=%s\nservice\tcpus=%s\tmemory=%s\tpids=%s\nredis\tcpus=%s\tmemory=%s\tpids=%s\nsibling\tcpus=%s\tmemory=%s\tpids=%s\n' \
  "$runner_cpus" "$runner_memory" "$runner_pids" \
  "$builder_cpus" "$builder_memory" "$builder_memory_swap" "$builder_pids" \
  "$service_cpus" "$service_memory" "$service_pids" \
  "$redis_cpus" "$redis_memory" "$redis_pids" \
  "$sibling_cpus" "$sibling_memory" "$sibling_pids" > "$LOG_DIR/resource-limits.tsv"
owned_network="$gate_run_id-network"
docker network create --label "aweb.candidate-gate=$resource_label" "$owned_network" >/dev/null

# Each stage runs in its own lane: its own runner, workspace volume, Postgres
# and Redis. Lanes share only the Docker daemon, this run's label and bind
# root (mktemp paths), and the builder; artifacts alone prunes its cache, so it
# has its own builder. Static runs first and alone. A stage writes its summary
# rows to its own file; this wrapper, the one writer of summary.tsv and of the
# recorder's stream, merges them when the stage ends.
start_lane_services() {
  local lane="$1" pg redis container db ext_schema applied
  pg="$owned_network-$lane-postgres"
  redis="$owned_network-$lane-redis"
  docker volume create --label "aweb.candidate-gate=$resource_label" "$pg-data" >/dev/null
  docker volume create --label "aweb.candidate-gate=$resource_label" "$redis-data" >/dev/null
  pg_id="$(docker run --detach --network "$owned_network" --name "$pg" \
    --label "aweb.candidate-gate=$resource_label" \
    --cpus "$service_cpus" --memory "$service_memory" --pids-limit "$service_pids" \
    -v "$pg-data:/var/lib/postgresql/data" \
    --env POSTGRES_USER=postgres --env POSTGRES_PASSWORD=postgres --env POSTGRES_DB=postgres \
    --health-cmd 'pg_isready -U postgres -d postgres' \
    --health-interval 2s --health-timeout 5s --health-retries 45 postgres:17)"
  redis_id="$(docker run --detach --network "$owned_network" --name "$redis" \
    --label "aweb.candidate-gate=$resource_label" \
    --cpus "$redis_cpus" --memory "$redis_memory" --pids-limit "$redis_pids" \
    -v "$redis-data:/data" \
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
}

# Copy the exact checkout and inputs through the Docker API. The host checkout
# is never mounted into a container; extracted dependency trees stay in Docker.
seed_lane_workspace() {
  local lane="$1" seed="$seed_name-$1"
  docker volume create --label "aweb.candidate-gate=$resource_label" "$workspace_volume-$lane" >/dev/null
  docker create --name "$seed" --label "aweb.candidate-gate=$resource_label" \
    --cpus "$runner_cpus" --memory "$runner_memory" --pids-limit "$runner_pids" \
    -v "$workspace_volume-$lane:$work" "$IMAGE" chown -R "$(id -u):$(id -g)" "$work" >/dev/null
  docker cp "$work/." "$seed:$work"
  docker start --attach "$seed"
  [[ "$(docker inspect --format '{{.State.ExitCode}}' "$seed")" == 0 ]] \
    || refuse "could not initialize Docker-owned workspace permissions"
  docker rm -v "$seed" >/dev/null
}

mkdir -p "$docker_bind_root" "$checkout/.candidate-home" "$LOG_DIR/lanes"
socket_gid="$(docker run --rm \
  --label "aweb.candidate-gate=$resource_label" \
  --cpus "$redis_cpus" --memory "$redis_memory" --pids-limit "$redis_pids" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE" stat -c '%g' /var/run/docker.sock)"
naapp_packages_text="$(make -s --no-print-directory -C "$ROOT" naapp-e2e-packages)"
read -r -a naapp_packages <<<"$(printf '%s\n' "$naapp_packages_text" | tr '\n' ' ')"
naapp_e2e_allocations=""
for package in "${naapp_packages[@]}"; do
  # These are container ports; no host socket is allocated or published.
  naapp_e2e_allocations+="$package $gate_run_id-naapp-${package##*/} 8010 5432"$'\n'
done
artifacts_builder="$builder_name-artifacts"
if [[ " $pending " == *" artifacts "* ]]; then
  printf 'builder\t%s\n' "$artifacts_builder" >> "$LOG_DIR/owned-resources.tsv"
  BUILDX_CONFIG="$buildx_config" docker buildx create \
    --name "$artifacts_builder" --driver docker-container \
    "unix:///var/run/docker.sock" --bootstrap >/dev/null \
    || refuse "could not provision the artifacts stage's builder"
  docker update --cpus "$builder_cpus" --memory "$builder_memory" --memory-swap "$builder_memory_swap" --pids-limit "$builder_pids" \
    "buildx_buildkit_${artifacts_builder}0" >/dev/null \
    || refuse "could not apply candidate builder resource limits"
fi
for lane in $pending; do
  start_lane_services "$lane"
  seed_lane_workspace "$lane"
done

# Runs one stage in its lane. The exit file is how the wrapper learns it ended,
# so it is written whatever the runner's exit.
run_lane() {
  local lane="$1" name="$runner_name-$1" builder="$builder_name" lane_status=0
  local pg="$owned_network-$1-postgres" redis="$owned_network-$1-redis"
  [[ "$lane" != artifacts ]] || builder="$artifacts_builder"
  printf 'runner\t%s\n' "$name" >> "$LOG_DIR/owned-resources.tsv"
  docker run --rm --init \
    --name "$name" \
    --label "aweb.candidate-gate=$resource_label" \
    --cpus "$runner_cpus" \
    --memory "$runner_memory" \
    --pids-limit "$runner_pids" \
    --network "$owned_network" \
    --user "$(id -u):$(id -g)" \
    --group-add "$socket_gid" \
    -e HOME="$checkout/.candidate-home" \
    -e PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    -e PATH="$checkout/candidate-gate/bin:/usr/local/go/bin:/opt/uv:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -e AWEB_CANDIDATE_REAL_DOCKER=/usr/bin/docker \
    -e AWEB_CANDIDATE_RESOURCE_LABEL="$resource_label" \
    -e GATE_CPUS="$GATE_CPUS" \
    -e GATE_MEMORY_MIB="$GATE_MEMORY_MIB" \
    -e AWEB_CANDIDATE_SIBLING_CPUS="$sibling_cpus" \
    -e AWEB_CANDIDATE_SIBLING_MEMORY="$sibling_memory" \
    -e AWEB_CANDIDATE_SIBLING_PIDS="$sibling_pids" \
    -e DOCKER_BUILDKIT=1 \
    -e COMPOSE_DOCKER_CLI_BUILD=1 \
    -e COMPOSE_BAKE=true \
    -e CANDIDATE_SOURCE_SHA="$SOURCE_SHA" \
    -e CANDIDATE_RUNNER_NAME="$name" \
    -e CANDIDATE_CHECKOUT_ROOT="$checkout" \
    -e CANDIDATE_SUMMARY="$LOG_DIR/lanes/$lane.tsv" \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0="$checkout" \
    -e CLI_VERSION="${CLI_VERSION:-}" \
    -e A2A_GATEWAY_VERSION="${A2A_GATEWAY_VERSION:-}" \
    -e LIBRARY_E2E_BLUEPRINT_SRC="$LIBRARY_E2E_BLUEPRINT_SRC" \
    -e CANDIDATE_LOG_DIR="$LOG_DIR" \
    -e CANDIDATE_HOST_PORT_STATUS="$host_port_status" \
    -e USER_PATHS_LATEST_METADATA="${USER_PATHS_LATEST_METADATA:-}" \
    -e USER_PATHS_LATEST_SHA256="${USER_PATHS_LATEST_SHA256:-}" \
    -e USER_PATHS_RESOLVE_SECONDS="${USER_PATHS_RESOLVE_SECONDS:-0}" \
    -e CANDIDATE_RESOURCE_MANIFEST="$LOG_DIR/owned-resources.tsv" \
    -e BUILDX_CONFIG="$buildx_config" \
    -e BUILDX_BUILDER="$builder" \
    -e UV_LINK_MODE=copy \
    -e GOCACHE=/tmp/go-build \
    -e GOMODCACHE="$go_mod_cache" \
    -e GOFLAGS=-modcacherw \
    -e NPM_CONFIG_CACHE=/tmp/npm-cache \
    -e AWEB_DOCKER_BIND_ROOT="$docker_bind_root" \
    -e AWEB_SKEW_PROJECT_TOKEN="${suite_projects[0]}" \
    -e AWEB_E2E_PROJECT="${suite_projects[1]}" \
    -e AWEB_FED_AUTH_PROJECT="${suite_projects[2]}" \
    -e AWEB_FED_E2E_PROJECT="${suite_projects[3]}" \
    -e LIBRARY_E2E_PROJECT="${suite_projects[4]}" \
    -e NAAPP_E2E_CONTAINER_NETWORK=1 \
    -e NAAPP_E2E_ALLOCATIONS="$naapp_e2e_allocations" \
    -e TEST_DB_HOST="$pg" \
    -e TEST_DB_PORT=5432 \
    -e TEST_DB_USER=postgres \
    -e TEST_DB_PASSWORD=postgres \
    -e PGHOST="$pg" \
    -e PGPORT=5432 \
    -e PGUSER=postgres \
    -e PGPASSWORD=postgres \
    -e PGDATABASE=postgres \
    -e REDIS_URL="redis://$redis:6379/0" \
    -e CANDIDATE_GATE_IMAGE="$IMAGE" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$workspace_volume-$lane:$work" \
    -v "$docker_bind_root:$docker_bind_root" \
    -v "$LOG_DIR:$LOG_DIR" \
    -w "$checkout" \
    "$IMAGE" \
    bash scripts/candidate-suite.sh "$lane" > "$LOG_DIR/lanes/$lane.out" 2>&1 || lane_status=$?
  printf '%s\n' "$lane_status" > "$LOG_DIR/lanes/$lane.exit"
}

# Merges an ended lane's rows and reports its targets and stage verdict on the
# recorder's stream. A lane stopped before its stage row reports STOPPED: it
# did not fail, and it records no stage row.
finish_lane() {
  local lane="$1" stopped_by="$2" status
  status="$(cat "$LOG_DIR/lanes/$lane.exit")"
  [[ ! -f "$LOG_DIR/lanes/$lane.tsv" ]] || cat "$LOG_DIR/lanes/$lane.tsv" >> "$LOG_DIR/summary.tsv"
  grep -E '^(candidate: |user-paths coverage: )' "$LOG_DIR/lanes/$lane.out" || true
  printf 'gate lane %s: exit %s in %ss\n' "$lane" "$status" "$(( SECONDS - lane_started ))"
  if grep -q "^$lane"$'\t' "$LOG_DIR/lanes/$lane.tsv" 2>/dev/null; then
    grep "^candidate stage-verdict: $lane " "$LOG_DIR/lanes/$lane.out" || true
    return
  fi
  if [[ -n "$stopped_by" ]]; then
    printf 'candidate: %s STOPPED (after %s FAILED)\n' "$lane" "$stopped_by"
    printf '%s\tSTOPPED\t-\t%ss\tafter %s FAILED\n' "$lane" "$(( SECONDS - lane_started ))" "$stopped_by" >> "$LOG_DIR/summary.tsv"
    printf 'candidate stage-verdict: %s STOPPED\n' "$lane"
  else
    printf '%s\tFAILED\t%s.log\t%ss\tlane exit %s\n' "$lane" "$lane" "$(( SECONDS - lane_started ))" "$status" >> "$LOG_DIR/summary.tsv"
    printf 'candidate stage-verdict: %s FAILED\n' "$lane"
  fi
}

lane_passed() {
  grep -q "^$1"$'\tPASSED\t' "$LOG_DIR/lanes/$1.tsv" 2>/dev/null && [[ "$(cat "$LOG_DIR/lanes/$1.exit")" == 0 ]]
}

: > "$LOG_DIR/summary.tsv"
status=0
lanes="$pending"
lane_started=$SECONDS
if [[ " $pending " == *" static "* ]]; then
  run_lane static
  finish_lane static ""
  lanes="${pending/static/}"
  if ! lane_passed static; then
    status=1
    for lane in $lanes; do
      printf 'candidate: %s NOT-RUN (static FAILED)\n' "$lane"
      printf '%s\tNOT-RUN\t-\t0s\tstatic FAILED\n' "$lane" >> "$LOG_DIR/summary.tsv"
    done
    lanes=""
  fi
fi
lane_started=$SECONDS
declare -A lane_ended=() lane_pid=()
for lane in $lanes; do
  run_lane "$lane" &
  lane_pid[$lane]=$!
done
first_red=""
remaining="$(wc -w <<<"$lanes")"
while (( remaining > 0 )); do
  sleep 2
  for lane in $lanes; do
    [[ -z "${lane_ended[$lane]:-}" ]] || continue
    # A lane process that died without its exit file is an infrastructure end.
    if [[ ! -f "$LOG_DIR/lanes/$lane.exit" ]] && ! kill -0 "${lane_pid[$lane]}" 2>/dev/null; then
      [[ -f "$LOG_DIR/lanes/$lane.exit" ]] || printf '70\n' > "$LOG_DIR/lanes/$lane.exit"
    fi
    [[ -f "$LOG_DIR/lanes/$lane.exit" ]] || continue
    lane_ended[$lane]=1
    remaining=$(( remaining - 1 ))
    if [[ -z "$first_red" ]]; then
      finish_lane "$lane" ""
      if ! lane_passed "$lane"; then
        # The first red stops every other lane: the run fails fast.
        first_red="$lane"
        status=1
        for other in $lanes; do
          [[ -n "${lane_ended[$other]:-}" ]] || docker kill --signal TERM "$runner_name-$other" >/dev/null 2>&1 || true
        done
        stop_deadline=$(( SECONDS + 120 ))
      fi
    else
      finish_lane "$lane" "$first_red"
    fi
  done
  if [[ -n "$first_red" ]] && (( remaining > 0 && SECONDS > stop_deadline )); then
    for other in $lanes; do
      [[ -n "${lane_ended[$other]:-}" ]] || docker kill --signal KILL "$runner_name-$other" >/dev/null 2>&1 || true
    done
  fi
done

if [[ "$status" -ne 0 ]]; then
  printf 'candidate gate FAILED; logs: %s\n' "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log" >&2
  exit "$status"
fi
printf 'candidate gate PASSED at %s; logs: %s\n' \
  "$SOURCE_SHA" "$LOG_DIR" | tee -a "$LOG_DIR/wrapper-verdict.log"

}

# The child owns Docker cleanup. Its output reader survives group signals and
# records each stage as it passes; the lock holder waits for cleanup before
# recording the rest of the run's verdict.
source "$ROOT/scripts/candidate-record.sh"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_log="$LEDGER_LOGS/${KEY:0:12}-run-$run_id.log"
wait_for_disk
mkdir -- "$LOG_DIR" || refuse "could not allocate run logs: $LOG_DIR"
output_pipe="$LOG_DIR/output.pipe"
mkfifo "$output_pipe"
if [[ -n "${AWEB_GATE_RUN_REGISTRY:-}" ]]; then
  printf '%s\t%s\n' "$run_id" "$LOG_DIR" >> "$AWEB_GATE_RUN_REGISTRY"
fi
trap 'candidate_interrupted 130 INT' INT
trap 'candidate_interrupted 143 TERM' TERM
(trap '' INT TERM; record_stages_as_they_pass) < "$output_pipe" &
candidate_writer=$!
run_candidate > "$output_pipe" 2>&1 &
candidate_job=$!
set +e
wait "$candidate_job"
status=$?
candidate_child_status=$status
trap '' INT TERM
finish_candidate_output
if [[ "$status" == 0 && "$candidate_writer_status" != 0 ]]; then status=1; fi
finalize_candidate "$status"
status=$?
exit "$status"
