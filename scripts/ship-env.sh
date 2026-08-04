#!/usr/bin/env bash
# Owns the ship gate's ambient dependencies: PostgreSQL, Redis, the pinned Go
# toolchain, the reviewed aw binary, and the Library-stack inputs.
#
# Services that already answer are reused untouched, which is how the hosted
# workflow's job-provisioned containers keep working. Anything unreachable is
# provisioned as a disposable container, and exactly those containers are
# removed on exit - success or failure. pgdbm's test factory reads
# TEST_DB_HOST/PORT/USER/PASSWORD (not libpq PG*), so provisioning exports
# both families.
#
# Usage: ship-env.sh <command...>   run <command...> inside the owned environment
#        ship-env.sh --self-test    prove the reuse/provision/cleanup/toolchain arms

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_IMAGE=postgres:17
REDIS_IMAGE=redis:7
PG_CONTAINER=aweb-ship-postgres
REDIS_CONTAINER=aweb-ship-redis
# 55432 belongs to the Library e2e stack (LIBRARY_E2E_POSTGRES_PORT default),
# which the cli-e2e suite starts while this service is still running.
PG_LOCAL_PORT=55542
REDIS_LOCAL_PORT=56379

fatal() {
  printf 'FATAL: %s\n' "$1" >&2
  exit 1
}

reachable() {
  (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null || return 1
  exec 3>&- 3<&-
}

OWNED_CONTAINERS=()
cleanup_owned() {
  local container
  for container in ${OWNED_CONTAINERS[@]+"${OWNED_CONTAINERS[@]}"}; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
}

provision() {
  local name="$1" image="$2" host_port="$3" container_port="$4"
  shift 4
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run --detach --name "$name" \
    --publish "$host_port:$container_port" "$@" "$image" >/dev/null
  OWNED_CONTAINERS+=("$name")
}

wait_healthy() {
  local container="$1" probe="$2"
  local attempt
  for attempt in $(seq 1 90); do
    if docker exec "$container" $probe >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container" >&2 || true
  return 1
}

redis_probe_target() {
  local url="${REDIS_URL:-redis://localhost:6379/0}"
  local hostport="${url#*://}"
  hostport="${hostport%%/*}"
  printf '%s %s\n' "${hostport%%:*}" "${hostport##*:}"
}

# Reuse is for endpoints somebody provisioned FOR this gate: the hosted
# workflow's job services (CI is always set there) or an explicit opt-in. A
# plain local run always provisions its own disposable services - a reachable
# localhost:5432 on a developer machine is somebody's personal database, and
# the gate creates and drops test databases.
reuse_allowed() {
  [[ -n "${CI:-}${AWEB_SHIP_REUSE_SERVICES:-}" ]]
}

ensure_services() {
  local pg_host="${TEST_DB_HOST:-localhost}" pg_port="${TEST_DB_PORT:-5432}"
  if reuse_allowed && reachable "$pg_host" "$pg_port"; then
    echo "ship-env: reusing PostgreSQL at $pg_host:$pg_port"
  else
    provision "$PG_CONTAINER" "$PG_IMAGE" "$PG_LOCAL_PORT" 5432 \
      --env POSTGRES_USER=postgres \
      --env POSTGRES_PASSWORD=postgres \
      --env POSTGRES_DB=postgres
    wait_healthy "$PG_CONTAINER" "pg_isready -U postgres -d postgres" \
      || fatal "provisioned PostgreSQL never became ready"
    export TEST_DB_HOST=localhost TEST_DB_PORT="$PG_LOCAL_PORT"
    export TEST_DB_USER=postgres TEST_DB_PASSWORD=postgres
    export PGHOST=localhost PGPORT="$PG_LOCAL_PORT" PGUSER=postgres
    export PGPASSWORD=postgres PGDATABASE=postgres
    echo "ship-env: provisioned $PG_IMAGE as $PG_CONTAINER on port $PG_LOCAL_PORT"
  fi

  local redis_target redis_host redis_port
  redis_target="$(redis_probe_target)"
  redis_host="${redis_target%% *}"
  redis_port="${redis_target##* }"
  if reuse_allowed && reachable "$redis_host" "$redis_port"; then
    echo "ship-env: reusing Redis at $redis_host:$redis_port"
  else
    provision "$REDIS_CONTAINER" "$REDIS_IMAGE" "$REDIS_LOCAL_PORT" 6379
    wait_healthy "$REDIS_CONTAINER" "redis-cli ping" \
      || fatal "provisioned Redis never became ready"
    export REDIS_URL="redis://localhost:$REDIS_LOCAL_PORT/0"
    echo "ship-env: provisioned $REDIS_IMAGE as $REDIS_CONTAINER on port $REDIS_LOCAL_PORT"
  fi
}

ensure_toolchain() {
  export GOTOOLCHAIN=local
  local expected actual
  expected="go$(awk '$1 == "go" { print $2; exit }' "$ROOT/cli/go/go.mod")"
  actual="$(go env GOVERSION 2>/dev/null || echo none)"
  if [[ "$actual" != "$expected" ]]; then
    cat >&2 <<EOF
FATAL: ship requires $expected first on PATH; the runner is $actual.
The audit gates ship against the stdlib that actually ships. Fix:
  go install golang.org/dl/$expected@latest && $expected download
  export PATH="\$($expected env GOROOT)/bin:\$PATH"
EOF
    return 1
  fi
}

ensure_cli() {
  (cd "$ROOT" && make build >/dev/null)
  export PATH="$ROOT/cli/go:$PATH"
  echo "ship-env: reviewed aw binary first on PATH ($ROOT/cli/go/aw)"
}

ensure_library_inputs() {
  local library="${LIBRARY_E2E_LIBRARY_CONTEXT:-$ROOT/../library}"
  local blueprint="${LIBRARY_E2E_BLUEPRINT_SRC:-$ROOT/../blueprints/team}"
  [[ -d "$library" && -d "$blueprint" ]] && return 0
  cat >&2 <<EOF
FATAL: the CLI real-stack journey needs the Library stack inputs before the
gate starts, not an hour into it. Missing:
$([[ -d "$library" ]] || echo "  $library")
$([[ -d "$blueprint" ]] || echo "  $blueprint")
Provide them as sibling checkouts of this repository:
  git clone git@github.com:awebai/library.git
  git clone git@github.com:awebai/blueprints.git
or point LIBRARY_E2E_LIBRARY_CONTEXT / LIBRARY_E2E_BLUEPRINT_SRC at existing
checkouts. See docs/e2e-library-stack.md.
EOF
  return 1
}

ensure_tools() {
  command -v docker >/dev/null 2>&1 || fatal "ship requires docker for its journeys and services"
  command -v uv >/dev/null 2>&1 || fatal "ship requires uv (https://docs.astral.sh/uv/): brew install uv"
  command -v tmux >/dev/null 2>&1 || fatal "ship's guarded launcher tests require tmux: brew install tmux"
  local node_major
  node_major="$(node --version 2>/dev/null | sed 's/^v//;s/\..*//')" || true
  if [[ "$node_major" != "22" ]]; then
    # Trust only the binary's measured version: a stale homebrew opt symlink
    # can leave node@22's path resolving to a different major.
    local pinned_node pinned_major=""
    pinned_node="$(brew --prefix node@22 2>/dev/null || true)"
    [[ -n "$pinned_node" && -x "$pinned_node/bin/node" ]] \
      && pinned_major="$("$pinned_node/bin/node" --version | sed 's/^v//;s/\..*//')"
    if [[ "$pinned_major" == "22" ]]; then
      export PATH="$pinned_node/bin:$PATH"
      echo "ship-env: Node $(node --version) first on PATH (hosted gate pins major 22)"
    else
      fatal "ship requires Node 22 (the major the hosted gate pins); found ${node_major:-none}. Fix: brew install node@22"
    fi
  fi
}

run_gate() {
  ensure_tools
  ensure_toolchain
  ensure_library_inputs
  trap cleanup_owned EXIT
  ensure_services
  ensure_cli
  "$@"
}

# ── self-test ────────────────────────────────────────────────────────
# Stubs live on PATH (like guard-bin) and a throwaway TCP listener stands in
# for a reachable service; no real containers or network services are used.

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  local stub_log="$tmp/docker.log"

  mkdir -p "$tmp/bin"
  cat >"$tmp/bin/docker" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$stub_log"
exit 0
EOF
  chmod +x "$tmp/bin/docker"

  python3 - "$tmp/listener-port" <<'EOF' &
import socket, sys, time
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(32)
with open(sys.argv[1], "w") as handle:
    handle.write(str(server.getsockname()[1]))
time.sleep(60)
EOF
  local listener_pid=$!
  local attempt
  for attempt in $(seq 1 50); do
    [[ -s "$tmp/listener-port" ]] && break
    sleep 0.1
  done
  [[ -s "$tmp/listener-port" ]] || fatal "self-test listener never started"
  local listener_port
  listener_port="$(cat "$tmp/listener-port")"

  # Arm 1: under CI, both services answer, so nothing is provisioned.
  : >"$stub_log"
  (
    export PATH="$tmp/bin:$PATH"
    export CI=1
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT="$listener_port"
    export REDIS_URL="redis://127.0.0.1:$listener_port/0"
    OWNED_CONTAINERS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  if grep -q "run" "$stub_log"; then
    fatal "self-test: reuse path started a container"
  fi
  echo "ok   reachable services are reused and no container is started"

  # Arm 1b: the same reachable services outside CI belong to somebody else;
  # a plain local run provisions its own.
  : >"$stub_log"
  (
    export PATH="$tmp/bin:$PATH"
    unset CI AWEB_SHIP_REUSE_SERVICES
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT="$listener_port"
    export REDIS_URL="redis://127.0.0.1:$listener_port/0"
    OWNED_CONTAINERS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  grep -q -- "run --detach --name $PG_CONTAINER .* $PG_IMAGE" "$stub_log" \
    || fatal "self-test: a plain local run reused a foreign database"
  echo "ok   a plain local run provisions even when a foreign service is listening"

  # Arm 2: nothing answers, so both services are provisioned and removed.
  : >"$stub_log"
  (
    export PATH="$tmp/bin:$PATH"
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=1
    export REDIS_URL="redis://127.0.0.1:1/0"
    OWNED_CONTAINERS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  grep -q -- "run --detach --name $PG_CONTAINER .* $PG_IMAGE" "$stub_log" \
    || fatal "self-test: PostgreSQL was not provisioned as $PG_IMAGE"
  grep -q -- "run --detach --name $REDIS_CONTAINER .* $REDIS_IMAGE" "$stub_log" \
    || fatal "self-test: Redis was not provisioned as $REDIS_IMAGE"
  grep -q -- "rm -f $PG_CONTAINER" "$stub_log" && grep -q -- "rm -f $REDIS_CONTAINER" "$stub_log" \
    || fatal "self-test: provisioned containers were not cleaned up"
  echo "ok   unreachable services are provisioned and cleaned up"

  # Arm 3: the gate fails after provisioning; cleanup must still run.
  : >"$stub_log"
  set +e
  (
    set -e
    export PATH="$tmp/bin:$PATH"
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=1
    export REDIS_URL="redis://127.0.0.1:1/0"
    trap cleanup_owned EXIT
    OWNED_CONTAINERS=()
    ensure_services >/dev/null
    false
  )
  local failed_gate=$?
  set -e
  [[ "$failed_gate" -ne 0 ]] || fatal "self-test: failing gate reported success"
  grep -q -- "rm -f $PG_CONTAINER" "$stub_log" && grep -q -- "rm -f $REDIS_CONTAINER" "$stub_log" \
    || fatal "self-test: cleanup skipped when the gate failed"
  echo "ok   cleanup runs even when the gate fails"

  # Arm 4: a drifted toolchain is refused and the message names the fix.
  cat >"$tmp/bin/go" <<'EOF'
#!/usr/bin/env bash
[[ "$1 $2" == "env GOVERSION" ]] && { echo go0.0.0; exit 0; }
exit 1
EOF
  chmod +x "$tmp/bin/go"
  local refusal
  set +e
  refusal="$(PATH="$tmp/bin:$PATH" bash -c '
    source "'"${BASH_SOURCE[0]}"'" --functions-only
    ensure_toolchain
  ' 2>&1)"
  local refused=$?
  set -e
  [[ "$refused" -ne 0 ]] || fatal "self-test: drifted toolchain was accepted"
  grep -q "requires go" <<<"$refusal" && grep -q "golang.org/dl" <<<"$refusal" \
    || fatal "self-test: toolchain refusal does not name the fix"
  echo "ok   a mismatched Go toolchain is refused with the fix"

  kill "$listener_pid" >/dev/null 2>&1 || true
  echo "ship-env self-test: all arms passed"
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  --functions-only)
    # Sourced by the self-test to exercise a single function in isolation.
    return 0 2>/dev/null || exit 0
    ;;
  "")
    fatal "usage: ship-env.sh <command...> | --self-test"
    ;;
  *)
    run_gate "$@"
    ;;
esac
