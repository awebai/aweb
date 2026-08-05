#!/usr/bin/env bash
# Owns the ship gate's ambient dependencies: PostgreSQL, Redis, the pinned Go
# toolchain, the reviewed aw binary, and the Library-stack inputs.
#
# Services that already answer are reused only when somebody provisioned them
# FOR this gate: the hosted workflow's job services (CI is always set there)
# or an explicit opt-in. Otherwise the script provisions disposable containers
# with per-run unique names and Docker-assigned loopback host ports, records
# the container ids it created, and removes exactly those ids on exit -
# success or failure. Nothing with a name this run did not create is ever
# touched, and Docker's port assignment makes host-port collisions impossible
# by construction. pgdbm's test factory reads TEST_DB_HOST/PORT/USER/PASSWORD
# (not libpq PG*), so provisioning exports both families.
#
# Usage: ship-env.sh <command...>   run <command...> inside the owned environment
#        ship-env.sh --self-test    prove the reuse/provision/cleanup/toolchain arms

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_IMAGE=postgres:17
REDIS_IMAGE=redis:7

fatal() {
  printf 'FATAL: %s\n' "$1" >&2
  exit 1
}

new_run_id() {
  od -An -N4 -tx4 /dev/urandom | tr -d ' \n'
}
RUN_ID="$(new_run_id)"

reachable() {
  (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null || return 1
  exec 3>&- 3<&-
}

OWNED_IDS=()
cleanup_owned() {
  local id
  for id in ${OWNED_IDS[@]+"${OWNED_IDS[@]}"}; do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
}

# Creates one container and reports through PROVISIONED_ID/PROVISIONED_PORT.
# The name is unique to this run purely for debuggability; ownership and
# cleanup go by the id Docker returned, and the host port is whatever Docker
# assigned on the loopback interface.
PROVISIONED_ID=""
PROVISIONED_PORT=""
provision() {
  local base="$1" image="$2" container_port="$3"
  shift 3
  PROVISIONED_ID="$(docker run --detach --name "aweb-ship-$base-$RUN_ID" \
    --publish "127.0.0.1::$container_port" "$@" "$image")"
  OWNED_IDS+=("$PROVISIONED_ID")
  PROVISIONED_PORT="$(docker port "$PROVISIONED_ID" "$container_port/tcp" | head -n 1 | sed 's/.*://')"
  [[ -n "$PROVISIONED_PORT" ]] || fatal "docker did not report a host port for $base"
}

wait_healthy() {
  local id="$1" probe="$2"
  local attempt
  for attempt in $(seq 1 90); do
    if docker exec "$id" $probe >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$id" >&2 || true
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
    provision pg "$PG_IMAGE" 5432 \
      --env POSTGRES_USER=postgres \
      --env POSTGRES_PASSWORD=postgres \
      --env POSTGRES_DB=postgres
    wait_healthy "$PROVISIONED_ID" "pg_isready -U postgres -d postgres" \
      || fatal "provisioned PostgreSQL never became ready"
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT="$PROVISIONED_PORT"
    export TEST_DB_USER=postgres TEST_DB_PASSWORD=postgres
    export PGHOST=127.0.0.1 PGPORT="$PROVISIONED_PORT" PGUSER=postgres
    export PGPASSWORD=postgres PGDATABASE=postgres
    echo "ship-env: provisioned $PG_IMAGE on 127.0.0.1:$PROVISIONED_PORT (id ${PROVISIONED_ID:0:12})"
  fi

  local redis_target redis_host redis_port
  redis_target="$(redis_probe_target)"
  redis_host="${redis_target%% *}"
  redis_port="${redis_target##* }"
  if reuse_allowed && reachable "$redis_host" "$redis_port"; then
    echo "ship-env: reusing Redis at $redis_host:$redis_port"
  else
    provision redis "$REDIS_IMAGE" 6379
    wait_healthy "$PROVISIONED_ID" "redis-cli ping" \
      || fatal "provisioned Redis never became ready"
    export REDIS_URL="redis://127.0.0.1:$PROVISIONED_PORT/0"
    echo "ship-env: provisioned $REDIS_IMAGE on 127.0.0.1:$PROVISIONED_PORT (id ${PROVISIONED_ID:0:12})"
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

run_gate() {
  ensure_tools
  ensure_toolchain
  ensure_library_inputs
  trap cleanup_owned EXIT
  ensure_services
  ensure_cli
  # ship-gate refuses to run without this marker, so the gate cannot be
  # reached while skipping the ownership above.
  AWEB_SHIP_ENV_READY="$RUN_ID" "$@"
}

# ── self-test ────────────────────────────────────────────────────────
# Stubs live on PATH (like guard-bin) and a throwaway TCP listener stands in
# for a reachable service; no real containers or network services are used.
# The stub docker returns a fresh container id per `run` and a distinct port
# per id, so ownership and collision behavior are observable from its log.

SELF_TEST_TMP=""
SELF_TEST_LISTENER=""
self_test_cleanup() {
  if [[ -n "$SELF_TEST_LISTENER" ]]; then
    kill "$SELF_TEST_LISTENER" 2>/dev/null || true
  fi
  if [[ -n "$SELF_TEST_TMP" ]]; then
    rm -rf "$SELF_TEST_TMP"
  fi
}

self_test() {
  local tmp listener_pid=""
  tmp="$(mktemp -d)"
  SELF_TEST_TMP="$tmp"
  trap self_test_cleanup EXIT
  local stub_log="$tmp/docker.log"

  mkdir -p "$tmp/bin"
  cat >"$tmp/bin/docker" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "$stub_log"
case "\$1" in
  run)
    count=\$( (grep -c . "$tmp/cid-counter") 2>/dev/null || echo 0)
    echo x >> "$tmp/cid-counter"
    echo "cid\$count"
    ;;
  port)
    echo "127.0.0.1:6000\${2#cid}"
    ;;
  exec)
    exit 0
    ;;
esac
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
  listener_pid=$!
  SELF_TEST_LISTENER="$listener_pid"
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
    OWNED_IDS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  if grep -q "run" "$stub_log"; then
    fatal "self-test: reuse path started a container"
  fi
  echo "ok   reachable services are reused and no container is started"

  # Arm 2: the same reachable services outside CI belong to somebody else;
  # a plain local run provisions its own.
  : >"$stub_log"
  (
    export PATH="$tmp/bin:$PATH"
    unset CI AWEB_SHIP_REUSE_SERVICES
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT="$listener_port"
    export REDIS_URL="redis://127.0.0.1:$listener_port/0"
    OWNED_IDS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  grep -q -- "run --detach --name aweb-ship-pg-" "$stub_log" \
    || fatal "self-test: a plain local run reused a foreign database"
  echo "ok   a plain local run provisions even when a foreign service is listening"

  # Arm 3: provisioning must never remove or reference a container it did not
  # create: no `rm` before the first `run`, and every removal is a recorded id.
  if awk '$1 == "rm" { seen_rm = 1 } $1 == "run" && seen_rm { exit 1 }' "$stub_log"; then :; else
    fatal "self-test: something was removed before anything was created"
  fi
  if grep -- "rm" "$stub_log" | grep -qv -- "rm -f cid"; then
    fatal "self-test: cleanup removed something other than a created container id"
  fi
  echo "ok   provisioning never touches containers it did not create"

  # Arm 4: cleanup removes exactly the ids this run created.
  : >"$stub_log"
  : >"$tmp/cid-counter"
  (
    export PATH="$tmp/bin:$PATH"
    unset CI AWEB_SHIP_REUSE_SERVICES
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=1
    export REDIS_URL="redis://127.0.0.1:1/0"
    OWNED_IDS=()
    ensure_services >/dev/null
    cleanup_owned
  )
  grep -q -- "rm -f cid0" "$stub_log" && grep -q -- "rm -f cid1" "$stub_log" \
    || fatal "self-test: created container ids were not cleaned up"
  [[ "$(grep -c -- "rm -f" "$stub_log")" == "2" ]] \
    || fatal "self-test: cleanup removed more than the two created ids"
  echo "ok   cleanup removes exactly the created container ids"

  # Arm 5: the gate fails after provisioning; cleanup must still run.
  : >"$stub_log"
  : >"$tmp/cid-counter"
  set +e
  (
    set -e
    export PATH="$tmp/bin:$PATH"
    unset CI AWEB_SHIP_REUSE_SERVICES
    export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=1
    export REDIS_URL="redis://127.0.0.1:1/0"
    trap cleanup_owned EXIT
    OWNED_IDS=()
    ensure_services >/dev/null
    false
  )
  local failed_gate=$?
  set -e
  [[ "$failed_gate" -ne 0 ]] || fatal "self-test: failing gate reported success"
  grep -q -- "rm -f cid0" "$stub_log" && grep -q -- "rm -f cid1" "$stub_log" \
    || fatal "self-test: cleanup skipped when the gate failed"
  echo "ok   cleanup runs even when the gate fails"

  # Arm 6: two provisioning runs use distinct names and each removes only its
  # own ids - the concurrent-gate case.
  : >"$stub_log"
  : >"$tmp/cid-counter"
  local run_a_names run_b_names
  for _ in a b; do
    (
      export PATH="$tmp/bin:$PATH"
      unset CI AWEB_SHIP_REUSE_SERVICES
      export TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=1
      export REDIS_URL="redis://127.0.0.1:1/0"
      RUN_ID="$(new_run_id)"
      OWNED_IDS=()
      ensure_services >/dev/null
      cleanup_owned
    )
  done
  run_a_names="$(grep -- "run --detach" "$stub_log" | grep -o -- "--name [^ ]*" | sort)"
  [[ "$(printf '%s\n' "$run_a_names" | sort -u | wc -l | tr -d ' ')" == "4" ]] \
    || fatal "self-test: concurrent runs produced colliding container names"
  [[ "$(grep -c -- "rm -f" "$stub_log")" == "4" ]] \
    || fatal "self-test: concurrent runs did not each clean up their own ids"
  echo "ok   concurrent provisioning runs do not collide"

  # Arm 7: a drifted toolchain is refused and the message names the fix.
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
  SELF_TEST_LISTENER=""
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
