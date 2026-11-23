#!/usr/bin/env bash
#
# End-to-end Library stack: bring up awid + aweb + Library on one network,
# seed the aweb.team catalog blueprint into Library, and verify it is live.
#
# This is the self-hosted tier of the aweb e2e harness (default-aabq.1):
# postgres + redis + awid + OSS aweb + Library, all built from source, anchored
# on folio/library docker-compose.e2e.yml.
#
# Journeys run inside the stack's network, never from the host: the server
# fetches an app manifest only over pinned HTTPS, so Library serves TLS at an
# in-network name signed by a stack CA, and every team installs Library before
# it calls a member route. Inside the candidate gate the runner already sits in
# the network; elsewhere `journey` starts a disposable runner container there
# (scripts/e2e/journey-runner.Dockerfile). Nothing is published to the host.
#
# Usage:
#   ./scripts/e2e-library-stack.sh [all|up|seed|journey|server-proof|down]
#     all  (default)  up + seed + teardown
#     up              build + prepare + start the stack, wait until healthy
#     seed            seed the aweb.team blueprint into an already-running stack
#     journey <cmd>   run <cmd> (relative to the checkout) inside the network
#     server-proof    bind installed aweb version/wheel bytes to container identity
#     down            tear the stack down and remove all state (-v)
#
# Committed local inputs (see docs/e2e-library-stack.md):
#   naapp/library                                  Library service source, built
#                                                  from this checkout's root
#   naapp/library/test-vectors/blueprints/team     seeded aweb.team blueprint
# Override the blueprint with LIBRARY_E2E_BLUEPRINT_SRC.
#
# Environment overrides:
#   AW_BIN                     aw binary for the journeys (default: built from source)
#   AWEB_SKEW_RUNTIME_PROOF_PATH              server-proof output JSON
#   AWEB_SKEW_EXPECTED_SERVER_VERSION         required installed aweb version
#   AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256    required retained wheel SHA-256
#   AWEB_SKEW_EXPECTED_MCP_VERSION             required installed MCP version
#   KEEP_UP=1                  with `all`, skip teardown on success

set -euo pipefail

ACTION="${1:-all}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$REPO_ROOT/scripts/journey-network.sh"
COMPOSE_FILE="$REPO_ROOT/docker-compose.e2e.yml"
# Per-worktree compose project name so concurrent runs from different checkouts
# (e.g. an author and a reviewer worktree) never tear down each other's stack.
# Stable for a given checkout, so up/seed/down within one run target one stack.
PROJECT="${LIBRARY_E2E_PROJECT:-aweb-e2e-stack-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)}"
export LIBRARY_E2E_PROJECT="$PROJECT"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
# Optional overlay compose file, appended only when set. CI uses it to add the
# buildx GHA layer-cache config (docker-compose.e2e.cache.yml); local runs leave
# it unset and are unaffected.
if [[ -n "${LIBRARY_E2E_COMPOSE_OVERLAY:-}" ]]; then
  COMPOSE+=(-f "$LIBRARY_E2E_COMPOSE_OVERLAY")
fi

# Every service is addressed by its project-scoped in-network name, the same
# name the candidate gate's network adds, so the TLS name and the team-auth
# audiences are one origin wherever the journeys run.
LIBRARY_E2E_AWID_HOST="$(journey_hostname "$PROJECT" awid)"
LIBRARY_E2E_AWEB_HOST="$(journey_hostname "$PROJECT" aweb)"
LIBRARY_E2E_LIBRARY_HOST="$(journey_hostname "$PROJECT" library)"
export LIBRARY_E2E_AWID_HOST LIBRARY_E2E_AWEB_HOST LIBRARY_E2E_LIBRARY_HOST
AWID_URL="http://$LIBRARY_E2E_AWID_HOST:8010"
AWEB_URL="https://$LIBRARY_E2E_AWEB_HOST:8000"
LIBRARY_URL="https://$LIBRARY_E2E_LIBRARY_HOST:8765"
# Container ports; the stack publishes none.
AWID_PORT=8010
AWEB_PORT=8000
LIBRARY_PORT=8765
POSTGRES_PORT=5432

# Both inputs are versioned under this checkout, so release evidence and normal
# e2e runs consume the same exact source. The blueprint override remains supported.
export LIBRARY_E2E_BLUEPRINT_SRC="${LIBRARY_E2E_BLUEPRINT_SRC:-$REPO_ROOT/naapp/library/test-vectors/blueprints/team}"

assert_project_absent() {
  local containers networks volumes images
  containers="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")"
  networks="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  images="$(docker images -q --filter "label=com.docker.compose.project=$PROJECT")"
  if [[ -n "$containers$networks$volumes$images" ]]; then
    echo "FATAL: Compose project $PROJECT left container/network/volume/image residue" >&2
    echo "  containers=${containers:-none} networks=${networks:-none} volumes=${volumes:-none} images=${images:-none}" >&2
    return 1
  fi
}

remove_stack() {
  remove_preparation_containers
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans
  assert_project_absent
}

# The seed container prepare_fixture writes the fixture through, while it exists.
PREPARATION_SEED=""

# Removes the live seed; a removal failure is reported and returned.
release_preparation_seed() {
  [[ -n "$PREPARATION_SEED" ]] || return 0
  local seed="$PREPARATION_SEED"
  PREPARATION_SEED=""
  if ! docker rm -f "$seed" >/dev/null; then
    echo "FATAL: could not remove the preparation container $seed" >&2
    return 1
  fi
}

# An interrupted run removes its live seed, then exits with the signal's status,
# which runs the `all` action's teardown.
trap 'release_preparation_seed; exit 130' INT
trap 'release_preparation_seed; exit 143' TERM

# prepare_fixture's seed containers, named "$PROJECT-prepare-<pid>". Compose
# lists only the containers it created, so a seed a killed run left behind is
# removed here by name, or it would keep the fixture volume in use.
remove_preparation_containers() {
  local seeds
  seeds="$(docker ps -aq --filter "name=^${PROJECT}-prepare-")"
  if [[ -n "$seeds" ]]; then
    # shellcheck disable=SC2086 # one container id per word
    docker rm -f $seeds >/dev/null
  fi
}

stack_up() {
  if [[ ! -f "$REPO_ROOT/naapp/library/Dockerfile" ]]; then
    echo "FATAL: library source not found at $REPO_ROOT/naapp/library" >&2
    exit 1
  fi
  echo "=== Building, preparing and starting the stack ==="
  echo "  library source:  $REPO_ROOT/naapp/library"
  echo "  blueprint src:   $LIBRARY_E2E_BLUEPRINT_SRC"
  # Reset this exact project first and prove it has no residue. A failed reset
  # must not silently reuse state or redirect cleanup to another invocation.
  remove_stack
  "${COMPOSE[@]}" build
  # Creating the services creates the stack's network, and the project-labelled
  # fixture and library-source volumes the preparation writes into.
  "${COMPOSE[@]}" create --no-build
  prepare_fixture
  LIBRARY_E2E_STACK_SUBNET="$(python3 "$REPO_ROOT/scripts/candidate-network.py" subnet "${PROJECT}_default")"
  export LIBRARY_E2E_STACK_SUBNET
  "${COMPOSE[@]}" -f "$REPO_ROOT/scripts/e2e/stack-subnet.compose.yml" up --no-build -d --wait
  echo "  stack healthy: awid=$AWID_URL aweb=$AWEB_URL library=$LIBRARY_URL"
}

# The stack CA and the certificate for Library's and aweb's in-network names, the stack
# scripts the services run, and Library's template and grant-read key. Named
# volumes and Docker API copies also work when this runs inside a container.
prepare_fixture() {
  PREPARATION_SEED="$PROJECT-prepare-$$"
  # The project label makes a leftover seed visible to assert_project_absent.
  docker create --name "$PREPARATION_SEED" --label "com.docker.compose.project=$PROJECT" \
    --user 0 --entrypoint /app/.venv/bin/python \
    -v "$PROJECT-fixture:/fixture" -e PYTHONPATH=/fixture/test-support \
    "$PROJECT-aweb" /fixture/e2e/stack_tls_prepare.py "$LIBRARY_E2E_LIBRARY_HOST" "$LIBRARY_E2E_AWEB_HOST" localhost >/dev/null
  local status=0
  {
    docker cp "$REPO_ROOT/scripts/e2e/." "$PREPARATION_SEED:/fixture/e2e" &&
      docker cp "$REPO_ROOT/naapp-lib/testing/src/." "$PREPARATION_SEED:/fixture/test-support" &&
      docker start -a "$PREPARATION_SEED"
  } || status=$?
  release_preparation_seed || { (( status != 0 )) || status=1; }
  (( status == 0 )) || return "$status"
  docker run --rm --user 0 --entrypoint /app/.venv/bin/python \
    -v "$PROJECT-fixture:/fixture" -v "$PROJECT-library-source:/app/naapp/library/src/library" \
    -e PYTHONPATH=/fixture/e2e "$PROJECT-library" \
    /fixture/e2e/library_stack_prepare.py "$LIBRARY_URL"
}

# Run a command from the checkout inside the stack's network, with the stack's
# endpoints and CA in its environment.
stack_journey() {
  (( $# > 0 )) || { echo "usage: e2e-library-stack.sh journey <command...>" >&2; return 2; }
  local env=(
    -e AWEB_URL="$AWEB_URL" -e AWID_REGISTRY_URL="$AWID_URL"
    -e LIBRARY_E2E_LIBRARY_URL="$LIBRARY_URL" -e LIBRARY_E2E_PROJECT="$PROJECT"
    -e AW_E2E_TEST_RUN="${AW_E2E_TEST_RUN:-}"
  )
  if [[ -n "${CANDIDATE_RUNNER_NAME:-}" ]]; then
    # The gate's runner is attached to the stack network already.
    local ca
    ca="$(mktemp)"
    docker run --rm --entrypoint cat -v "$PROJECT-fixture:/fixture:ro" "$PROJECT-aweb" /fixture/tls/ca.pem >"$ca"
    (cd "$REPO_ROOT" && AWEB_URL="$AWEB_URL" AWID_REGISTRY_URL="$AWID_URL" \
      LIBRARY_E2E_LIBRARY_URL="$LIBRARY_URL" SSL_CERT_FILE="$ca" "$@")
    return
  fi
  # The journeys write only to their own temporary directories, never to the
  # mounted checkout; Go's module cache persists in a named volume.
  local image="aweb-journey-runner:local"
  docker build -q -t "$image" -f "$REPO_ROOT/scripts/e2e/journey-runner.Dockerfile" "$REPO_ROOT/scripts/e2e" >/dev/null
  local mounts=(
    -v "$REPO_ROOT:/src:ro"
    -v /var/run/docker.sock:/var/run/docker.sock
    -v "$PROJECT-fixture:/fixture:ro"
    -v "$LIBRARY_E2E_BLUEPRINT_SRC:/blueprint:ro"
    -v aweb-journey-runner-gomod:/go/pkg/mod
  )
  env+=(-e SSL_CERT_FILE=/fixture/tls/ca.pem -e LIBRARY_E2E_BLUEPRINT_SRC=/blueprint)
  if [[ -n "${AW_BIN:-}" ]]; then
    mounts+=(-v "$AW_BIN:/aw-bin/aw:ro")
    env+=(-e AW_BIN=/aw-bin/aw)
  fi
  docker run --rm --network "${PROJECT}_default" "${mounts[@]}" "${env[@]}" -w /src "$image" "$@"
}

stack_seed() {
  stack_journey bash scripts/e2e/library_stack_journeys.sh seed
}

stack_server_proof() {
  : "${AWEB_SKEW_RUNTIME_PROOF_PATH:?server-proof requires its output path}"
  : "${AWEB_SKEW_EXPECTED_SERVER_VERSION:?server-proof requires expected version}"
  : "${AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256:?server-proof requires expected wheel SHA-256}"
  : "${AWEB_SKEW_EXPECTED_MCP_VERSION:?server-proof requires expected MCP version}"
  : "${AW_SKEW_CELL_IDENTITY_SHA256:?server-proof requires cell identity SHA-256}"
  [[ "$AWEB_SKEW_RUNTIME_PROOF_PATH" = /* ]] \
    || { echo "FATAL: server-proof output path must be absolute" >&2; return 1; }

  local container_id image_id runtime_json
  container_id="$("${COMPOSE[@]}" ps -q aweb)"
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "FATAL: aweb container identity is not a full Docker ID" >&2; return 1; }
  image_id="$(docker inspect --format '{{.Image}}' "$container_id")"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo "FATAL: aweb image identity is not a sha256 ID" >&2; return 1; }
  runtime_json="$("${COMPOSE[@]}" exec -T \
    -e EXPECTED_SERVER_VERSION="$AWEB_SKEW_EXPECTED_SERVER_VERSION" \
    -e EXPECTED_WHEEL_SHA256="$AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256" \
    -e EXPECTED_MCP_VERSION="$AWEB_SKEW_EXPECTED_MCP_VERSION" \
    aweb python -c '
import glob
import hashlib
import importlib.metadata
import json
import os
import re

def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()

inventory = {}
for distribution in importlib.metadata.distributions():
    name = normalized(distribution.metadata["Name"])
    assert name not in inventory, name
    inventory[name] = distribution.version
inventory = dict(sorted(inventory.items()))
server = importlib.metadata.version("aweb")
mcp = importlib.metadata.version("mcp")
wheels = glob.glob("/opt/aweb-artifact/*.whl")
assert len(wheels) == 1, wheels
wheel = hashlib.sha256(open(wheels[0], "rb").read()).hexdigest()
assert server == os.environ["EXPECTED_SERVER_VERSION"], (server, os.environ["EXPECTED_SERVER_VERSION"])
assert wheel == os.environ["EXPECTED_WHEEL_SHA256"], (wheel, os.environ["EXPECTED_WHEEL_SHA256"])
assert mcp == os.environ["EXPECTED_MCP_VERSION"], (mcp, os.environ["EXPECTED_MCP_VERSION"])
canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
print(json.dumps({
    "installed_distributions": inventory,
    "installed_distributions_sha256": hashlib.sha256(canonical).hexdigest(),
    "mcp_version": mcp,
    "server_version": server,
    "wheel_sha256": wheel,
}, sort_keys=True, separators=(",", ":")))
')"

  PROOF_CONTAINER_ID="$container_id" \
  PROOF_IMAGE_ID="$image_id" \
  PROOF_RUNTIME_JSON="$runtime_json" \
  PROOF_PROJECT="$PROJECT" \
  PROOF_CELL_IDENTITY_SHA256="$AW_SKEW_CELL_IDENTITY_SHA256" \
  PROOF_AWEB_PORT="$AWEB_PORT" \
  PROOF_AWID_PORT="$AWID_PORT" \
  PROOF_LIBRARY_PORT="$LIBRARY_PORT" \
  PROOF_POSTGRES_PORT="$POSTGRES_PORT" \
  python3 - "$AWEB_SKEW_RUNTIME_PROOF_PATH" <<'PY'
import json
import os
from pathlib import Path
import sys

runtime = json.loads(os.environ["PROOF_RUNTIME_JSON"])
expected = {
    "installed_distributions", "installed_distributions_sha256", "mcp_version",
    "server_version", "wheel_sha256",
}
assert set(runtime) == expected, runtime
runtime.update({
    "cell_identity_sha256": os.environ["PROOF_CELL_IDENTITY_SHA256"],
    "container_id": os.environ["PROOF_CONTAINER_ID"],
    "image_id": os.environ["PROOF_IMAGE_ID"],
    "ports": {
        "aweb": int(os.environ["PROOF_AWEB_PORT"]),
        "awid": int(os.environ["PROOF_AWID_PORT"]),
        "library": int(os.environ["PROOF_LIBRARY_PORT"]),
        "postgres": int(os.environ["PROOF_POSTGRES_PORT"]),
    },
    "project": os.environ["PROOF_PROJECT"],
})
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(runtime, sort_keys=True, separators=(",", ":")) + "\n")
temporary.replace(path)
PY
  echo "  exact server runtime proven: aweb=$AWEB_SKEW_EXPECTED_SERVER_VERSION image=$image_id"
}

stack_down() {
  echo "=== Tearing down the stack (removing all state) ==="
  remove_stack
}

case "$ACTION" in
  up)
    stack_up
    ;;
  seed)
    stack_seed
    ;;
  journey)
    shift
    stack_journey "$@"
    ;;
  server-proof)
    stack_server_proof
    ;;
  down)
    stack_down
    ;;
  all)
    trap 'status=$?; trap - EXIT; cleanup=0; if [[ "${KEEP_UP:-}" != "1" || $status -ne 0 ]]; then stack_down || cleanup=$?; fi; if (( status != 0 )); then exit "$status"; fi; exit "$cleanup"' EXIT
    stack_up
    stack_seed
    echo ""
    echo "ALL PASSED: awid + aweb + Library up healthy and seeded with aweb.team"
    ;;
  *)
    echo "unknown action: $ACTION (use: all|up|seed|journey|server-proof|down)" >&2
    exit 2
    ;;
esac
