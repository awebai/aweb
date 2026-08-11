#!/usr/bin/env bash
#
# End-to-end Library stack: bring up awid + aweb + Library on one network,
# seed the aweb.team catalog blueprint into Library, and verify it is live.
#
# This is the self-hosted tier of the aweb e2e harness (default-aabq.1):
# postgres + redis + awid + OSS aweb + Library, all built from source, anchored
# on folio/library docker-compose.e2e.yml.
#
# Usage:
#   ./scripts/e2e-library-stack.sh [all|up|seed|server-proof|down]
#     all  (default)  up + wait healthy + seed + verify + teardown
#     up              build + start the stack, wait until healthy, leave running
#     seed            seed the aweb.team blueprint into an already-running stack
#     server-proof    bind installed aweb version/wheel bytes to container identity
#     down            tear the stack down and remove all state (-v)
#
# Cross-repo dependencies (see docs/e2e-library-stack.md):
#   ../library              Library service source (build context)
#   ../blueprints/team      the aweb.team blueprint seeded into Library
# Override either with LIBRARY_E2E_LIBRARY_CONTEXT / LIBRARY_E2E_BLUEPRINT_SRC.
#
# Environment overrides:
#   LIBRARY_E2E_AWID_PORT      awid host port      (default: 18010)
#   LIBRARY_E2E_AWEB_PORT      aweb host port      (default: 18000)
#   LIBRARY_E2E_LIBRARY_PORT   library host port   (default: 18765)
#   LIBRARY_E2E_POSTGRES_PORT  postgres host port  (default: 55432)
#   AW_BIN                     aw binary to drive the seed (default: aw on PATH)
#   AWEB_SKEW_RUNTIME_PROOF_PATH              server-proof output JSON
#   AWEB_SKEW_EXPECTED_SERVER_VERSION         required installed aweb version
#   AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256    required retained wheel SHA-256
#   AWEB_SKEW_EXPECTED_MCP_VERSION             required installed MCP version
#   KEEP_UP=1                  with `all`, skip teardown on success

set -euo pipefail

ACTION="${1:-all}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.e2e.yml"
# Per-worktree compose project name so concurrent runs from different checkouts
# (e.g. an author and a reviewer worktree) never tear down each other's stack.
# Stable for a given checkout, so up/seed/down within one run target one stack.
PROJECT="${LIBRARY_E2E_PROJECT:-aweb-e2e-stack-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
# Optional overlay compose file, appended only when set. CI uses it to add the
# buildx GHA layer-cache config (docker-compose.e2e.cache.yml); local runs leave
# it unset and are unaffected.
if [[ -n "${LIBRARY_E2E_COMPOSE_OVERLAY:-}" ]]; then
  COMPOSE+=(-f "$LIBRARY_E2E_COMPOSE_OVERLAY")
fi

AWID_PORT="${LIBRARY_E2E_AWID_PORT:-18010}"
AWEB_PORT="${LIBRARY_E2E_AWEB_PORT:-18000}"
LIBRARY_PORT="${LIBRARY_E2E_LIBRARY_PORT:-18765}"
DOCKER_PUBLISHED_HOST="${AWEB_DOCKER_PUBLISHED_HOST:-127.0.0.1}"
case "$DOCKER_PUBLISHED_HOST" in
  127.0.0.1|aweb-docker.test) ;;
  *) echo "unsupported AWEB_DOCKER_PUBLISHED_HOST: $DOCKER_PUBLISHED_HOST" >&2; exit 2 ;;
esac

AWID_URL="http://$DOCKER_PUBLISHED_HOST:$AWID_PORT"
AWEB_URL="http://$DOCKER_PUBLISHED_HOST:$AWEB_PORT"
LIBRARY_URL="http://$DOCKER_PUBLISHED_HOST:$LIBRARY_PORT"

# Resolve a cross-repo sibling checkout. The two inputs (../library, ../blueprints)
# live beside the *main* repo. In a normal checkout that is $REPO_ROOT/..; in a
# git worktree $REPO_ROOT/.. is the worktree's parent, not the main repo's, so we
# also try the main repo's parent (via --git-common-dir). An explicit override
# always wins. Result: a worktree run works with no manual env vars.
resolve_sibling() {
  local subpath="$1" explicit="$2"
  if [[ -n "$explicit" ]]; then
    echo "$explicit"
    return
  fi
  if [[ -d "$REPO_ROOT/../$subpath" ]]; then
    (cd "$REPO_ROOT/../$subpath" && pwd -P)
    return
  fi
  local common main
  if common="$(git -C "$REPO_ROOT" rev-parse --git-common-dir 2>/dev/null)"; then
    main="$(cd "$REPO_ROOT" && cd "$(dirname "$common")" && pwd -P)"
    if [[ -d "$main/../$subpath" ]]; then
      (cd "$main/../$subpath" && pwd -P)
      return
    fi
  fi
  # Conventional path; stack_up fails with a clear message if it does not exist.
  echo "$REPO_ROOT/../$subpath"
}

# Cross-repo build inputs. Exported so the compose file's build context and the
# seed script pick them up.
export LIBRARY_E2E_LIBRARY_CONTEXT="$(resolve_sibling library "${LIBRARY_E2E_LIBRARY_CONTEXT:-}")"
export LIBRARY_E2E_BLUEPRINT_SRC="$(resolve_sibling blueprints/team "${LIBRARY_E2E_BLUEPRINT_SRC:-}")"
# Keep every advertised public endpoint in lockstep with the published-host probes.
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="${LIBRARY_E2E_AWEB_PUBLIC_ORIGIN:-$AWEB_URL}"
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="${LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL:-$AWID_URL}"
export LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN="${LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN:-$LIBRARY_URL}"
# Pin the published ports compose binds so they match the health-check URLs.
export LIBRARY_E2E_AWID_PORT="$AWID_PORT"
export LIBRARY_E2E_AWEB_PORT="$AWEB_PORT"
export LIBRARY_E2E_LIBRARY_PORT="$LIBRARY_PORT"
export LIBRARY_E2E_POSTGRES_PORT="${LIBRARY_E2E_POSTGRES_PORT:-55432}"

wait_health() {
  local label="$1" url="$2"
  echo "Waiting for $label health ($url)..."
  for _ in $(seq 1 90); do
    if curl -sf "$url" >/dev/null 2>&1; then
      echo "  $label healthy"
      return 0
    fi
    sleep 2
  done
  echo "  FATAL: $label never became healthy" >&2
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --tail=40 >&2 || true
  return 1
}

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
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans
  assert_project_absent
}

stack_up() {
  if [[ ! -d "$LIBRARY_E2E_LIBRARY_CONTEXT" ]]; then
    echo "FATAL: library source not found at $LIBRARY_E2E_LIBRARY_CONTEXT" >&2
    echo "Set LIBRARY_E2E_LIBRARY_CONTEXT to the ../library checkout." >&2
    exit 1
  fi
  echo "=== Building and starting the stack ==="
  echo "  library context: $LIBRARY_E2E_LIBRARY_CONTEXT"
  echo "  blueprint src:   $LIBRARY_E2E_BLUEPRINT_SRC"
  # Reset this exact project first and prove it has no residue. A failed reset
  # must not silently reuse state or redirect cleanup to another invocation.
  remove_stack
  "${COMPOSE[@]}" up --build -d
  wait_health awid "$AWID_URL/health"
  wait_health aweb "$AWEB_URL/health"
  wait_health library "$LIBRARY_URL/health"
  echo "  stack healthy: awid=$AWID_URL aweb=$AWEB_URL library=$LIBRARY_URL"
}

stack_seed() {
  echo "=== Seeding the aweb.team catalog blueprint ==="
  AW_BIN="${AW_BIN:-aw}" \
  LIBRARY_E2E_AWID_URL="$AWID_URL" \
  LIBRARY_E2E_LIBRARY_URL="$LIBRARY_URL" \
  LIBRARY_E2E_BLUEPRINT_SRC="$LIBRARY_E2E_BLUEPRINT_SRC" \
  python3 "$REPO_ROOT/scripts/e2e/seed_catalog_blueprint.py"
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
  PROOF_POSTGRES_PORT="$LIBRARY_E2E_POSTGRES_PORT" \
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
    echo "unknown action: $ACTION (use: all|up|seed|server-proof|down)" >&2
    exit 2
    ;;
esac
