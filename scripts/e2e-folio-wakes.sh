#!/usr/bin/env bash
# Real AWID + aweb + Folio + aw + channel-core acceptance. No mocks.
# The services and client share one compose network; no host ports are needed.
# Builds the CLI and channel consumer from this exact checkout inside Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EVIDENCE="${FOLIO_WAKE_EVIDENCE:-$(mktemp -d /tmp/folio-wakes-evidence.XXXXXX)}"
mkdir -p "$EVIDENCE"
COMPOSE=(docker compose -p abrm-folio --project-directory "$ROOT" -f "$ROOT/scripts/e2e/folio-wakes.compose.yml")
BUILDER="folio-wakes-$$"
SEED="folio-wakes-seed-$$"
export FOLIO_WAKES_ORIGIN=https://folio-wakes.test:8765
export FOLIO_WAKES_APP_KEY_FILES='{}'
cleanup() {
  status=$?
  "${COMPOSE[@]}" unpause aweb >/dev/null 2>&1 || true
  "${COMPOSE[@]}" logs --no-color >"$EVIDENCE/services.log" 2>&1 || true
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans || status=1
  docker container rm -f "$SEED" >/dev/null 2>&1 || true
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  echo "Evidence: $EVIDENCE"
  exit "$status"
}
if [[ -n "$(docker ps -aq --filter label=com.docker.compose.project=abrm-folio)" ]]; then
  echo 'abrm-folio project already exists; finish its owner-run gate first' >&2
  exit 1
fi
trap cleanup EXIT
docker buildx create --name "$BUILDER" --driver docker-container \
  --driver-opt memory=2g,cpu-period=100000,cpu-quota=200000 >/dev/null
"${COMPOSE[@]}" build --builder "$BUILDER" >"$EVIDENCE/build.log" 2>&1
# Named volumes and Docker API copies also work when this runner is a container;
# bind paths in that container would otherwise be resolved on the daemon's host.
"${COMPOSE[@]}" create --no-build folio
docker create --name "$SEED" --user 0 --entrypoint /app/.venv/bin/python \
  -v abrm-folio-fixture:/fixture -e PYTHONPATH=/fixture/test-support \
  abrm-folio-aweb /fixture/e2e/folio_wakes_prepare.py >/dev/null
docker cp "$ROOT/scripts/e2e/." "$SEED:/fixture/e2e"
docker cp "$ROOT/naapp-lib/testing/src/." "$SEED:/fixture/test-support"
docker start -a "$SEED"
docker container rm "$SEED" >/dev/null
"${COMPOSE[@]}" up --no-build -d --wait postgres redis awid aweb
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U aweb -d aweb \
  -c 'CREATE DATABASE library OWNER aweb'
git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/source-sha.txt"
"${COMPOSE[@]}" run --rm --no-deps client 2>&1 | tee "$EVIDENCE/acceptance.log"
