#!/usr/bin/env bash
# Real AWID + aweb + Folio + aw + channel-core acceptance. No mocks.
# Requires Docker/buildx/Compose, Go, Node/npm and Python 3. Fixed disposable
# project abrm-folio and loopback ports 38000/38010/38765/57432 must be unused.
# AW_BIN may name the exact candidate binary; otherwise build from this tree.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EVIDENCE="${FOLIO_WAKE_EVIDENCE:-$(mktemp -d /tmp/folio-wakes-evidence.XXXXXX)}"
mkdir -p "$EVIDENCE"
COMPOSE=(docker compose -p abrm-folio --project-directory "$ROOT" -f "$ROOT/scripts/e2e/folio-wakes.compose.yml")
BUILDER="folio-wakes-$$"
WORK="$(mktemp -d /tmp/folio-wakes-bin.XXXXXX)"
cleanup() {
  status=$?
  "${COMPOSE[@]}" unpause aweb >/dev/null 2>&1 || true
  "${COMPOSE[@]}" logs --no-color >"$EVIDENCE/services.log" 2>&1 || true
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans || status=1
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  echo "Evidence: $EVIDENCE"
  exit "$status"
}
# Refuse someone else's active gate instead of resetting its state.
if [[ -n "$(docker ps -aq --filter label=com.docker.compose.project=abrm-folio)" ]]; then
  echo 'abrm-folio project already exists; finish its owner-run gate first' >&2
  exit 1
fi
trap cleanup EXIT
# Limit the build as well as every service in the compose file.
docker buildx create --name "$BUILDER" --driver docker-container \
  --driver-opt memory=2g,cpu-period=100000,cpu-quota=200000 >/dev/null
"${COMPOSE[@]}" build --builder "$BUILDER" >"$EVIDENCE/build.log" 2>&1
"${COMPOSE[@]}" up --no-build -d --wait
if [[ -z "${AW_BIN:-}" ]]; then
  (cd "$ROOT/cli/go" && go build -o "$WORK/aw" ./cmd/aw)
  export AW_BIN="$WORK/aw"
fi
(cd "$ROOT/channel-core" && npm ci --ignore-scripts && npm run build) >"$EVIDENCE/channel-build.log" 2>&1
git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/source-sha.txt"
python3 "$ROOT/scripts/e2e/folio_wakes.py" 2>&1 | tee "$EVIDENCE/acceptance.log"
