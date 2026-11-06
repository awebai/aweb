#!/usr/bin/env bash
# Real Library grant/custody acceptance using compose DNS, HTTPS, operator admin
# and the current CLI's pin/CAS install. All clients/services stay inside Docker.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${GRANT_APP_E2E_REPO_ROOT:-$SCRIPT_DIR/..}" && pwd -P)"
PROJECT="${GRANT_APP_E2E_PROJECT:-aweb-e2e-grant-app}"
export GRANT_APP_E2E_PROJECT="$PROJECT"
export BUILDX_CONFIG="${BUILDX_CONFIG:-/tmp/aweb-candidate-buildx}"
BUILDER="${GRANT_APP_E2E_BUILDER:-${BUILDX_BUILDER:-aweb-candidate-gate}}"
COMPOSE=(docker compose -p "$PROJECT" --project-directory "$REPO_ROOT" -f "$REPO_ROOT/docker-compose.e2e.yml" -f "$REPO_ROOT/scripts/e2e/grant-app-acceptance.compose.yml")
EVIDENCE="${GRANT_APP_E2E_EVIDENCE_DIR:-$(mktemp -d /tmp/aweb-grant-app-evidence.XXXXXX)}"
mkdir -p "$EVIDENCE"
exec > >(tee -a "$EVIDENCE/run.log") 2>&1
SEED="grant-app-seed-$$"
cleanup() {
  status=$?
  "${COMPOSE[@]}" logs --no-color >"$EVIDENCE/compose-logs.txt" 2>&1 || true
  "${COMPOSE[@]}" ps >"$EVIDENCE/compose-ps.txt" 2>&1 || true
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
    | xargs -r docker inspect -f '{{.Name}} cpus_nano={{.HostConfig.NanoCpus}} memory={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' >"$EVIDENCE/container-limits.txt" 2>&1 || true
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans || status=1
  docker rm -f "$SEED" >/dev/null 2>&1 || true
  for kind in container network volume image; do
    case "$kind" in
      container) residue="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ;;
      network) residue="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ;;
      volume) residue="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ;;
      image) residue="$(docker images -q --filter "label=com.docker.compose.project=$PROJECT")" ;;
    esac
    [[ -z "$residue" ]] || { echo "$kind residue for $PROJECT: $residue" >&2; status=1; }
  done
  echo "evidence kept in $EVIDENCE"
  exit "$status"
}
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  echo "project $PROJECT already exists; refusing to reuse someone else's state" >&2
  exit 1
fi
trap cleanup EXIT
docker buildx inspect "$BUILDER" >"$EVIDENCE/builder.txt" 2>&1
"${COMPOSE[@]}" build --builder "$BUILDER" >"$EVIDENCE/build.log" 2>&1
"${COMPOSE[@]}" create --no-build aweb
docker create --name "$SEED" --user 0 --entrypoint /app/.venv/bin/python \
  -v "$PROJECT-fixture:/fixture" -e PYTHONPATH=/fixture/test-support \
  "$PROJECT-aweb" /fixture/e2e/grant_app_prepare.py >/dev/null
docker cp "$REPO_ROOT/scripts/e2e/." "$SEED:/fixture/e2e"
docker cp "$REPO_ROOT/naapp-lib/testing/src/." "$SEED:/fixture/test-support"
docker start -a "$SEED"
docker rm "$SEED" >/dev/null
"${COMPOSE[@]}" up --no-build -d --wait postgres redis awid aweb library
# The creation-time bounds apply to the client too.
unbounded="$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" \
  | xargs -r docker inspect -f '{{.Name}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' \
  | awk '$2 == 0 || $3 == 0 || $4 == "<nil>" || $4 <= 0 {print $1}')"
[[ -z "$unbounded" ]] || { echo "unbounded containers: $unbounded" >&2; exit 1; }
git -C "$REPO_ROOT" rev-parse HEAD >"$EVIDENCE/source-sha.txt"
"${COMPOSE[@]}" run --rm --no-deps client 2>&1 | tee "$EVIDENCE/acceptance.log"
