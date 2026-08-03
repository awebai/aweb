#!/usr/bin/env bash
# Run channel's managed real-stack suite with one uniquely owned Compose project.
# The EXIT trap covers success, failure, startup failure, and graceful CI
# cancellation; the outer ship-suite runner separately preserves suite results.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROJECT="aweb-channel-integration-$RANDOM-$$"
RUNTIME="$(mktemp -d "${TMPDIR:-/tmp}/aweb-channel-integration.XXXXXX")"

compose() {
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-channel-integration-cleanup}" \
    docker compose --project-name "$PROJECT" -f "$ROOT/server/docker-compose.yml" "$@"
}

verify_absent() {
  local resource="$1"
  shift
  local found
  if ! found="$("$@")"; then
    echo "Could not verify targeted $resource cleanup for $PROJECT" >&2
    return 1
  fi
  if [[ -n "$found" ]]; then
    echo "Targeted teardown left $resource for $PROJECT: $found" >&2
    return 1
  fi
}

cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT

  if ! compose down -v --remove-orphans >/dev/null 2>&1; then
    echo "Targeted Compose teardown failed for $PROJECT" >&2
    cleanup_failed=1
  fi
  verify_absent containers docker ps -aq \
    --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
  verify_absent volumes docker volume ls -q \
    --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
  verify_absent networks docker network ls -q \
    --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
  rm -rf -- "$RUNTIME" || cleanup_failed=1

  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

# External services cannot exercise the managed outage/reconnect case. The
# canonical release target fails closed instead of reporting that partial mode
# as complete channel integration coverage.
if [[ -n "${AWEB_TEST_URL:-}" || -n "${AWID_TEST_URL:-}" ]]; then
  echo "Channel release integration requires its owned managed stack; unset AWEB_TEST_URL and AWID_TEST_URL" >&2
  exit 2
fi

cd "$ROOT/channel"
CHANNEL_INTEGRATION_COMPOSE_PROJECT="$PROJECT" \
CHANNEL_INTEGRATION_TEMP_ROOT="$RUNTIME" \
npm run test:integration
