#!/usr/bin/env bash
# Run channel's managed real-stack suite with one uniquely owned Compose project.
# The EXIT trap covers success, failure, startup failure, and graceful CI
# cancellation; the outer ship-suite runner separately preserves suite results.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROJECT="aweb-channel-integration-$RANDOM-$$"
RUNTIME="${TMPDIR:-/tmp}/$PROJECT.runtime"
RUNTIME_OWNED=0
RESULTS="$RUNTIME/vitest-report.json"

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
  trap - EXIT HUP INT TERM

  if [[ "$RUNTIME_OWNED" -eq 1 ]]; then
    # --rmi local removes Compose-built project images but never the pulled
    # Postgres/Redis images. The exact generated image references are checked
    # separately so a failed query cannot look like absence.
    if ! compose down -v --remove-orphans --rmi local >/dev/null 2>&1; then
      echo "Targeted Compose teardown failed for $PROJECT" >&2
      cleanup_failed=1
    fi
    verify_absent containers docker ps -aq \
      --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
    verify_absent volumes docker volume ls -q \
      --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
    verify_absent networks docker network ls -q \
      --filter label=com.docker.compose.project="$PROJECT" || cleanup_failed=1
    verify_absent "awid image" docker image ls -q \
      --filter reference="$PROJECT-awid" || cleanup_failed=1
    verify_absent "aweb image" docker image ls -q \
      --filter reference="$PROJECT-aweb" || cleanup_failed=1
    rm -rf -- "$RUNTIME" || cleanup_failed=1
  fi

  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}

# Install cleanup before acquiring the first owned resource. Signal traps turn
# graceful cancellation into an explicit nonzero exit, then the EXIT trap owns
# teardown and preserves that primary status.
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# External services cannot exercise the managed outage/reconnect case. The
# canonical release target fails closed instead of reporting that partial mode
# as complete channel integration coverage.
if [[ -n "${AWEB_TEST_URL:-}" || -n "${AWID_TEST_URL:-}" ]]; then
  echo "Channel release integration requires its owned managed stack; unset AWEB_TEST_URL and AWID_TEST_URL" >&2
  exit 2
fi

# The path and ownership bit are set before mkdir, so cancellation after mkdir
# creates the directory can still target exactly what this process acquired.
RUNTIME_OWNED=1
mkdir -m 700 -- "$RUNTIME"

cd "$ROOT/channel"
if CHANNEL_INTEGRATION_COMPOSE_PROJECT="$PROJECT" \
  CHANNEL_INTEGRATION_TEMP_ROOT="$RUNTIME" \
  npm run test:integration -- --reporter=json --outputFile="$RESULTS"; then
  test_status=0
else
  test_status=$?
fi
if [[ "$test_status" -ne 0 ]]; then
  exit "$test_status"
fi

# Vitest exits zero when tests are skipped, so status alone is not release
# evidence. Require the exact managed inventory before cleanup may report green.
node - "$RESULTS" <<'NODE'
const fs = require("node:fs");
const path = process.argv[2];
let report;
try {
  report = JSON.parse(fs.readFileSync(path, "utf8"));
} catch (error) {
  console.error(`Channel integration result report is missing or invalid: ${error.message}`);
  process.exit(1);
}
const expected = {
  numTotalTestSuites: 1,
  numPassedTestSuites: 1,
  numFailedTestSuites: 0,
  numPendingTestSuites: 0,
  numTotalTests: 2,
  numPassedTests: 2,
  numFailedTests: 0,
  numPendingTests: 0,
  numTodoTests: 0,
};
const differences = [];
if (!Array.isArray(report.testResults) || report.testResults.length !== 1) {
  differences.push(`testResults.length=${report.testResults?.length ?? "missing"}, expected 1`);
}
for (const [key, value] of Object.entries(expected)) {
  if ((report[key] ?? 0) !== value) differences.push(`${key}=${report[key] ?? "missing"}, expected ${value}`);
}
if (differences.length > 0) {
  console.error(`Channel integration inventory is incomplete: ${differences.join("; ")}`);
  process.exit(1);
}
console.log("Channel integration inventory: 1 file, 2 passed, 0 skipped");
NODE
