#!/usr/bin/env bash
# A naapp package's real-stack e2e, run on the stack's own network.
#
# Usage: naapp-e2e.sh <package dir, relative to the checkout> <enable variable>
#   e.g. naapp-e2e.sh naapp/library LIBRARY_E2E
#
# The app reaches its team server only through its egress guard, at an
# operator-listed origin inside the stack's network, so the tests run there:
# - inside the candidate gate, its runner already joins the stack's network
#   under its scoped runner name (scripts/candidate-network.py prepare), and
#   the gate's compose wrapper adds every service's scoped name;
# - anywhere else (a developer's machine, CI), this script adds the same
#   scoped names with the gate's own override and runs the tests in a
#   disposable runner container joined to the network under the same name.
# Nothing is published to the host.
set -euo pipefail

package_dir="${1:?usage: naapp-e2e.sh <package dir> <enable variable>}"
enable="${2:?usage: naapp-e2e.sh <package dir> <enable variable>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
project="${NAAPP_E2E_PROJECT:?NAAPP_E2E_PROJECT names the compose project of the stack}"
cd "$REPO_ROOT/$package_dir"
compose=(docker compose -p "$project" -f docker-compose.e2e.yml)
# AWID accepts the requests the tests sign for its scoped name.
AWID_PUBLIC_ORIGINS="http://awid:8010,http://$(python3 "$REPO_ROOT/scripts/candidate-network.py" hostname "$project" awid):8010"
export AWID_PUBLIC_ORIGINS

if [[ -n "${CANDIDATE_RUNNER_NAME:-}" ]]; then
  # The gate's runner: its wrapper places the stack and joins the network.
  cleanup() {
    status=$?; trap - EXIT
    "${compose[@]}" down -v --remove-orphans || status=1
    exit "$status"
  }
  trap cleanup EXIT
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  "${compose[@]}" up --build -d
  env "$enable=1" NAAPP_E2E_CONTAINER_NETWORK=1 uv run pytest -q -m e2e -p aweb_naapp_testing.deployment_logs
  exit 0
fi

override="$(mktemp "${TMPDIR:-/tmp}/naapp-e2e-override.XXXXXX")"
cleanup() {
  status=$?; trap - EXIT
  "${compose[@]}" -f "$override" down -v --remove-orphans || status=1
  rm -f "$override"
  exit "$status"
}
trap cleanup EXIT
# The gate's own override: every service's scoped name, and no host ports.
"${compose[@]}" config --format json | python3 "$REPO_ROOT/scripts/candidate-network.py" override > "$override"
compose+=(-f "$override")
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up --build -d --wait

image="aweb-journey-runner:local"
docker build -q -t "$image" -f "$REPO_ROOT/scripts/e2e/journey-runner.Dockerfile" "$REPO_ROOT/scripts/e2e" >/dev/null
runner="$(python3 "$REPO_ROOT/scripts/candidate-network.py" hostname "$project" runner)"
# The checkout is mounted read-only. The package and the coordination server it
# starts each keep their own environment, in a volume over their .venv.
mkdir -p .venv "$REPO_ROOT/server/.venv"
docker run --rm \
  --network "${project}_default" --network-alias "$runner" \
  -v "$REPO_ROOT:/src:ro" \
  -v "/src/$package_dir/.venv" \
  -v /src/server/.venv \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e "$enable=1" \
  -e NAAPP_E2E_PROJECT="$project" \
  -e NAAPP_E2E_CONTAINER_NETWORK=1 \
  -e UV_PYTHON=3.12 \
  -e GOCACHE=/tmp/go-build \
  -e GOMODCACHE=/tmp/go-mod \
  -w "/src/$package_dir" \
  "$image" \
  bash -c '
    set -euo pipefail
    # The checkout is mounted read-only and owned by another user.
    git config --global --add safe.directory "*"
    (cd /src/cli/go && go build -o /tmp/aw/aw ./cmd/aw)
    export PATH="/tmp/aw:$PATH"
    uv sync --frozen
    # The fixtures start this separate project with offline, frozen uv.
    uv sync --frozen --project /src/server
    # A package whose lock has Playwright gets that version of the browser.
    if [[ -x .venv/bin/playwright ]]; then
      uv run --frozen playwright install --with-deps --only-shell chromium
    fi
    uv run --frozen pytest -q -m e2e -p aweb_naapp_testing.deployment_logs -p no:cacheprovider --basetemp=/tmp/pytest
  '
