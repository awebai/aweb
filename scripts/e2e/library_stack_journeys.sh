#!/usr/bin/env bash
# The root e2e stack's journeys. scripts/e2e-library-stack.sh runs this from
# inside the stack's network (the gate's runner, or a disposable runner
# container), with the stack's endpoints and CA in the environment.
#
# Usage: library_stack_journeys.sh seed|cli-suite|all
#   seed       publish the aweb.team catalog blueprint as an installed team
#   cli-suite  the real-binary Go e2e suite (AW_E2E=1, -tags e2e)
#   all        seed, then the suite
#
# Environment (set by e2e-library-stack.sh journey):
#   AWEB_URL, AWID_REGISTRY_URL, LIBRARY_E2E_LIBRARY_URL  in-network endpoints
#   LIBRARY_E2E_PROJECT     the stack's compose project
#   SSL_CERT_FILE           the stack CA, which signs Library's certificate
#   LIBRARY_E2E_BLUEPRINT_SRC  the catalog blueprint to seed
#   AW_BIN                  exact prebuilt aw (release skew); otherwise built here
#   AW_E2E_TEST_RUN         optional Go -run selector

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
: "${AWEB_URL:?}" "${AWID_REGISTRY_URL:?}" "${LIBRARY_E2E_LIBRARY_URL:?}"
: "${LIBRARY_E2E_PROJECT:?}" "${SSL_CERT_FILE:?}" "${LIBRARY_E2E_BLUEPRINT_SRC:?}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

select_aw_binary() {
  if [[ -n "${AW_BIN:-}" ]]; then
    [[ -x "$AW_BIN" ]] || { echo "FATAL: AW_BIN is not executable: $AW_BIN" >&2; return 1; }
    echo "=== Use exact prebuilt aw binary: $AW_BIN ==="
  else
    echo "=== Build the aw binary ==="
    (cd "$REPO_ROOT/cli/go" && go build -o "$WORK/aw" ./cmd/aw)
    AW_BIN="$WORK/aw"
  fi
  export AW_BIN
}

seed() {
  echo "=== Seed the aweb.team catalog blueprint ==="
  LIBRARY_E2E_AWID_URL="$AWID_REGISTRY_URL" \
  LIBRARY_E2E_AWEB_URL="$AWEB_URL" \
  python3 "$REPO_ROOT/scripts/e2e/seed_catalog_blueprint.py"
}

cli_suite() {
  echo "=== Run the real-stack Go e2e suite (AW_E2E=1, -tags e2e) ==="
  local args=(test -tags e2e ./e2e -count=1 -v)
  if [[ -n "${AW_E2E_TEST_RUN:-}" ]]; then
    args+=(-run "$AW_E2E_TEST_RUN")
  fi
  (cd "$REPO_ROOT/cli/go" && AW_E2E=1 go "${args[@]}")
}

select_aw_binary
case "${1:-}" in
  seed) seed ;;
  cli-suite) cli_suite ;;
  all) seed; cli_suite ;;
  *) echo "usage: library_stack_journeys.sh seed|cli-suite|all" >&2; exit 2 ;;
esac
