#!/usr/bin/env bash
#
# CLI real-stack e2e harness (default-aabq.2).
#
# Brings up the combined awid + aweb + Library stack (default-aabq.1), runs the
# seed and the env-gated Go e2e suite against the real services from inside
# the stack's network, and tears the stack down with -v on exit. The journeys
# run in the network because the server fetches app manifests only over pinned
# HTTPS and every team installs Library before calling it; see
# docs/e2e-library-stack.md.
#
# Usage:
#   ./cli/scripts/e2e.sh            (or: make -C cli e2e)
#
# Requires Docker. The stack builds Library from this checkout and uses its
# committed aweb.team fixture, so no sibling checkout is needed; override the
# fixture with LIBRARY_E2E_BLUEPRINT_SRC to test another checked-out input.
#
# Environment overrides:
#   AW_BIN                     exact prebuilt aw binary (otherwise built from source)
#   AW_E2E_TEST_RUN           optional Go -run selector
#   KEEP_UP=1                 leave the stack up on success (skip teardown)

set -euo pipefail

CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$CLI_DIR/.." && pwd -P)"
STACK="$REPO_ROOT/scripts/e2e-library-stack.sh"

teardown() {
  local status=$? cleanup_status=0
  trap - EXIT
  if [[ "${KEEP_UP:-}" != "1" || $status -ne 0 ]]; then
    "$STACK" down || cleanup_status=$?
  fi
  if (( status != 0 )); then
    exit "$status"
  fi
  exit "$cleanup_status"
}

main() {
  trap teardown EXIT
  if [[ -n "${AW_BIN:-}" ]]; then
    AW_BIN="$(cd "$(dirname "$AW_BIN")" && pwd -P)/$(basename "$AW_BIN")"
    export AW_BIN
  fi

  echo "=== Bring up the stack ==="
  "$STACK" up
  if [[ -n "${AWEB_SKEW_RUNTIME_PROOF_PATH:-}" ]]; then
    "$STACK" server-proof
  fi
  "$STACK" journey bash scripts/e2e/library_stack_journeys.sh all

  echo ""
  echo "ALL PASSED: real-binary e2e suite green against the live stack"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
