#!/usr/bin/env bash
#
# CLI real-stack e2e harness (default-aabq.2).
#
# Brings up the combined awid + aweb + Library stack (default-aabq.1), selects
# an exact aw binary, runs the env-gated Go e2e suite against the real services,
# and tears the stack down with -v on exit.
#
# Usage:
#   ./cli/scripts/e2e.sh            (or: make -C cli e2e)
#
# Requires Docker and the sibling ../library + ../blueprints checkouts. The
# stack script auto-resolves those even from a git worktree, so no manual env
# vars are needed; override with LIBRARY_E2E_LIBRARY_CONTEXT /
# LIBRARY_E2E_BLUEPRINT_SRC if your layout differs.
#
# Environment overrides:
#   LIBRARY_E2E_AWID_PORT     awid host port    (default: 18010)
#   LIBRARY_E2E_AWEB_PORT     aweb host port    (default: 18000)
#   LIBRARY_E2E_LIBRARY_PORT  library host port (default: 18765)
#   AW_BIN                     exact prebuilt aw binary (otherwise build source)
#   AW_E2E_TEST_RUN           optional Go -run selector
#   KEEP_UP=1                 leave the stack up on success (skip teardown)

set -euo pipefail

CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$CLI_DIR/.." && pwd -P)"
STACK="$REPO_ROOT/scripts/e2e-library-stack.sh"

AWID_PORT="${LIBRARY_E2E_AWID_PORT:-18010}"
AWEB_PORT="${LIBRARY_E2E_AWEB_PORT:-18000}"
LIBRARY_PORT="${LIBRARY_E2E_LIBRARY_PORT:-18765}"

AWEB_URL="http://127.0.0.1:$AWEB_PORT"
AWID_URL="http://127.0.0.1:$AWID_PORT"
LIBRARY_URL="http://127.0.0.1:$LIBRARY_PORT"

teardown() {
  local status=$?
  if [[ "${KEEP_UP:-}" != "1" || $status -ne 0 ]]; then
    "$STACK" down || true
  fi
  exit $status
}

select_aw_binary() {
  # The ordinary journey builds source. A skew cell supplies exact downloaded
  # bytes through AW_BIN; never rebuild or replace those bytes here.
  if [[ -n "${AW_BIN:-}" ]]; then
    AW_BIN="$(cd "$(dirname "$AW_BIN")" && pwd -P)/$(basename "$AW_BIN")"
    [[ -x "$AW_BIN" ]] || {
      echo "FATAL: AW_BIN is not executable: $AW_BIN" >&2
      return 1
    }
    echo "=== Use exact prebuilt aw binary: $AW_BIN ==="
  else
    echo "=== Build the aw binary ==="
    make -C "$CLI_DIR/go" build
    AW_BIN="$CLI_DIR/go/aw"
  fi
}

configure_go_args() {
  GO_ARGS=(test -tags e2e ./e2e -count=1 -v)
  if [[ -n "${AW_E2E_TEST_RUN:-}" ]]; then
    GO_ARGS+=(-run "$AW_E2E_TEST_RUN")
  fi
}

main() {
  trap teardown EXIT
  select_aw_binary

  echo "=== Bring up + seed the stack ==="
  "$STACK" up
  AW_BIN="$AW_BIN" "$STACK" seed

  echo "=== Run the real-stack Go e2e suite (AW_E2E=1, -tags e2e) ==="
  configure_go_args
  (
    cd "$CLI_DIR/go"
    AW_E2E=1 \
    AW_BIN="$AW_BIN" \
    AWEB_URL="$AWEB_URL" \
    AWID_REGISTRY_URL="$AWID_URL" \
    LIBRARY_E2E_LIBRARY_URL="$LIBRARY_URL" \
    go "${GO_ARGS[@]}"
  )

  echo ""
  echo "ALL PASSED: real-binary e2e suite green against the live stack"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
