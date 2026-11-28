#!/usr/bin/env bash
# Exercise every freshness check in both directions: a clean fixture must pass,
# and the specific stale artifact the check owns must fail for that reason.
# Each self-test exits non-zero when its clean fixture is refused or its stale
# fixture is accepted, so its exit status is the verdict.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run_self_test() {
  local label="$1"
  shift
  local out
  if ! out="$("$@" 2>&1)"; then
    printf 'FAIL: %s self-test did not complete successfully:\n%s\n' "$label" "$out" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

run_self_test "Python lock" bash scripts/check-python-locks.sh --self-test
run_self_test "generated CLI reference" bash scripts/regenerate-cli-reference.sh --self-test
run_self_test "AWID public site document links" bash scripts/test-awid-site-doc-links.sh
run_self_test "TypeScript dist" bash scripts/test-typescript-dist-freshness.sh
run_self_test "aw wake channel-core bundle" bash scripts/check-wake-channel-core-bundle.sh --self-test

echo "freshness negative fixtures passed in both directions"
