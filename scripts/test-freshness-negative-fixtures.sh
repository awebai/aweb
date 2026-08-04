#!/usr/bin/env bash
# Exercise every freshness check in both directions: a clean fixture must pass,
# and the specific stale artifact the check owns must fail for that reason.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run_self_test() {
  local label="$1" expected="$2"
  shift 2
  local out
  if ! out="$("$@" 2>&1)"; then
    printf 'FAIL: %s self-test did not complete successfully:\n%s\n' "$label" "$out" >&2
    return 1
  fi
  printf '%s\n' "$out"
  if ! grep -Fq "$expected" <<<"$out"; then
    printf 'FAIL: %s self-test did not report its negative control: %s\n' "$label" "$expected" >&2
    return 1
  fi
}

run_self_test "Python lock" \
  "self-test passed: clean locks pass; stale AWID version and missing dependent-lock dependency fail" \
  bash scripts/check-python-locks.sh --self-test
run_self_test "generated CLI reference" \
  "self-test passed: clean generation plus visible-addition, removed-command, and stale-output controls" \
  bash scripts/regenerate-cli-reference.sh --self-test
run_self_test "AWID public site document mirrors" \
  "self-test passed: clean mirrors pass; stale copies and dead publication-context links fail" \
  bash scripts/test-awid-site-doc-freshness.sh
run_self_test "TypeScript dist" \
  "self-test passed: clean TypeScript builds pass and source-level security reverts fail" \
  bash scripts/test-typescript-dist-freshness.sh

echo "freshness negative fixtures passed in both directions"
