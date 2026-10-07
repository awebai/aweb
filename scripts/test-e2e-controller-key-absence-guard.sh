#!/usr/bin/env bash
# Mutation guard for the post-fetch controller-key absence assertion. The full
# journey must fail for exactly that assertion when the derived key path is
# seeded immediately before the real observation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

# Gate artifacts live outside the disposable runner volume. Standalone runs
# retain unexpected output in a private directory under their temp root.
artifact_dir="$(mktemp -d "${CANDIDATE_LOG_DIR:-${TMPDIR:-/tmp}}/aweb-controller-key-guard.XXXXXX")"
output="$artifact_dir/journey.log"
(umask 077; : >"$output")
keep_output=0
cleanup_output() {
  if [[ "$keep_output" == 0 ]]; then
    rm -f -- "$output"
    rmdir -- "$artifact_dir"
  fi
}
trap cleanup_output EXIT

status=0
AWEB_E2E_SEED_ERIN_CONTROLLER_KEY_LEAK=1 \
  ./scripts/e2e-oss-user-journey.sh >"$output" 2>&1 || status=$?

seeded="SEED: simulated post-fetch controller-key leak at the production-resolved path"
expected="FAIL: erin remote home has no controller team key (unexpected "
terminal="=== Done ==="
seed_count="$(grep -Fc "$seeded" "$output" || true)"
diagnostic_count="$(grep -Fc "$expected" "$output" || true)"
terminal_count="$(grep -Fxc "$terminal" "$output" || true)"
if [[ "$status" -ne 1 || "$seed_count" -ne 1 || "$diagnostic_count" -ne 1 || "$terminal_count" -ne 1 ]] || \
   ! grep -Fq "FAILED: 1 failures," "$output"; then
  echo "FAIL: controller-key mutation did not make only the real absence assertion fail after a complete journey" >&2
  echo "journey status: $status; seed count: $seed_count; exact diagnostic count: $diagnostic_count; terminal count: $terminal_count" >&2
  keep_output=1
  echo "Full child output retained privately: $output" >&2
  exit 1
fi

printf '%s\n' "$(grep -F "$expected" "$output")"
echo "self-test passed: a post-fetch key at the production-resolved path makes the real E2E assertion fail"
