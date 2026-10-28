#!/usr/bin/env bash
# The OSS product proof. The entry point selects missing stages; this script
# runs their existing product targets and writes their real results.
set -euo pipefail

run() { printf '\n=== candidate: %s ===\n' "$1"; make "$1"; }
if [[ "${1:-}" == "--isolated-suites" ]]; then
  export TEST_EGRESS_RUNNER=
  run test-server
  run test-awid
  run test-naapp
  run test-cli
  run test-cli-auth-v2
  run _candidate-unit-channel
  run test-channel-name-live-contract
  run _candidate-unit-channel-core
  run _candidate-unit-pi
  exit 0
fi

log_dir="${CANDIDATE_LOG_DIR:?CANDIDATE_LOG_DIR is required}"
stages="${1:-checks unit artifacts integration}"
checks() {
  run _candidate-gate-docker-boundaries
  run test-shipping
  run check-page-renderer-bundle
  run check-aw-commit-repo-stamp
  run check-cli-go-tidy
  run check-cli-release-vcs-stamps
  run test-python-locks
  run lint-naapp
  run test-sot-source-inventories
  run test-identity-python-inventory
  run test-identity-go-inventory
  run test-identity-ts-inventory
  run test-vector-provenance
  run test-federation-error-reference
  run test-federation-authority-mutations
  run test-federation-harness
  run test-cli-reference
  run test-mcp-tools-reference
  run _candidate-channel-version
  run check-a2a-copy-guardrails
  run test-go-vulnerability-audit
  run check-go-vulnerability-audit
  run test-release-cli-version
}
unit() {
  run _candidate-unit-suites
}
artifacts() {
  run _candidate-artifact-server
  run _candidate-artifact-awid-package
  run _candidate-artifact-awid-image
  run _candidate-artifact-naapp-package
  run _candidate-artifact-channel
  run _candidate-artifact-pi
  run _candidate-artifact-skills
  run _candidate-artifact-a2a-image
  docker buildx prune --all --force --keep-storage=10GB --builder "${BUILDX_BUILDER:?}"
}
integration() {
  # A reused stage proves its tests, not the continued existence of its
  # disposable build outputs. Prepare the inputs needed in this new runner.
  run freshness
  run test-channel-core-process-guard
  run _candidate-oats
  run _candidate-oats-proof-helpers
  run test-tmux-guard
  run test-a2a-gateway-e2e
  run test-channel-integration
  run test-e2e
  run test-federation-e2e
  run cli-e2e
  run e2e-naapp
  run test-npm-exact-publish
  run test-pypi-exact-publish
  run test-oci-exact-publish
}

# Prepare disposable outputs once when their first consumer is reached, even
# if the stage that previously built them was reused from the ledger.
node_ready=0
cli_ready=0
: > "$log_dir/summary.tsv"
for stage in $stages; do
  case "$stage" in checks|unit|artifacts|integration) ;; *) echo "unknown candidate stage: $stage" >&2; exit 2;; esac
  case "$stage" in
    unit|artifacts|integration)
      if [[ "$node_ready" == 0 ]]; then run _candidate-node-deps; node_ready=1; fi ;;
  esac
  case "$stage" in
    artifacts|integration)
      if [[ "$cli_ready" == 0 ]]; then run build; cli_ready=1; fi ;;
  esac
  started=$SECONDS
  set +e
  ( set -e; "$stage" ) 2>&1 | tee "$log_dir/$stage.log"
  status=${PIPESTATUS[0]}
  set -e
  result=PASSED
  [[ "$status" == 0 ]] || result=FAILED
  printf '%s\t%s\t%s.log\t%ss\n' "$stage" "$result" "$stage" "$((SECONDS-started))" >> "$log_dir/summary.tsv"
  [[ "$status" == 0 ]] || exit "$status"
done
printf '\ncandidate suite PASSED\n'
