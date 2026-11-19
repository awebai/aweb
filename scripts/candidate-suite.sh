#!/usr/bin/env bash
# The OSS product proof. The entry point selects missing stages; this script
# runs their existing product targets and writes their real results.
set -euo pipefail

run() { printf '\n=== candidate: %s ===\n' "$1"; make "$1"; }
if [[ "${1:-}" == "--isolated-suites" ]]; then
  export TEST_EGRESS_RUNNER=
  run test-server
  run test-awid
  run test-key-holder
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
stage_owner="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vm-gate/vm_gate/aweb_stages.py"
stages="$(python3 "$stage_owner" "${1:-all}")" || exit 2
checks() {
  cat "$log_dir/host-published-port.log"
  run check-generated-copies
  run test-generated-copies
  run check-private-boundary
  run _candidate-gate-docker-boundaries
  run _candidate-gate-compose-adoption
  run test-shipping
  run check-page-renderer-bundle
  run check-aw-commit-repo-stamp
  run check-cli-go-tidy
  run check-cli-release-vcs-stamps
  run test-python-locks
  run lint-naapp
  run test-sot-source-inventories
  run test-identity-primitives
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
user-paths() {
  run e2e-user-paths
}
unit() {
  # These source checks belong to every unit proof, including unit-only runs.
  # Refuse before node preparation or the expensive isolated product suites.
  run test-identity-primitives
  run test-vector-provenance
  run test-sot-source-inventories
  run test-python-locks
  run lint-naapp
  if [[ "$node_ready" == 0 ]]; then run _candidate-node-deps; fi
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
  run e2e-folio-wakes
  run test-npm-exact-publish
  run test-pypi-exact-publish
  run test-oci-exact-publish
}

# Prepare disposable outputs when a consumer is reached, including reused stages.
node_ready=0
cli_ready=0
prepare_stage() {
  case "$1" in
    artifacts|integration)
      if [[ "$node_ready" == 0 ]]; then run _candidate-node-deps; fi
      if [[ "$cli_ready" == 0 ]]; then run build; fi ;;
  esac
}
source "$(dirname "$stage_owner")/../../candidate-stage-lanes.sh"
batches="$(python3 "$stage_owner" --batches "$stages")"
: > "$log_dir/summary.tsv"
# The parent alone writes the canonical summary, including both parallel results.
trap collect_stage_results EXIT
while IFS= read -r batch; do
  if [[ "$batch" == 'unit integration' ]]; then
    run_parallel_stages
  else
    run_stage "$batch"
    case "$batch" in
      unit) node_ready=1 ;;
      artifacts) node_ready=1; cli_ready=1 ;;
    esac
  fi
  collect_stage_results
done <<< "$batches"
printf '\ncandidate suite PASSED\n'
