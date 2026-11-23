#!/usr/bin/env bash
# The OSS product proof. The entry point selects missing stages; this script
# runs their existing product targets and writes their real results.
set -euo pipefail

log_dir="${CANDIDATE_LOG_DIR:?CANDIDATE_LOG_DIR is required}"
summary="$log_dir/summary.tsv"

target_result() {
  local target="$1" verdict="$2" elapsed="$3" note="${4:-}"
  printf 'candidate: %s %s%s\n' "$target" "$verdict" "${note:+ ($note)}"
  printf '%s/%s\t%s\t%s\t%ss\t%s\n' \
    "$stage" "$target" "$verdict" "$target_log" "$elapsed" "$note" >> "$summary"
}

run_step() {
  local target="$1" started=$SECONDS status
  shift
  printf '\n=== candidate: %s ===\n' "$target"
  if "$@"; then
    target_result "$target" PASSED "$((SECONDS-started))"
  else
    status=$?
    if [[ "$stage_status" == 0 ]]; then stage_status=$status; fi
    target_result "$target" FAILED "$((SECONDS-started))" "exit $status"
  fi
}

run() {
  # These journeys use the CLI built in this runner. The other integration
  # targets build their own inputs or have no dependency on a stage artifact.
  case "$stage/$1" in
    integration/_candidate-oats|integration/e2e-naapp)
      if grep -Eq '^(artifacts|integration)/build'$'\tFAILED\t' "$summary"; then
        if [[ "$stage_status" == 0 ]]; then stage_status=1; fi
        target_result "$1" SKIPPED 0 "build FAILED"
        return
      fi ;;
  esac
  run_step "$1" make "$1"
}

if [[ "${1:-}" == "--isolated-suites" ]]; then
  export TEST_EGRESS_RUNNER=
  stage=unit
  target_log=test-egress/suite.log
  stage_status=0
  : > "$summary"
  run test-server
  run test-awid
  run test-naapp
  run test-cli
  run _candidate-registry-upgrade
  run test-cli-auth-v2
  run _candidate-unit-channel
  run test-channel-name-live-contract
  run _candidate-unit-channel-core
  run _candidate-unit-pi
  exit "$stage_status"
fi

all_stages="checks user-paths unit artifacts integration"
requested="${1:-$all_stages}"
selected=" "
for stage in $requested; do
  case "$stage" in checks|user-paths|unit|artifacts|integration) ;; *) echo "unknown candidate stage: $stage" >&2; exit 2;; esac
  selected+="$stage "
done

host_published_port() {
  cat "$log_dir/host-published-port.log" || return
  return "${CANDIDATE_HOST_PORT_STATUS:-0}"
}

checks() {
  run check-python-static
  run check-product-table-writes
  run check-secrets-shards
  run_step host-published-port host_published_port
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
  # Keep source controls first, and keep collecting the independent results
  # when one of them finds a defect.
  run test-identity-primitives
  run test-vector-provenance
  run test-sot-source-inventories
  run test-python-locks
  run lint-naapp
  prepare_node
  run _candidate-unit-suites
  if [[ -f "$log_dir/test-egress/summary.tsv" ]]; then
    cat "$log_dir/test-egress/summary.tsv" >> "$summary"
  fi
}
artifacts() {
  prepare_node
  prepare_cli
  run _candidate-artifact-server
  run _candidate-artifact-awid-package
  run _candidate-artifact-awid-image
  run _candidate-artifact-naapp-package
  run _candidate-artifact-channel
  run _candidate-artifact-pi
  run _candidate-artifact-skills
  run _candidate-artifact-a2a-image
  run_step prune-builder prune_builder
}
integration() {
  prepare_node
  prepare_cli
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

prune_builder() {
  if [[ -z "${BUILDX_BUILDER:-}" ]]; then
    echo 'BUILDX_BUILDER is required' >&2
    return 2
  fi
  docker buildx prune --all --force --keep-storage=10GB --builder "$BUILDX_BUILDER"
}

prepare_node() {
  if ! grep -Eq '^(unit|artifacts|integration)/_candidate-node-deps'$'\t' "$summary"; then
    run _candidate-node-deps
  fi
}

prepare_cli() {
  # A reused artifact stage has no files in this runner.
  if ! grep -Eq '^(artifacts|integration)/build'$'\t' "$summary"; then
    run build
  fi
}

suite_status=0
: > "$summary"
for stage in $all_stages; do
  [[ "$selected" == *" $stage "* ]] || continue
  started=$SECONDS
  target_log="$stage.log"
  set +e
  ( set -e; stage_status=0; "$stage"; exit "$stage_status" ) 2>&1 | tee "$log_dir/$stage.log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  status=${statuses[0]}
  if [[ "${statuses[1]}" != 0 ]]; then status=${statuses[1]}; fi
  if [[ "$status" == 0 ]]; then
    result=PASSED
  else
    result=FAILED
    if [[ "$suite_status" == 0 ]]; then suite_status=$status; fi
  fi
  coverage=""
  if [[ "$stage" == user-paths && -f "$log_dir/user-paths/coverage-summary.txt" ]]; then
    coverage="$(cat "$log_dir/user-paths/coverage-summary.txt")"
    printf 'user-paths coverage: %s\n' "$coverage"
  fi
  printf '%s\t%s\t%s.log\t%ss\t%s\n' "$stage" "$result" "$stage" "$((SECONDS-started))" "$coverage" >> "$summary"
done
if [[ "$suite_status" == 0 ]]; then
  printf '\ncandidate suite PASSED\n'
else
  printf '\ncandidate suite FAILED\n'
fi
exit "$suite_status"
