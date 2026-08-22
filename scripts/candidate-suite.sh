#!/usr/bin/env bash
# The complete OSS product proof. Keep this as an explicit list: a candidate
# always runs every target, and the first failing target makes the suite red.
set -euo pipefail

run() {
  printf '\n=== candidate: %s ===\n' "$1"
  make "$1"
}

run _candidate-gate-docker-boundaries
run test-shipping
run check-aw-commit-repo-stamp
run check-cli-go-tidy
run check-cli-release-vcs-stamps
run test-python-locks
run test-sot-source-inventories
run test-vector-provenance
run test-federation-error-reference
run test-federation-authority-mutations
run test-federation-harness
run test-cli-reference
run test-mcp-tools-reference
run _candidate-channel-version
run _candidate-node-deps
run test-server
run test-awid
run test-cli
run _candidate-unit-channel
run test-channel-name-live-contract
run _candidate-unit-channel-core
run _candidate-unit-pi
run check-a2a-copy-guardrails
run test-go-vulnerability-audit
run test-release-cli-version
run build
run _candidate-artifact-server
run _candidate-artifact-awid-package
run _candidate-artifact-awid-image
run _candidate-artifact-channel
run _candidate-artifact-pi
run _candidate-artifact-skills
run _candidate-artifact-a2a-image

: "${BUILDX_BUILDER:?BUILDX_BUILDER is required}"
: "${BUILDX_CONFIG:?BUILDX_CONFIG is required}"
docker buildx prune --all --force --keep-storage=10GB --builder "$BUILDX_BUILDER"

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
run test-npm-exact-publish
run test-pypi-exact-publish
run test-oci-exact-publish

printf '\ncandidate suite PASSED\n'
