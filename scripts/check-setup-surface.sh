#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

scripts/regenerate-cli-reference.sh --check
scripts/check-resource-packs.sh

(
  cd cli/go
  go test ./cmd/aw -run 'TestAwTopLevelHelpGroupsCommandsByArchitecture|TestAgentsCommandSurfaceKeepsLegacyAgentsAlongsideHumanTeamVerbs|TestTeamBootstrapInRepoMissingSourceFailsBeforeMutation|TestAgentsProvisionMissingSourceFailsBeforeMutation|TestTeamBootstrapHostedNonInteractiveFailureRollsBackAgentsLayout|TestTeamBootstrapRollbackPreservesAgentsLayoutWithIdentityState|TestAwRolesAdd|TestAwRolesShowAcceptsPositionalRoleName'
)

echo "setup surface checks passed"
