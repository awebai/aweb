#!/usr/bin/env bash
# The team deployment journey's launch adapter for one machine, over the
# operator's own command (deploy/team/teamctl).
#
#   TEAM_DEPLOYMENT_PROJECT=<compose project> TEAM_DEPLOYMENT_RUN_DIR=<dir> \
#     scripts/e2e-team-deployment.sh compose <up|connect|down> <deployment.yaml>
#
# up       teamctl start.
# connect  teamctl connect.
# down     the lab's cleanup, never an operator's: removes every container,
#          network and volume of the project, the test world's included, and
#          checks that none is left. The deployment's data is gone with it.
#
# TEAM_DEPLOYMENT_COMPOSE_FILES names the journey's further Compose files,
# separated by colons (its test registry, DNS and mail).
set -euo pipefail

TEAMCTL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/team/teamctl"

usage() {
  echo "usage: TEAM_DEPLOYMENT_PROJECT=<name> TEAM_DEPLOYMENT_RUN_DIR=<dir> $0 compose <up|connect|down> <deployment.yaml>" >&2
  exit 2
}

[[ $# -eq 3 && "$1" == compose ]] || usage
[[ -n "${TEAM_DEPLOYMENT_PROJECT:-}" && -n "${TEAM_DEPLOYMENT_RUN_DIR:-}" ]] || usage
project="$TEAM_DEPLOYMENT_PROJECT"
case "$2" in
  up) exec "$TEAMCTL" start "$3" ;;
  connect) exec "$TEAMCTL" connect "$3" ;;
  down) ;;
  *) usage ;;
esac

compose=()
while IFS= read -r argument; do compose+=("$argument"); done < <(
  "$TEAMCTL" connect "$3" | python3 -c 'import json, sys; print("\n".join(json.load(sys.stdin)["compose"]))'
)
# Every profile: a service whose profile is off at down (the journey's aw
# machines) is still the project's.
"${compose[@]}" --profile '*' down --volumes --remove-orphans
left=0
for kind in container network volume; do
  if [[ "$kind" == container ]]; then
    ids="$(docker container ls -aq --filter "label=com.docker.compose.project=$project")"
  else
    ids="$(docker "$kind" ls -q --filter "label=com.docker.compose.project=$project")"
  fi
  if [[ -n "$ids" ]]; then
    echo "e2e-team-deployment: $kind left after down: $ids" >&2
    left=1
  fi
done
exit "$left"
