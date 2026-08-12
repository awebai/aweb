#!/usr/bin/env bash
# Wait for the release-branch publication workflow covering one artifact.
# The publication workflows trigger on the aweb release-branch push that
# continue performs, so continue's per-artifact duty is monitoring, not
# dispatch: find the run of this artifact's workflow at the release SHA and
# fail if that run fails. Arguments: <artifact> <version>, or
# --print-workflow <artifact> to emit the mapped workflow file and exit.
set -euo pipefail

print_only=""
if [[ "${1:-}" == "--print-workflow" ]]; then
  print_only=1
  shift
fi
artifact="${1:?artifact name required}"

case "$artifact" in
  aw-cli)                             workflow="aw-release.yml" ;;
  a2a-gateway-image)                  workflow="a2a-gateway-release.yml" ;;
  aweb-server|awid-service)           workflow="pypi-release.yml" ;;
  awid-image)                         workflow="awid-image-release.yml" ;;
  channel-plugin|pi-extension|skills) workflow="npm-release.yml" ;;
  *) echo "no publication workflow is mapped for artifact '$artifact'" >&2; exit 2 ;;
esac

if [[ -n "$print_only" ]]; then
  echo "$workflow"
  exit 0
fi

version="${2:?version required}"
git fetch origin release >&2
sha="$(git rev-parse refs/remotes/origin/release)"
deadline=$(( SECONDS + 900 ))
run_id=""
while :; do
  run_id="$(gh run list --workflow "$workflow" --commit "$sha" --limit 1 \
    --json databaseId --jq '.[0].databaseId // empty')"
  [[ -n "$run_id" ]] && break
  if (( SECONDS >= deadline )); then
    echo "no $workflow run appeared for $sha within 15 minutes" >&2
    exit 1
  fi
  sleep 15
done
echo "watching $workflow run $run_id for $artifact $version at $sha" >&2
exec gh run watch "$run_id" --exit-status >&2
