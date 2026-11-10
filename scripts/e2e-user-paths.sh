#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/prepare-release-wheels.sh"
runtime="${CANDIDATE_GATE_IMAGE:-${USER_PATHS_RUNTIME_IMAGE:?prepare the candidate runtime first}}"
export USER_PATHS_RUNTIME_IMAGE="${AWEB_CANDIDATE_RESOURCE_LABEL:-aweb-user-paths-$$}-wheels"
trap 'docker image rm "$USER_PATHS_RUNTIME_IMAGE" >/dev/null' EXIT
docker build --load --build-arg CANDIDATE_RUNTIME="$runtime" --build-arg CANDIDATE_SOURCE_TREE="$CANDIDATE_SOURCE_TREE" \
  -f "$ROOT/scripts/candidate-wheel-runtime.Dockerfile" \
  -t "$USER_PATHS_RUNTIME_IMAGE" "$CANDIDATE_WHEEL_CONTEXT"
python3 "$ROOT/scripts/e2e/user_paths_stack.py"
