#!/usr/bin/env bash
# Source from each maintained journey, including CI's direct script callers.
# Callers with an existing EXIT handler call this after their service teardown;
# otherwise preparation installs its own handler. Keep ownership separate from
# CANDIDATE_WHEEL_CONTEXT, which a caller may copy into its own temporary root.
cleanup_release_wheels() {
  local context result=0
  for context in "${_release_wheel_contexts[@]:-}"; do
    [[ -z "$context" ]] || rm -rf -- "$context" || result=1
  done
  _release_wheel_contexts=()
  return "$result"
}
if [[ -z "$(trap -p EXIT)" ]]; then
  trap 'status=$?; cleanup_release_wheels || status=1; exit "$status"' EXIT
fi
release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export CANDIDATE_ARTIFACT_DIR="${CANDIDATE_ARTIFACT_DIR:-$release_root/.cache/release-artifacts/$(git -C "$release_root" rev-parse HEAD)}"
python3 "$release_root/scripts/release_artifacts.py" python --root "$release_root" || return
python3 "$release_root/scripts/release_artifacts.py" verify --root "$release_root" || return
CANDIDATE_WHEEL_CONTEXT="$(python3 "$release_root/scripts/release_artifacts.py" materialize --root "$release_root")" || return
_release_wheel_contexts+=("$CANDIDATE_WHEEL_CONTEXT")
export CANDIDATE_WHEEL_CONTEXT CANDIDATE_WHEEL_MODE=1
export CANDIDATE_SOURCE_TREE="$(git -C "$release_root" rev-parse 'HEAD^{tree}')"
