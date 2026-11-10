#!/usr/bin/env bash
# Source from each maintained journey, including CI's direct script callers.
release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export CANDIDATE_ARTIFACT_DIR="${CANDIDATE_ARTIFACT_DIR:-$release_root/.cache/release-artifacts/$(git -C "$release_root" rev-parse HEAD)}"
python3 "$release_root/scripts/release_artifacts.py" python --root "$release_root" || return
python3 "$release_root/scripts/release_artifacts.py" materialize --root "$release_root" || return
