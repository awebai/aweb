#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 next | check <proposed-version>" >&2
  exit 2
}

cd "$(git rev-parse --show-toplevel)"

REMOTE="${CLI_RELEASE_REMOTE:-origin}"

published_versions() {
  local refs
  if ! refs="$(git ls-remote --tags --refs "$REMOTE" 'refs/tags/aw-v*')"; then
    echo "ERROR: could not read published CLI tags from remote '$REMOTE'." >&2
    exit 1
  fi
  printf '%s\n' "$refs" \
    | awk '{ sub("refs/tags/aw-v", "", $2); if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $2 }'
}

latest_published_version() {
  local latest
  latest="$(published_versions | sort -V | tail -n 1)"
  if [ -z "$latest" ]; then
    echo "ERROR: no stable aw-vX.Y.Z tags found on remote '$REMOTE'; fetch/publish CLI tag history before releasing." >&2
    exit 1
  fi
  printf '%s\n' "$latest"
}

require_stable_version() {
  local label="$1" version="$2"
  if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "ERROR: $label '$version' is not a stable X.Y.Z CLI version." >&2
    exit 1
  fi
}

version_is_greater() {
  local candidate="$1" floor="$2"
  local candidate_major candidate_minor candidate_patch
  local floor_major floor_minor floor_patch
  IFS=. read -r candidate_major candidate_minor candidate_patch <<<"$candidate"
  IFS=. read -r floor_major floor_minor floor_patch <<<"$floor"
  (( candidate_major > floor_major )) \
    || (( candidate_major == floor_major && candidate_minor > floor_minor )) \
    || (( candidate_major == floor_major && candidate_minor == floor_minor && candidate_patch > floor_patch ))
}

command="${1:-}"
case "$command" in
  next)
    [ "$#" -eq 1 ] || usage
    latest="$(latest_published_version)"
    require_stable_version "latest published CLI version" "$latest"
    IFS=. read -r major minor patch <<<"$latest"
    printf '%s.%s.%s\n' "$major" "$minor" "$((10#$patch + 1))"
    ;;
  check)
    [ "$#" -eq 2 ] || usage
    proposed="$2"
    latest="$(latest_published_version)"
    require_stable_version "proposed CLI version" "$proposed"
    require_stable_version "latest published CLI version" "$latest"
    if ! version_is_greater "$proposed" "$latest"; then
      echo "ERROR: proposed CLI version $proposed is not strictly greater than latest published CLI version $latest." >&2
      exit 1
    fi
    echo "OK: proposed CLI version $proposed is greater than latest published CLI version $latest."
    ;;
  *)
    usage
    ;;
esac
