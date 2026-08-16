#!/usr/bin/env bash
set -euo pipefail

# Release-model guard (default-aaed): server/ changes require a strictly
# greater version in server/pyproject.toml. The hosted image builds the
# server from source, so an unbumped server change would ship under the
# previous published version label (this happened at m3.2: 11339ba4
# shipped as "1.26.21").
#
# Two comparisons, each honest for its context:
#  - Release-tag floor (always): if server/ differs from the last
#    reachable server-v* tag, the current version must exceed the tag's.
#    Compares against the working tree so the change-time guard holds
#    before the bump is committed.
#  - Change range (when a base ref is passed, as CI does): if server/
#    differs between the base and the current tree, the current version
#    must exceed the base's. The floor alone would let a later change
#    inherit an earlier unreleased bump.
#
# Usage: check-server-version-bump.sh [BASE_REF]

cd "$(git rev-parse --show-toplevel)"

if [ ! -f server/pyproject.toml ]; then
  echo "ERROR: server/pyproject.toml not found; run from the aweb repo." >&2
  exit 1
fi

pyproject_version() { sed -n 's/^version = "\(.*\)"/\1/p' | head -n 1; }

require_greater() {
  local from_label="$1" from_version="$2" current_version="$3" changed="$4"
  if [ -z "$from_version" ] || [ -z "$current_version" ]; then
    echo "ERROR: could not read a version from server/pyproject.toml ($from_label: '$from_version', current: '$current_version')." >&2
    exit 1
  fi
  if [ "$current_version" = "$from_version" ]; then
    echo "ERROR: server/ changed since $from_label but server/pyproject.toml still says $from_version." >&2
    echo "Changed files:" >&2
    echo "$changed" | sed 's/^/  /' | head -20 >&2
    echo "Bump the version in server/pyproject.toml (and run 'uv lock' in server/) so the next release tag covers these changes." >&2
    exit 1
  fi
  local highest
  highest="$(printf '%s\n%s\n' "$from_version" "$current_version" | sort -V | tail -n 1)"
  if [ "$highest" != "$current_version" ]; then
    echo "ERROR: server/pyproject.toml version $current_version is lower than $from_label ($from_version)." >&2
    exit 1
  fi
}

CURRENT_VERSION="$(pyproject_version < server/pyproject.toml)"

# -- Change-range check (CI): base ref vs current tree --
BASE_REF="${1:-}"
if [ -n "$BASE_REF" ]; then
  if git rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
    RANGE_CHANGED="$(git diff --name-only "$BASE_REF" -- server/)"
    if [ -n "$RANGE_CHANGED" ]; then
      BASE_VERSION="$(git show "$BASE_REF:server/pyproject.toml" | pyproject_version)"
      require_greater "change base $BASE_REF" "$BASE_VERSION" "$CURRENT_VERSION" "$RANGE_CHANGED"
      echo "OK: server/ changed since change base $BASE_REF and version bumped $BASE_VERSION -> $CURRENT_VERSION."
    else
      echo "OK: server/ unchanged since change base $BASE_REF."
    fi
  else
    echo "WARNING: change base '$BASE_REF' is not a commit here; skipping the range check (tag floor still applies)." >&2
  fi
fi

# -- Release-tag floor (always) --
BASE_TAG="$(git describe --tags --match 'server-v*' --abbrev=0 HEAD 2>/dev/null || true)"
if [ -z "$BASE_TAG" ]; then
  echo "ERROR: no server-v* tag reachable from HEAD." >&2
  echo "If this is CI, fetch the full history and tags (fetch-depth: 0)." >&2
  exit 1
fi

CHANGED="$(git diff --name-only "$BASE_TAG" -- server/)"
if [ -z "$CHANGED" ]; then
  echo "OK: server/ unchanged since $BASE_TAG."
  exit 0
fi

TAG_VERSION="$(git show "$BASE_TAG:server/pyproject.toml" | pyproject_version)"
require_greater "$BASE_TAG" "$TAG_VERSION" "$CURRENT_VERSION" "$CHANGED"

echo "OK: server/ changed since $BASE_TAG and version bumped $TAG_VERSION -> $CURRENT_VERSION."
