#!/usr/bin/env bash
set -euo pipefail

# Release-model guard (default-aaed): server/ changes since the last
# server-v* release tag require a strictly greater version in
# server/pyproject.toml. The hosted image builds the server from source,
# so an unbumped server change would ship under the previous published
# version label (this happened at m3.2: 11339ba4 shipped as "1.26.21").
#
# Compares the last reachable server-v* tag against the working tree, so
# it holds both in CI (clean checkout) and in `make release-server-check`,
# where the bump may not be committed yet.

cd "$(git rev-parse --show-toplevel)"

if [ ! -f server/pyproject.toml ]; then
  echo "ERROR: server/pyproject.toml not found; run from the aweb repo." >&2
  exit 1
fi

pyproject_version() { sed -n 's/^version = "\(.*\)"/\1/p' | head -n 1; }

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
CURRENT_VERSION="$(pyproject_version < server/pyproject.toml)"

if [ -z "$TAG_VERSION" ] || [ -z "$CURRENT_VERSION" ]; then
  echo "ERROR: could not read a version from server/pyproject.toml (tag: '$TAG_VERSION', current: '$CURRENT_VERSION')." >&2
  exit 1
fi

if [ "$CURRENT_VERSION" = "$TAG_VERSION" ]; then
  echo "ERROR: server/ changed since $BASE_TAG but server/pyproject.toml still says $TAG_VERSION." >&2
  echo "Changed files:" >&2
  echo "$CHANGED" | sed 's/^/  /' | head -20 >&2
  echo "Bump the version in server/pyproject.toml (and run 'uv lock' in server/) so the next release tag covers these changes." >&2
  exit 1
fi

HIGHEST="$(printf '%s\n%s\n' "$TAG_VERSION" "$CURRENT_VERSION" | sort -V | tail -n 1)"
if [ "$HIGHEST" != "$CURRENT_VERSION" ]; then
  echo "ERROR: server/pyproject.toml version $CURRENT_VERSION is lower than the last release tag $BASE_TAG ($TAG_VERSION)." >&2
  exit 1
fi

echo "OK: server/ changed since $BASE_TAG and version bumped $TAG_VERSION -> $CURRENT_VERSION."
