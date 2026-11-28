#!/usr/bin/env bash
# Make the aw distribution checkout hold the tagged CLI source: every top-level
# entry except the checkout's own .git and .github is removed, then the source
# tree, its .github included, is copied over it.
#
#   sync-aw-distribution.sh <cli/go source> <distribution checkout>
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <source> <distribution>" >&2; exit 2; }
source="$1"
external="$2"
[[ -d "$source" && -d "$external/.git" ]] \
  || { echo "sync-aw-distribution: $source must be a directory and $external a git checkout" >&2; exit 2; }

find "$external" -mindepth 1 -maxdepth 1 ! -name .git ! -name .github -exec rm -rf {} +
cp -a "$source/." "$external/"
