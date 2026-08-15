#!/usr/bin/env bash
# Run the complete clean-Docker gate for the exact aweb commit being released.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"
RELEASE_SOURCE_SHA="$SOURCE_SHA" "$ROOT/scripts/release-local-gate.sh"
