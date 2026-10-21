#!/usr/bin/env bash
# E2E must exercise the checkout's build, including when a released aw is installed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
selected="$(command -v aw || true)"
if [[ -z "$selected" || ! "$selected" -ef "$ROOT/cli/go/aw" ]]; then
  echo 'naapp e2e requires this checkout’s cli/go/aw on PATH; run make build' >&2
  exit 1
fi
AW_NO_UPDATE_CHECK=1 aw version
