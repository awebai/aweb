#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ESBUILD="$ROOT/channel/node_modules/.bin/esbuild"
if [[ ! -x "$ESBUILD" ]]; then
  echo "missing pinned esbuild at channel/node_modules/.bin/esbuild" >&2
  exit 1
fi
version="$($ESBUILD --version)"
if [[ "$version" != "0.27.5" ]]; then
  echo "unexpected esbuild version $version (want 0.27.5)" >&2
  exit 1
fi
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
"$ESBUILD" "$ROOT/cli/go/wake/channel_core_runner_entry.ts" \
  --bundle --platform=node --format=esm \
  --banner:js="import { createRequire as __awebCreateRequire } from 'node:module'; const require = __awebCreateRequire(import.meta.url);" \
  --outfile="$tmp" >/dev/null
if ! diff -u "$ROOT/cli/go/wake/channel_core_runner_bundle.mjs" "$tmp"; then
  echo "channel-core wake runner bundle is stale; rebuild with scripts/check-wake-channel-core-bundle.sh after editing entry/core" >&2
  exit 1
fi
