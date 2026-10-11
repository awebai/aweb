#!/usr/bin/env bash
# The aw wake broker embeds cli/go/wake/channel_core_runner_bundle.mjs
# (go:embed), a build of channel-core. Fail when it differs from a fresh build
# of the current entry and channel-core source.
#   (no args)    check the committed bundle
#   --write      rebuild the committed bundle
#   --self-test  a clean build passes; a channel-core source change made after
#                the bundle was built is refused
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# esbuild path comments are relative to the working directory.
cd "$ROOT"
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
TSC="$ROOT/channel-core/node_modules/.bin/tsc"
if [[ ! -x "$TSC" ]]; then
  echo "missing pinned tsc at channel-core/node_modules/.bin/tsc" >&2
  exit 1
fi
STALE_MESSAGE="channel-core wake runner bundle is stale; rebuild with scripts/check-wake-channel-core-bundle.sh --write after editing entry/core"

build_bundle() {
  local out="$1"
  "$ESBUILD" cli/go/wake/channel_core_runner_entry.ts \
    --bundle --platform=node --format=esm --log-level=warning \
    --banner:js="import { createRequire as __awebCreateRequire } from 'node:module'; const require = __awebCreateRequire(import.meta.url);" \
    --outfile="$out" >/dev/null
}

check_bundle() {
  local committed="$1" fresh
  fresh="$(mktemp)"
  build_bundle "$fresh"
  if ! diff -u "$committed" "$fresh"; then
    rm -f "$fresh"
    echo "$STALE_MESSAGE" >&2
    return 1
  fi
  rm -f "$fresh"
}

self_test() {
  local tmp out status
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/aweb-wake-bundle.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/cli/go/wake" "$tmp/channel-core" "$tmp/channel/node_modules"
  cp "$ROOT/cli/go/wake/channel_core_runner_entry.ts" "$ROOT/cli/go/wake/oats_command.ts" "$tmp/cli/go/wake/"
  cp -R "$ROOT/channel-core/src" "$tmp/channel-core/src"
  ln -s "$ROOT/channel-core/node_modules" "$tmp/channel-core/node_modules"
  ln -s "$ROOT/channel/node_modules/.bin" "$tmp/channel/node_modules/.bin"
  (cd "$tmp" && ESBUILD="$ESBUILD" bash -c "$(declare -f build_bundle); build_bundle cli/go/wake/channel_core_runner_bundle.mjs")
  if ! out="$(cd "$tmp" && ESBUILD="$ESBUILD" STALE_MESSAGE="$STALE_MESSAGE" bash -c "$(declare -f build_bundle check_bundle); check_bundle cli/go/wake/channel_core_runner_bundle.mjs" 2>&1)"; then
    printf 'SELF-TEST FAIL: a freshly built bundle was refused:\n%s\n' "$out" >&2
    return 1
  fi
  # The source moves on after the bundle was built, as a7764e257 did.
  sed -i.bak 's/until you verify the sender\./until you verify the sender. wake-bundle-freshness-probe/' "$tmp/channel-core/src/channel.ts"
  rm -f "$tmp/channel-core/src/channel.ts.bak"
  if ! grep -Fq "wake-bundle-freshness-probe" "$tmp/channel-core/src/channel.ts"; then
    echo "SELF-TEST INCONCLUSIVE: the probe source change was not applied" >&2
    return 1
  fi
  set +e
  out="$(cd "$tmp" && ESBUILD="$ESBUILD" STALE_MESSAGE="$STALE_MESSAGE" bash -c "$(declare -f build_bundle check_bundle); check_bundle cli/go/wake/channel_core_runner_bundle.mjs" 2>&1)"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "SELF-TEST FAIL: a bundle older than its channel-core source was accepted" >&2
    return 1
  fi
  if ! grep -Fq "$STALE_MESSAGE" <<<"$out" || ! grep -Fq "wake-bundle-freshness-probe" <<<"$out"; then
    printf 'SELF-TEST INCONCLUSIVE: the stale bundle failed without naming the source change:\n%s\n' "$out" >&2
    return 1
  fi
  echo "self-test passed: a fresh wake bundle passes and a bundle older than its channel-core source fails"
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  --write)
    "$TSC" --noEmit --strict --skipLibCheck --moduleResolution bundler --module ESNext --target ESNext --lib ESNext --types node --typeRoots "$ROOT/channel-core/node_modules/@types" cli/go/wake/channel_core_runner_entry.ts
    build_bundle cli/go/wake/channel_core_runner_bundle.mjs
    ;;
  "")
    "$TSC" --noEmit --strict --skipLibCheck --moduleResolution bundler --module ESNext --target ESNext --lib ESNext --types node --typeRoots "$ROOT/channel-core/node_modules/@types" cli/go/wake/channel_core_runner_entry.ts
    check_bundle cli/go/wake/channel_core_runner_bundle.mjs
    ;;
  *)
    echo "usage: $0 [--write|--self-test]" >&2
    exit 2
    ;;
esac
