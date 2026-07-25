#!/usr/bin/env bash
# Prove the dist gates against source-level regressions, not pre-existing dist
# files: dist is untracked and every package build regenerates it. Clean source
# must build and pass; removing each adapter's guarded source behavior must
# rebuild successfully and then fail the production package checker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aweb-dist-freshness.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/channel-core" "$TMP/channel" "$TMP/pi-extension"
cp -R "$ROOT/channel-core/src" "$TMP/channel-core/src"
cp -R "$ROOT/channel/src" "$TMP/channel/src"
cp -R "$ROOT/pi-extension/src" "$TMP/pi-extension/src"

build_channel() {
  mkdir -p "$TMP/channel/dist"
  NODE_PATH="$ROOT/channel/node_modules:$ROOT/channel-core/node_modules" \
    "$ROOT/channel/node_modules/.bin/esbuild" "$TMP/channel/src/index.ts" \
      --bundle --platform=node --format=esm \
      --outfile="$TMP/channel/dist/index.js" \
      --alias:@awebai/channel-core="$TMP/channel-core/src/index.ts" \
      >/dev/null
}

build_pi_extension() {
  mkdir -p "$TMP/pi-extension/dist"
  NODE_PATH="$ROOT/pi-extension/node_modules:$ROOT/channel-core/node_modules" \
    "$ROOT/pi-extension/node_modules/.bin/esbuild" "$TMP/pi-extension/src/index.ts" \
      --bundle --platform=node --format=esm --external:@awebai/aw \
      --outfile="$TMP/pi-extension/dist/index.js" \
      --alias:@awebai/channel-core="$TMP/channel-core/src/index.ts" \
      >/dev/null
}

expect_checker_failure() {
  local label="$1" expected="$2"
  shift 2
  local out status
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: $label source regression was accepted" >&2
    return 1
  fi
  if ! grep -Fq "$expected" <<<"$out"; then
    printf 'SELF-TEST INCONCLUSIVE: %s failed without naming %s:\n%s\n' \
      "$label" "$expected" "$out" >&2
    return 1
  fi
}

# Positive direction: both adapters built from the clean copied source pass the
# same checkers used by package builds and the freshness gate.
build_channel
node "$ROOT/channel/scripts/check-package-dist.mjs" \
  --dist "$TMP/channel/dist/index.js" >/dev/null
build_pi_extension
node "$ROOT/pi-extension/scripts/check-package-dist.mjs" \
  --dist "$TMP/pi-extension/dist/index.js" >/dev/null

# Negative direction, channel: remove the real genesis-to-did:aw binding check,
# rebuild, and require the checker to identify the missing fix-specific marker.
python3 - "$TMP/channel-core/src/identity/registry.ts" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
guard = '''    if (computeStableID(genesisPub) !== resolution.did_aw) {
      return { outcome: "HARD_ERROR", error: "did:aw not derived from genesis key" };
    }
'''
if text.count(guard) != 1:
    raise SystemExit(f"expected one genesis identity-binding guard, found {text.count(guard)}")
path.write_text(text.replace(guard, ""), encoding="utf-8")
PY
build_channel
expect_checker_failure "channel genesis binding" "did:aw not derived from genesis key" \
  node "$ROOT/channel/scripts/check-package-dist.mjs" \
    --dist "$TMP/channel/dist/index.js"

# Restore the isolated core source, then seed the prior identity-first ordering
# for Pi and require its checker to reject the rebuilt bundle.
rm -rf "$TMP/channel-core/src"
cp -R "$ROOT/channel-core/src" "$TMP/channel-core/src"
python3 - "$TMP/channel-core/src/config.ts" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
current = "  const stableID = certificateStableID || identityStableID;"
stale = "  const stableID = identityStableID || certificateStableID;"
if text.count(current) != 1:
    raise SystemExit(f"expected one certificate-first stable ID assignment, found {text.count(current)}")
path.write_text(text.replace(current, stale), encoding="utf-8")
PY
build_pi_extension
expect_checker_failure "pi-extension certificate-first resolution" \
  "missing certificate-first stable_id resolution" \
  node "$ROOT/pi-extension/scripts/check-package-dist.mjs" \
    --dist "$TMP/pi-extension/dist/index.js"

echo "self-test passed: clean TypeScript builds pass and source-level security reverts fail"
