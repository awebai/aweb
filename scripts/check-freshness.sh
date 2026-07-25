#!/usr/bin/env bash
# Deterministic freshness gate (default-aajc.5): regenerate every intentionally
# committed generated artifact and fail if it drifts from its source. Routine
# CI runs this so drift is caught mechanically instead of by reviewer
# inspection. It never touches state outside the repository (isolated uv cache)
# and needs no production credentials.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/pycache}"

status=0
section() { printf '\n=== %s ===\n' "$1"; }

# 1. Python locks: an AWID version bump (or any dependency change) that the
#    editable server/awid lock records must be reflected in the committed lock.
section "python locks (awid, server)"
(cd awid && uv lock) && (cd server && uv lock)
if git diff --quiet -- awid/uv.lock server/uv.lock; then
  echo "locks are up to date"
else
  echo "FAIL: uv.lock drift — run 'cd awid && uv lock' and 'cd server && uv lock', then commit"
  git --no-pager diff --stat -- awid/uv.lock server/uv.lock
  status=1
fi

# 2. CLI command reference, resource packs, and the reserved-app-ids artifact
#    (regenerated + diffed against live cobra by check-setup-surface.sh).
section "cli reference, resource packs, reserved app ids"
if scripts/check-setup-surface.sh; then
  echo "setup surface is up to date"
else
  echo "FAIL: setup-surface artifact drift (cli reference / resource packs / reserved app ids)"
  status=1
fi

# 3. channel-core is a file: dependency of the claude-channel plugin and the pi
#    extension; both rebuild it from source and the plugin bundle is gated by
#    scripts/check-package-dist.mjs (default-aaju). Verify a clean plugin build
#    still carries the security surface (the bundle reflects current src).
section "claude-channel bundle freshness (aaju gate)"
if (cd channel && npm run --silent build >/dev/null 2>&1 && node scripts/check-package-dist.mjs); then
  echo "channel bundle is up to date"
else
  echo "FAIL: claude-channel bundle stale or missing the security surface (see scripts/check-package-dist.mjs)"
  status=1
fi

# 4. pi-extension/dist is likewise untracked (default-aajc.5) and rebuilt from
#    src by prebuild/ensure-channel-core; verify a clean build produces a valid
#    bundle so the published pi package can never carry stale channel-core.
section "pi-extension bundle freshness"
if (cd pi-extension && node scripts/ensure-channel-core.mjs >/dev/null 2>&1 && npm run --silent build >/dev/null 2>&1 && node scripts/check-package-dist.mjs); then
  echo "pi-extension bundle is up to date"
else
  echo "FAIL: pi-extension bundle failed to build/validate from source"
  status=1
fi

if [ "$status" -eq 0 ]; then
  printf '\nAll freshness checks passed.\n'
else
  printf '\nFreshness checks FAILED.\n'
fi
exit "$status"
