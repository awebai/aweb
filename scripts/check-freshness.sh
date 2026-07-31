#!/usr/bin/env bash
# Freshness gate (default-aajc.5, scope corrected in default-aajc.16).
#
# WHAT THIS CHECKS, stated precisely because the previous wording claimed more
# than it validated:
#   1. Intentionally committed GENERATED artifacts are regenerated and must not
#      drift from their source (uv locks, CLI and MCP references, resource packs,
#      reserved app ids, the claude-channel and pi bundles).
#   2. Public AWID site document mirrors exactly match their canonical docs.
#   3. Repository paths REFERENCED IN DOCUMENTATION exist (check-doc-paths.sh).
#   4. Every lock/reference/dist/mirror check passes a clean fixture and rejects
#      the stale artifact it claims to detect (test-freshness-negative-fixtures.sh).
#
# WHAT IT CANNOT CHECK, and therefore what still requires human review: whether
# documentation PROSE is true. A path can resolve while the sentence around it
# is wrong; a :LINE anchor can point at unrelated code; a hand-written inventory
# (test counts, ownership tables) can be stale while every link works. This gate
# reduces the manual surface, it does not eliminate it — see the freshness
# section of docs/contributing.md.
#
# It never touches state outside the repository (isolated uv cache) and needs no
# production credentials.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/pycache}"

status=0
section() { printf '\n=== %s ===\n' "$1"; }

# 1. Python locks: an AWID version bump (or any dependency change) that the
#    editable server/awid lock records must be reflected in the committed lock.
#    --check is deliberately non-mutating: a verification gate must not repair
#    the evidence before reporting it, and a clean run must leave git clean.
section "python locks (awid, server)"
if scripts/check-python-locks.sh; then
  echo "locks are up to date"
else
  echo "FAIL: uv.lock drift — run 'cd awid && uv lock' and 'cd server && uv lock', then commit"
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

# 3. The public MCP inventory is generated from the real offline FastMCP
#    registration. Its focused suite also proves that registration additions
#    and removals fail until the explicit public grouping is reconciled.
section "MCP tools reference"
if make --no-print-directory test-mcp-tools-reference; then
  echo "MCP tools reference matches live OSS registration"
else
  echo "FAIL: MCP tools reference drift or incomplete registration coverage"
  status=1
fi

# 4. channel-core is a file: dependency of the claude-channel plugin and the pi
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

# 5. pi-extension/dist is likewise untracked (default-aajc.5) and rebuilt from
#    src by prebuild/ensure-channel-core; verify a clean build produces a valid
#    bundle so the published pi package can never carry stale channel-core.
section "pi-extension bundle freshness"
if (cd pi-extension && node scripts/ensure-channel-core.mjs >/dev/null 2>&1 && npm run --silent build >/dev/null 2>&1 && node scripts/check-package-dist.mjs); then
  echo "pi-extension bundle is up to date"
else
  echo "FAIL: pi-extension bundle failed to build/validate from source"
  status=1
fi

# 6. Public docs served by the AWID site are tracked mirrors of their canonical
#    docs. This is a comparison gate, not a release-time repair step.
section "AWID public site document mirrors"
if make --no-print-directory check-awid-site-docs; then
  echo "public AWID site documents match their canonical sources"
else
  echo "FAIL: public AWID site document drift — sync the configured mirrors and commit them"
  status=1
fi

# 7. Negative controls for the other generated-artifact and mirror checks above.
#    The MCP inventory's negative controls run in its focused suite in section 3.
#    Each self-test first accepts the clean artifact, then seeds the exact stale
#    artifact and requires a diagnostic failure. Both directions matter: an
#    always-red gate is no more trustworthy than an always-green one.
section "freshness negative fixtures (clean pass + stale fail)"
if scripts/test-freshness-negative-fixtures.sh; then
  echo "freshness checks pass clean fixtures and reject stale fixtures"
else
  echo "FAIL: a freshness check did not prove both its positive and negative direction"
  status=1
fi

# 8. Documentation path references. Deleted code must not be described as live;
#    default-aajc.6 removed the channel shadow modules while the architecture
#    map still documented them as existing. The self-test proves this check can
#    still FAIL, so it cannot decay into an always-green no-op.
section "documentation path references"
if scripts/check-doc-paths.sh --self-test && scripts/check-doc-paths.sh; then
  echo "documented paths are up to date"
else
  echo "FAIL: documentation references a path that does not exist (or the checker's self-test failed)"
  status=1
fi

# 9. The moved fixtures' ignore negations must stay EFFECTIVE, measured as an effect:
#    a new file written into a protected subtree has to be visible to git. Stripping a
#    negation does not untrack the files already tracked, so the loss appears only at
#    the next regeneration - and library builds its expected golden set from the
#    working tree rather than from git, so it passes on the machine that made it.
#    The self-test proves the gate reports both directions; note that until the
#    aweb-aauv.2 merge lands the live arm reports NOT APPLICABLE rather than passing.
section "moved fixture ignore negations (aweb-aauv.2 criterion 3)"
if scripts/check-naapp-golden-visibility.sh --self-test && scripts/check-naapp-golden-visibility.sh; then
  echo "protected subtrees are visible to git (or the movers are not here yet — read the notice above)"
else
  echo "FAIL: a moved fixture's ignore negations are no longer effective, so regenerating it silently loses files (or the checker's self-test failed)"
  status=1
fi

if [ "$status" -eq 0 ]; then
  printf '\nAll freshness checks passed.\n'
else
  printf '\nFreshness checks FAILED.\n'
fi
exit "$status"
