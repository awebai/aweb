#!/usr/bin/env bash
# Verify that repository paths referenced in documentation actually exist.
#
# SCOPE, stated precisely because the previous freshness comments overstated
# what was validated (default-aajc.16). This checks the EXISTENCE of referenced
# paths. It does NOT check that surrounding prose is accurate, that a :LINE
# anchor still points at the described symbol, or that any inventory (test
# counts, ownership tables) is current. Those remain human review obligations —
# see the freshness section of docs/contributing.md.
#
# It deliberately checks only backtick-quoted paths that are UNAMBIGUOUSLY
# repo-relative, meaning they start with one of the top-level directories below.
# Three exclusions are intentional:
#   - Documents that declare their own base directory (docs/restructuring/
#     cli-go-map.md states its paths are relative to cli/go/) would otherwise
#     produce false failures.
#   - awid/ and a2a/ are top-level directories AND names of cli/go/
#     subdirectories, so a bare `awid/client.go` is ambiguous. They are omitted
#     rather than guessed at. Consequence, stated rather than hidden: stale
#     references to the top-level awid/ service are NOT caught by this gate.
#   - Archived snapshots (see PRUNE below).
# A gate that reports false failures gets disabled, which is worse than no gate.
#
# Usage:
#   check-doc-paths.sh              scan docs/
#   check-doc-paths.sh --self-test  prove the checker fails on a missing path
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TOP_LEVEL='docs|cli|channel|channel-core|pi-extension|server|scripts|examples'

# Referenced correctly but legitimately absent from the tree. Every entry needs
# a reason; an unexplained allowlist rots the same way the documentation did.
is_allowed() {
  case "$1" in
    # Operator-created at deploy time and gitignored. The self-hosting guide
    # documents it as a file the operator writes, not one we ship.
    server/.env) return 0 ;;
    # A path in the UPSTREAM A2A repository, not this one. docs/a2a.md cites it
    # to record how the golden fixtures were cross-checked against upstream.
    scripts/proto_to_json_schema.sh) return 0 ;;
    # The release authority is deliberately cross-repository. These paths are
    # named under an explicit AC heading in docs/release.md and are verified by
    # AC's own docs/model gates, not by pretending they live in aweb.
    docs/publication-sources.json|docs/sot.md|scripts/check_release_model.py|scripts/verify_docs_contract.py) return 0 ;;
    # Named by docs/release.md's Delete list and Residue check as REMOVED
    # machinery: the authority records their deletion, so their absence is
    # the documented state, not a broken reference.
    scripts/release_driver.py|scripts/release_receipt_archive.py|docs/runnerless-release.md|docs/setup-surface-release-gates.md|scripts/check-release-tag-monotonic.sh|scripts/release_skew_harnesses.py|scripts/release_skew_cli_server.py|scripts/release_channel_pi_skew.py|scripts/release_federation_skew.py|scripts/release_persisted_state_skew.py) return 0 ;;
  esac
  return 1
}

# Documentation templates, not references to real files.
is_placeholder() {
  case "$1" in
    *...*|*NNN*|*'<'*|*'>'*|*'*'*|*'$'*) return 0 ;;
  esac
  return 1
}

# scan_docs <base_dir> <docs_dir>
# Resolves references against base_dir; reports any that do not exist.
scan_docs() {
  local base="$1" docs_dir="$2" missing=0 scanned=0 ref where

  # Archived snapshots are excluded BY DESIGN: an archive records the tree as it
  # was at a stated date and SHA, so its paths are EXPECTED not to resolve.
  # Requiring them to resolve would force us either to rewrite history or to
  # delete the record. The exclusion is narrow (one directory) and every
  # archived document must carry a prominent historical header.
  local refs
  refs="$(find "$docs_dir" -name '*.md' -not -path '*/node_modules/*' \
      -not -path '*/restructuring/archive/*' -print0 2>/dev/null \
    | xargs -0 grep -ohE '`('"$TOP_LEVEL"')/[A-Za-z0-9_./-]+(:[0-9]+)?`' 2>/dev/null \
    | tr -d '`' | sed 's/:[0-9]*$//' | sort -u)"

  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    is_placeholder "$ref" && continue
    is_allowed "$ref" && continue
    scanned=$((scanned + 1))
    if [ ! -e "$base/$ref" ]; then
      where="$(grep -rl -F "$ref" --include='*.md' "$docs_dir" 2>/dev/null | tr '\n' ' ')"
      echo "MISSING: $ref"
      echo "  referenced by: ${where:-unknown}"
      missing=$((missing + 1))
    fi
  done <<< "$refs"

  if [ "$missing" -gt 0 ]; then
    echo
    echo "FAIL: $missing documented path(s) do not exist."
    echo "Fix the reference, or if the path is correct but legitimately absent,"
    echo "add it to is_allowed() in this script WITH a reason."
    return 1
  fi
  echo "documented repository paths resolve ($scanned checked)"
  return 0
}

# A gate is only worth its ability to FAIL. This fixture proves the checker
# rejects a reference to a deleted path, so the check cannot silently degrade
# into an always-green no-op (default-aajc.16).
self_test() {
  local tmp status
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/docs" "$tmp/channel/src"
  : > "$tmp/channel/src/index.ts"

  printf 'Live reference: `channel/src/index.ts`\n' > "$tmp/docs/ok.md"
  if ! scan_docs "$tmp" "$tmp/docs" >/dev/null; then
    echo "SELF-TEST FAIL: a reference to an existing path was reported missing"
    return 1
  fi

  # channel/src/identity was deleted by default-aajc.6; referencing it must fail.
  printf 'Stale reference: `channel/src/identity/trust.ts`\n' > "$tmp/docs/stale.md"
  scan_docs "$tmp" "$tmp/docs" >/dev/null
  status=$?
  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: a reference to a DELETED path was accepted."
    echo "The gate cannot detect the defect it exists to catch."
    return 1
  fi

  echo "self-test passed: the checker accepts live paths and rejects deleted ones"
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

cd "$ROOT"
scan_docs "$ROOT" "docs"
exit $?
