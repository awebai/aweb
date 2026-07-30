#!/usr/bin/env bash
# Assert aweb-aauv.2's criterion 4: each moved subtree's test suite still produces the
# tally recorded for it, measured from a fresh clone so what runs is what git holds.
#
# THE FILENAME IS HISTORICAL AND IS NOW WRONG: this script rehearses nothing. It is left
# in place only because whether the remaining check survives at all is an open question
# (aweb-aauv.4), and renaming a file twice is worse than naming the lie once. If that
# check is kept, rename this for what it measures.
#
# THIS SCRIPT NO LONGER REHEARSES THE MOVE. The rehearsal arm grafted the three movers
# into a throwaway clone and asserted tree equality and the root entry set before the
# real merge. It was retired because THE OPERATION IT REHEARSED CANNOT RECUR: the three
# subtree merges landed on aweb main, main is the shared sync branch and is not
# rewritten, so there is no second first attempt to de-risk.
#
# It is worth being exact about why, because the arm WORKED when it was removed - two
# people ran it independently and the graft, the tree equality and the root entry set
# all passed. It was not deleted for being broken. Anyone reconstructing it can: the
# pre-move state of the receiving repo is the first parent of each merge (3d2861ee^1 =
# d3032c28, pre-all-moves since the three merges are linear), and the mover's own
# pre-move tree is the second parent. Merge parents do not expire.
#
# WHAT THE RECORDED TALLIES MEAN NOW. They describe the trees as they stand in aweb,
# not as they stood in the standalone repos - naapp/folio carries three Makefile guard
# tests that folio at 44e620f6 does not, so the same table cannot serve both. That is
# why the retired arm's parity comparison could not have been kept as it was, and it is
# a fact about the table rather than about the graft.
#
# WHAT SURVIVED HERE WAS NOT REVIEWED, AND ONE PART OF IT IS KNOWN TO BE BLIND. The
# retirement that produced this file was reviewed and ACKed; the reviewer stated, unprompted,
# that he had audited the retirement - no orphans, control flow intact, no residue - and had
# NOT audited assert_baseline_ref's semantics, because it survived untouched and so was
# outside the diff. Recorded because an ACK covers what the reviewer examined, and a later
# reader otherwise sees "reviewed" sitting over the following defect and concludes it was
# considered and accepted:
#
#   assert_baseline_ref does `git -C "$src" rev-parse "origin/main^{commit}"` where $src is
#   the LOCAL sibling clone. origin/main there is that clone's last-fetched tracking ref, so
#   the assertion cannot see the sibling repository advance - it sees whether someone has run
#   git fetch in ~/prj/awebai/library. A sibling that merges ten PRs while nobody fetches
#   passes this check unchanged.
#
# KNOWN AND DELIBERATELY UNFIXED. It is one of three reasons this arm is not a drift detector
# (the tally is also noisy on every legitimate change and silent on offsetting ones), and the
# arm's fate is open on aweb-aauv.4. Fixing this read now would build the wrong half of either
# answer: if the sibling repos are archived the arm goes entirely, and if they stay live the
# check that is wanted is a content comparison, not a ref assertion.
#
# The mover table points at the sibling repos' origin/main rather than at the merge
# parents, and for a DRIFT question that is correct: a merge parent is frozen, so
# anchoring to one would only ever re-verify what was merged. Whether drift detection
# is still wanted depends on whether those repos stay live (aweb-aauv.4).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/lib/naapp-movers.sh
source "$ROOT/scripts/lib/naapp-movers.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

assert_baseline_ref() {
  local src="$1" ref="$2" expected="$3" label="$4" actual
  actual="$(git -C "$src" rev-parse "$ref^{commit}")"
  if [[ "$actual" != "$expected"* ]]; then
    printf 'FAIL %s: the baseline was measured at %s but %s is now %s.\n' \
      "$label" "$expected" "$ref" "${actual:0:12}" >&2
    printf '      The recorded counts describe a different tree; re-baseline before comparing.\n' >&2
    return 1
  fi
}

# Pull one "key=value" tally out of a pytest summary line.
tally_of() {
  local output="$1" key="$2"
  printf '%s\n' "$output" | grep -oE "[0-9]+ $key" | tail -1 | grep -oE '^[0-9]+'
}

run_parity() {
  local merged="$1"
  local fresh="$WORK/fresh"
  local baseline dest ref command expectations label src mover msrc mdest mref
  local rc=0

  # A clone of the merged result, so what runs is what git holds.
  git clone -q "$merged" "$fresh" || { printf 'FAIL: could not clone the merged result\n' >&2; return 2; }

  while IFS= read -r baseline; do
    IFS='|' read -r dest ref command expectations <<< "$baseline"
    label="$(basename "$dest")"

    # The baseline's source commit must still be the commit being merged. src and its
    # ref are captured together: taking the ref from the loop variable after the loop
    # would read the LAST mover's ref rather than the matched one, which is invisible
    # while every mover happens to share a ref.
    src=""; local src_ref=""
    while IFS= read -r mover; do
      IFS=':' read -r msrc mdest mref <<< "$mover"
      if [[ "$mdest" == "$dest" ]]; then src="$msrc"; src_ref="$mref"; fi
    done < <(naapp_movers)
    if [[ -z "$src" ]]; then
      printf 'FAIL %s: no mover lands on %s, so its baseline cannot be checked\n' "$label" "$dest" >&2
      rc=1; continue
    fi
    assert_baseline_ref "$src" "$src_ref" "$ref" "$label" || { rc=1; continue; }

    if [[ ! -d "$fresh/$dest" ]]; then
      printf 'FAIL %s: %s is absent from the fresh clone\n' "$label" "$dest" >&2
      rc=1; continue
    fi

    printf '  running %s in the fresh clone: %s\n' "$label" "$command"
    local output status=0
    output="$(cd "$fresh/$dest" && eval "$command" 2>&1)" || status=$?

    local key expected actual mismatch=0
    for key in $expectations; do
      expected="${key#*=}"
      key="${key%%=*}"
      actual="$(tally_of "$output" "$key")"
      if [[ "$actual" != "$expected" ]]; then
        printf 'FAIL %s: expected %s=%s, measured %s=%s\n' \
          "$label" "$key" "$expected" "$key" "${actual:-none}" >&2
        mismatch=1
      fi
    done
    if [[ "$mismatch" -ne 0 || "$status" -ne 0 ]]; then
      printf '      pytest exited %s. Last lines:\n' "$status" >&2
      printf '%s\n' "$output" | tail -15 | sed 's/^/        /' >&2
      rc=1
      continue
    fi
    printf '  ok   %-12s %s, matching the recorded tally for %s at %s\n' \
      "$label" "$(printf '%s\n' "$expectations" | tr '\n' ' ')" "$dest" "$ref"
  done < <(naapp_parity_baselines)

  return "$rc"
}
# Are the moved subtrees present at their destinations? This asks nothing about history
# and is not a proxy for "the merge happened" - it is the condition that decides whether
# there is anything here to measure. A destination absent means this checkout predates
# the move, and comparing post-move tallies against it would report a violation that is
# an artifact of the checkout rather than a fact about the trees.
destinations_present() {
  local mover src dest ref
  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    git -C "$ROOT" cat-file -e "HEAD:$dest" 2>/dev/null || return 1
  done < <(naapp_movers)
}

if ! destinations_present; then
  printf 'CANNOT MEASURE: the moved subtrees are not at their destinations in this checkout,\n' >&2
  printf '                so it predates the naapp move. The recorded tallies describe the\n' >&2
  printf '                post-move trees and would report a violation that is an artifact\n' >&2
  printf '                of the checkout. Check out a commit that contains the move.\n' >&2
  exit 2
fi

echo "criterion 4: parity against the recorded tallies, measured on this repository"
run_parity "$ROOT"
echo
echo "parity complete: each mover's suite matches its recorded tally from a fresh clone"
echo "note: naapp-lib/ is not exercised - both movers install aweb-naapp from git, so the"
echo "      moved copy is executed by nothing here."
