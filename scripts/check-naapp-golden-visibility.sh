#!/usr/bin/env bash
# The post-move standing gate for aweb-aauv.2 criterion 3.
#
# THE PROPERTY, stated as an effect rather than as the presence of lines.
#
# library and folio each carry .gitignore negations that re-include paths their own
# rules - and aweb's root rules - would otherwise exclude:
#
#   library   !tests/vectors/**/.aw/     22 tracked golden fixture files live under
#             !tests/vectors/**/.aw/**   .aw/ directories inside tests/vectors
#   library   !.env.example  !**/.env.example
#   folio     !.env.example  !**/.env.example
#
# If a negation stops being effective, the existing tracked files stay tracked - git
# does not untrack a file because a rule would now match it - so nothing looks wrong.
# What breaks is the NEXT regeneration: new fixture files become invisible, git never
# offers to add them, and the golden set silently loses whatever was added. library's
# tests/test_blueprint_interpret.py builds its expected set with rglob against the
# working tree rather than git, so that loss passes on the machine that made it and
# fails only in a fresh clone.
#
# So this gate does not grep for the negation lines. Greping stays green if the
# obligation moves and goes red on harmless rewording. It writes a file into the
# protected subtree and requires git to see it, which is the actual property and is
# immune to how the ignore file is spelled or organised.
#
# TWO ARMS, AND THEY MEASURE DIFFERENT THINGS. Do not read one as the other.
#
#   --self-test   validates THIS SCRIPT against a synthetic tree: a probe that should
#                 be visible, and - with the negations stripped - one that must not
#                 be. It proves the instrument can report both directions. It says
#                 nothing about library's and folio's real rules. Runs everywhere,
#                 including CI, and depends on nothing outside this repository.
#
#   live run      measures the REAL tree in this repository. This is the only arm that
#                 can tell you the real negations are intact.
#
# THE GAP THIS GATE HAS UNTIL THE MOVE LANDS, stated because a silent version of it
# would read as coverage: naapp/library and naapp/folio do not exist yet, so the live
# arm has nothing to measure and reports NOT APPLICABLE. It becomes live by itself
# when aweb-aauv.2's merge lands. Until then the real negations are measured only by
# scripts/check-naapp-move-addable.sh, which reads the source repositories from
# outside aweb and is deliberately not wired into CI. That check is not this gate and
# must not be substituted for it: it measures the pre-move question and after the move
# it has nothing left to measure.
#
# When the movers are reachable - as siblings before the move, or in-repo after it -
# the self-test adds an arm that runs the same assertions against a scratch tree built
# from their REAL .gitignore files. That arm is skipped in CI, and a skip is reported
# as NOT RUN rather than as a pass.
#
# EXIT: 0 property holds (or not applicable), 1 property violated, 2 could not measure.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/lib/naapp-movers.sh
source "$ROOT/scripts/lib/naapp-movers.sh"

# Destination : the negation families that destination must keep effective.
#
# Keyed on destination because that is what this repository will contain, and the
# destinations are cross-checked against the shared movers table below so renaming a
# destination in one place cannot leave this gate silently measuring a path that no
# mover lands on. aweb-naapp is absent on purpose: its .gitignore is Python build
# artefacts with no negations, so it has no such property to hold.
NEGATION_CASES=(
  "naapp/library:golden_aw env_example"
  "naapp/folio:env_example"
)

PROBE_TAG="aauv2-visibility-probe"

# Scratch trees are removed through one EXIT trap over a global. A RETURN trap over a
# function-local reads that local as unset by the time it fires.
SCRATCH=""
cleanup_scratch() {
  if [[ -n "$SCRATCH" && -d "$SCRATCH" ]]; then
    rm -rf "$SCRATCH"
  fi
}
trap cleanup_scratch EXIT

fail()   { printf 'FAIL: %s\n' "$1" >&2; }
refuse() { printf 'CANNOT MEASURE: %s\n' "$1" >&2; }

# Every destination this gate names must be one a mover actually lands on.
assert_destinations_are_real() {
  local case_entry dest mover known
  known="$(naapp_movers | cut -d: -f2)"
  for case_entry in "${NEGATION_CASES[@]}"; do
    dest="${case_entry%%:*}"
    if ! printf '%s\n' "$known" | grep -qxF "$dest"; then
      refuse "this gate measures $dest, which no mover lands on. The movers table says: $(echo "$known" | tr '\n' ' ')"
      return 2
    fi
  done
}

# Is a path visible to git - would git offer to add it? This is the effect the
# property is about. A pathspec-limited status reports an ignored file as nothing at
# all, which is exactly the silence being guarded against.
path_is_visible() {
  local repo="$1" path="$2"
  git -C "$repo" status --porcelain --untracked-files=all -- "$path" 2>/dev/null \
    | grep -q '^??'
}

# Write a probe at $path, report whether git sees it, and remove it. The probe is
# removed by exact path and never with git checkout: a checkout here would discard
# whatever else the working tree holds.
probe_visibility() {
  local repo="$1" path="$2"
  # A separate statement: local expands all of its words before assigning any of
  # them, so a full="$repo/$path" on the line above reads both as unset.
  local full="$repo/$path"

  if [[ -e "$full" ]]; then
    refuse "probe path $path already exists; refusing to overwrite it"
    return 2
  fi
  mkdir -p "$(dirname "$full")" || { refuse "could not create $(dirname "$path")"; return 2; }
  printf 'transient probe written by %s; if this file is committed, that is a bug\n' \
    "$(basename "${BASH_SOURCE[0]}")" > "$full" || { refuse "could not write $path"; return 2; }

  local visible=1
  path_is_visible "$repo" "$path" && visible=0

  rm -f "$full"
  if [[ -e "$full" ]]; then
    refuse "probe $path could not be removed; the working tree has been left dirty"
    return 2
  fi
  return "$visible"
}

# library's golden fixtures: a probe inside a real tracked .aw/ directory under
# tests/vectors. Discovered from the index rather than hardcoded, so reorganising the
# fixtures moves the probe with them - and if no such directory is tracked, that is a
# refusal, because a probe written somewhere the negation does not cover would report
# visibility that means nothing.
case_golden_aw() {
  local repo="$1" dest="$2" dir
  dir="$(git -C "$repo" ls-files -- "$dest/tests/vectors" | grep '/\.aw/' | head -1)"
  if [[ -z "$dir" ]]; then
    refuse "$dest has no tracked file under a tests/vectors .aw/ directory, so the golden-fixture negation cannot be measured there"
    return 2
  fi
  dir="$(dirname "$dir")"
  probe_visibility "$repo" "$dir/$PROBE_TAG.md"
}

# The .env.example negations are depth-independent (!**/.env.example), so the probe
# goes in a fresh directory rather than over the tracked .env.example. What must hold
# for the measurement to mean anything is that the mover's own .gitignore is present -
# without it the negations are not in the tree at all and a visible probe would prove
# nothing.
case_env_example() {
  local repo="$1" dest="$2"
  if ! git -C "$repo" ls-files --error-unmatch "$dest/.gitignore" >/dev/null 2>&1; then
    refuse "$dest/.gitignore is not tracked, so its negations are not in this tree and visibility here would prove nothing"
    return 2
  fi
  probe_visibility "$repo" "$dest/$PROBE_TAG-dir/.env.example"
}

# Run every case for every mover present. Returns 0 all held, 1 one was violated,
# 2 something could not be measured.
check_tree() {
  local repo="$1" label="$2"
  local case_entry dest kinds kind rc worst=0 present=0 absent=0

  for case_entry in "${NEGATION_CASES[@]}"; do
    dest="${case_entry%%:*}"
    kinds="${case_entry#*:}"
    if [[ ! -d "$repo/$dest" ]]; then
      absent=$((absent + 1))
      continue
    fi
    present=$((present + 1))
    for kind in $kinds; do
      "case_$kind" "$repo" "$dest"
      rc=$?
      case "$rc" in
        0) printf '  ok   %-14s %-13s a new file in the protected subtree is visible to git\n' "$dest" "$kind" ;;
        1) fail "$label: $dest $kind - a new file in the protected subtree is INVISIBLE to git. The negations are no longer effective, so regenerating this fixture silently loses files."
           [[ "$worst" -lt 1 ]] && worst=1 ;;
        *) [[ "$worst" -lt 2 ]] && worst=2 ;;
      esac
    done
  done

  # All-or-none. A partially present set means the move landed somewhere unexpected,
  # and reporting the movers that ARE there as a pass would be a green covering a
  # missing destination.
  if [[ "$present" -gt 0 && "$absent" -gt 0 ]]; then
    fail "$label: $present mover destination(s) present and $absent absent. A partial set means the move landed somewhere other than the decided destinations; this gate will not report on the present ones alone."
    return 1
  fi
  if [[ "$present" -eq 0 ]]; then
    return 3
  fi
  return "$worst"
}

# A synthetic post-move tree. Rule TEXT is written here rather than copied from the
# movers so this arm runs in CI, where the source repositories do not exist. It
# reproduces the two shapes that matter: a directory exclusion re-included by a
# dir-plus-contents negation pair, and a file glob re-included by a negation. This
# validates the instrument. It is not evidence about library's and folio's real rules.
build_synthetic_tree() {
  local repo="$1"
  mkdir -p "$repo" || return 2
  git -C "$repo" init -q . || return 2
  git -C "$repo" config user.email gate@example.invalid
  git -C "$repo" config user.name "naapp visibility gate self-test"

  cat > "$repo/.gitignore" <<'EOF'
.aw/
.env
.env.*
**/.env
**/.env.*
EOF

  local dest
  for dest in naapp/library naapp/folio; do
    mkdir -p "$repo/$dest"
    cat > "$repo/$dest/.gitignore" <<'EOF'
.aw/
.env
.env.*

# Vendored conformance fixtures keep their literal .aw layout
!tests/vectors/**/.aw/
!tests/vectors/**/.aw/**
!.env.example
!**/.env.example
EOF
    # A tracked golden fixture file, which is also what makes the golden case's
    # discovery step reach a real directory.
    mkdir -p "$repo/$dest/tests/vectors/blueprints/expected/home/developer/.aw/profile"
    echo "golden" > "$repo/$dest/tests/vectors/blueprints/expected/home/developer/.aw/profile/instructions.md"
    echo "example" > "$repo/$dest/.env.example"
  done
  git -C "$repo" add -A >/dev/null 2>&1 || return 2
  git -C "$repo" commit -qm "synthetic post-move tree" >/dev/null 2>&1 || return 2
}

# Strip every negation from a tree's mover .gitignore files, and ASSERT the strip
# applied before any result is read. A mutation that silently did not apply turns
# this arm into a second copy of the positive arm.
strip_negations() {
  local repo="$1" dest kept before after
  for dest in naapp/library naapp/folio; do
    local g="$repo/$dest/.gitignore"
    [[ -f "$g" ]] || continue
    before="$(grep -c '^!' "$g")"
    if [[ "$before" -eq 0 ]]; then
      refuse "$dest/.gitignore has no negations to strip, so the mutation arm would prove nothing"
      return 2
    fi
    kept="$(grep -v '^!' "$g")"
    printf '%s\n' "$kept" > "$g"
    after="$(grep -c '^!' "$g" || true)"
    if [[ "$after" -ne 0 ]]; then
      refuse "$dest/.gitignore still has $after negation(s) after the strip; the mutation did not apply"
      return 2
    fi
  done
  git -C "$repo" add -A >/dev/null 2>&1
  git -C "$repo" commit -qm "strip the negations" >/dev/null 2>&1
}

# One self-test arm pair against a tree: probes visible, then invisible once stripped.
self_test_tree() {
  local repo="$1" label="$2"

  check_tree "$repo" "$label"
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fail "self-test ($label): the intact tree did not report every protected subtree as visible (rc=$rc)"
    return 1
  fi
  printf '  ok   %s: intact negations - every protected subtree is visible\n' "$label"

  strip_negations "$repo" || return 1
  check_tree "$repo" "$label" > /dev/null 2>&1
  rc=$?
  if [[ "$rc" -ne 1 ]]; then
    fail "self-test ($label): with every negation stripped the gate returned $rc rather than 1. It cannot detect the loss it exists to detect."
    return 1
  fi
  printf '  ok   %s: negations stripped - the gate goes RED\n' "$label"
}

run_self_test() {
  local work rc=0
  work="$(mktemp -d)" || { refuse "could not create a scratch directory"; return 2; }
  SCRATCH="$work"

  echo "self-test: the instrument reports both directions"
  build_synthetic_tree "$work/synthetic" || { refuse "could not build the synthetic tree"; return 2; }
  self_test_tree "$work/synthetic" "synthetic tree" || rc=1

  # The real-rules arm, when the movers are reachable. Skipped rather than assumed,
  # and a skip is reported as NOT RUN.
  echo "self-test: the same assertions against the movers' REAL .gitignore files"
  local mover src dest ref have_real=1 real="$work/real"
  mkdir -p "$real"
  git -C "$real" init -q .
  git -C "$real" config user.email gate@example.invalid
  git -C "$real" config user.name "naapp visibility gate self-test"
  cp "$ROOT/.gitignore" "$real/.gitignore"
  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    # Only the destinations this gate has cases for.
    printf '%s\n' "${NEGATION_CASES[@]}" | grep -q "^$dest:" || continue
    local rules=""
    if [[ -f "$ROOT/$dest/.gitignore" ]]; then
      rules="$ROOT/$dest/.gitignore"           # post-move: in this repository
    elif [[ -f "$src/.gitignore" ]]; then
      rules="$src/.gitignore"                  # pre-move: the sibling checkout
    fi
    if [[ -z "$rules" ]]; then
      have_real=0
      continue
    fi
    mkdir -p "$real/$dest/tests/vectors/blueprints/expected/home/developer/.aw/profile"
    cp "$rules" "$real/$dest/.gitignore"
    echo "golden" > "$real/$dest/tests/vectors/blueprints/expected/home/developer/.aw/profile/instructions.md"
    echo "example" > "$real/$dest/.env.example"
  done < <(naapp_movers)

  if [[ "$have_real" -eq 0 ]]; then
    printf '  NOT RUN  the movers are not reachable here, so the real rules were not measured.\n'
    printf '           This is expected in CI. It is NOT a pass: no statement about library\n'
    printf "           and folio's actual negations is made by this run.\n"
  else
    git -C "$real" add -A >/dev/null 2>&1
    git -C "$real" commit -qm "real mover rules" >/dev/null 2>&1
    self_test_tree "$real" "real mover rules" || rc=1
  fi

  if [[ "$rc" -eq 0 ]]; then
    echo "self-test passed: the gate accepts intact negations and rejects stripped ones"
  fi
  return "$rc"
}

main() {
  assert_destinations_are_real || return 2

  if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    return $?
  fi

  echo "checking that the moved fixtures' ignore negations are still effective"
  check_tree "$ROOT" "post-move tree"
  local rc=$?
  case "$rc" in
    0) echo "every protected subtree is visible to git"; return 0 ;;
    3) printf 'NOT APPLICABLE: no mover destination exists in this repository yet, so there is\n'
       printf '                nothing here to measure. This is not a pass. The gate becomes live\n'
       printf "                on its own when aweb-aauv.2's merge lands; until then the real\n"
       printf '                negations are measured only by check-naapp-move-addable.sh, from\n'
       printf '                outside this repository and not in CI.\n'
       return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

main "$@"
