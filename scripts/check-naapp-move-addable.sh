#!/usr/bin/env bash
# Prove that every file tracked in a repository moving into aweb still arrives
# intact at its destination path inside aweb.
#
# git add is silent on ignored paths: a copy-then-add move drops files with no
# output, no error, and a green test run, because the fixtures the tests would
# have used are dropped along with them. The absence of a complaint proves
# nothing here, so this check asks git explicitly.
#
# The property is stronger than "nothing was ignored". For each mover it places
# the tracked tree at its destination inside a scratch repository carrying
# aweb's ignore rules, adds it, and requires the resulting index to match the
# mover's index exactly on path, mode and blob. That one comparison covers:
#
#   path  - a file swallowed by an ignore rule
#   mode  - a lost executable bit
#   blob  - a dereferenced symlink, or content changed in transit
#
# Run with --self-test to exercise the check in the failing direction. The thing
# that makes it pass is the ignore negations each mover carries in its own
# .gitignore, so the self-test strips those and requires the check to name
# exactly the files aweb's own rules would swallow - a red that names the
# property rather than a red of unknown cause.
#
# This is a migration-time check against sibling checkouts outside aweb, so it
# is deliberately not wired into CI: once the movers live inside aweb it has
# nothing left to measure.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/lib/naapp-movers.sh
source "$ROOT/scripts/lib/naapp-movers.sh"

mapfile -t MOVERS < <(naapp_movers)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A scratch repository carrying aweb's ignore rules and nothing else, so the
# comparison measures the destination's rules rather than aweb's own contents.
build_scratch() {
  local scratch="$1" rules_root="${2:-$ROOT}" ignore_file source
  mkdir -p "$scratch"
  git -C "$scratch" init -q .
  git -C "$scratch" config core.fileMode true
  git -C "$scratch" config core.autocrlf false

  # $rules_root may hold only a mutated copy of the root .gitignore, so any file
  # it does not carry is taken from the repository as committed.
  while IFS= read -r ignore_file; do
    source="$rules_root/$ignore_file"
    [[ -f "$source" ]] || source="$ROOT/$ignore_file"
    mkdir -p "$scratch/$(dirname "$ignore_file")"
    cp -f "$source" "$scratch/$ignore_file"
  done < <(git -C "$ROOT" ls-files '*.gitignore' '.gitignore')

  # A silent copy failure would leave the scratch repo with no rules at all,
  # and an empty rule set passes every comparison for the wrong reason.
  if [[ ! -s "$scratch/.gitignore" ]]; then
    printf 'FAIL: scratch repo has no root .gitignore; aweb ignore rules were not applied\n' >&2
    return 1
  fi
}

# The (path, mode, blob) triples a mover carries at $ref, tab-separated and keyed
# on path. Tab-separated rather than space-separated so a path containing a space
# cannot be misread as a field boundary; git's own output is read with --format
# for the same reason.
mover_index() {
  git -C "$1" ls-tree -r --format='%(path)	%(objectmode)	%(objectname)' "$2" | sort
}

# The same triples after the tree at $ref is placed at $dest and added.
# git archive | tar preserves modes and symlinks, so a difference here is the
# destination's ignore rules rather than the copy method.
placed_index() {
  local src="$1" dest="$2" scratch="$3" mutate="$4" ref="$5"

  mkdir -p "$scratch/$dest"
  git -C "$src" archive "$ref" | tar -x -C "$scratch/$dest"

  if [[ "$mutate" == "strip-negations" && -f "$scratch/$dest/.gitignore" ]]; then
    grep -v '^!' "$scratch/$dest/.gitignore" > "$scratch/stripped" || true
    cp -f "$scratch/stripped" "$scratch/$dest/.gitignore"
  fi

  # What a copy that follows symlinks does to them, so the self-test can prove
  # the mode and content comparison sees it. library carries 8 tracked symlinks,
  # all inside the golden fixtures the interpret tests compare byte-exact.
  if [[ "$mutate" == "deref-symlinks" ]]; then
    local link target
    while IFS= read -r link; do
      target="$scratch/$dest/$link"
      [[ -L "$target" ]] || continue
      local literal
      literal="$(readlink "$target")"
      rm "$target"
      printf '%s' "$literal" > "$target"
    done < <(git -C "$src" ls-tree -r "$ref" | awk '$1 == "120000" { print $4 }')
  fi

  git -C "$scratch" add -A -- "$dest"
  git -C "$scratch" ls-files --format='%(path)	%(objectmode)	%(objectname)' -- "$dest" \
    | sed "s|^$dest/||" \
    | sort
}

# The paths aweb's root rules alone would swallow, derived without placing any
# file. The self-test compares this against what stripping the negations
# actually loses, so two independent derivations have to agree.
#
# check-ignore is asked without -v on purpose. With -v it prints a line for
# negated matches too, showing the bang pattern that made the path addable, so
# counting its output reports files as ignored when the true answer is none.
# The plain form prints only genuinely ignored paths. --no-index is required
# because check-ignore skips paths already in the index.
# check-ignore exits 1 when it matched nothing, which here is the good case and
# not an error, so its status is deliberately discarded rather than allowed to
# trip pipefail.
root_rule_casualties() {
  local src="$1" dest="$2" ref="$3" rules_root="${4:-$ROOT}"
  git -C "$src" ls-tree -r --name-only "$ref" \
    | sed "s|^|$dest/|" \
    > "$WORK/casualty-candidates"
  git -C "$rules_root" check-ignore --no-index --stdin \
    < "$WORK/casualty-candidates" \
    > "$WORK/casualty-hits" || true
  sed "s|^$dest/||" "$WORK/casualty-hits" | sort
}

# Writes the missing and changed paths to $WORK/loss; returns 1 on any difference.
compare_mover() {
  local src="$1" dest="$2" mutate="$3" label="$4" ref="$5" rules_root="${6:-$ROOT}"
  local scratch="$WORK/$label"
  local expected="$WORK/$label.expected" actual="$WORK/$label.actual"

  build_scratch "$scratch" "$rules_root"
  mover_index "$src" "$ref" > "$expected"
  placed_index "$src" "$dest" "$scratch" "$mutate" "$ref" > "$actual"

  local n_expected
  n_expected="$(wc -l < "$expected" | tr -d ' ')"
  if [[ "$n_expected" -eq 0 ]]; then
    printf 'FAIL: %s tracks no files; the comparison would pass vacuously\n' "$src" >&2
    return 2
  fi
  MOVER_TRACKED="$n_expected"

  # Both files are already keyed on path and sorted, which comm and join require.
  comm -23 <(cut -f1 "$expected") <(cut -f1 "$actual") > "$WORK/loss"
  join -t"$(printf '\t')" -j 1 "$expected" "$actual" \
    | awk -F'\t' '$2 != $4 || $3 != $5 { print $1 }' > "$WORK/changed"

  [[ ! -s "$WORK/loss" && ! -s "$WORK/changed" ]]
}

naapp_require_movers
naapp_assert_pin_agreement
echo

if [[ "${1:-}" == "--self-test" ]]; then
  echo "self-test: with each mover's own ignore negations stripped, this check must name exactly the files aweb's rules swallow"
  exercised=0
  for mover in "${MOVERS[@]}"; do
    IFS=':' read -r src dest ref <<< "$mover"
    name="$(basename "$src")"
    if ! git -C "$src" show "$ref:.gitignore" 2>/dev/null | grep -q '^!'; then
      printf '  --   %-12s carries no ignore negations; nothing to strip\n' "$name"
      continue
    fi
    if compare_mover "$src" "$dest" "strip-negations" "selftest-$name" "$ref"; then
      printf 'FAIL: %s still arrived intact with its ignore negations stripped; this check cannot see the loss it exists to catch\n' "$name" >&2
      exit 1
    fi
    root_rule_casualties "$src" "$dest" "$ref" > "$WORK/predicted"
    if ! diff -u "$WORK/predicted" "$WORK/loss" > "$WORK/selftest.diff"; then
      printf 'FAIL: %s lost a different set of files than aweb'"'"'s ignore rules predict.\n' "$name" >&2
      printf '      Left is predicted by git check-ignore, right is what the move actually lost:\n' >&2
      cat "$WORK/selftest.diff" >&2
      exit 1
    fi
    printf '  ok   %-12s stripping negations loses exactly the %s paths aweb'"'"'s rules match\n' \
      "$name" "$(wc -l < "$WORK/loss" | tr -d ' ')"
    exercised=$((exercised + 1))
  done
  if [[ "$exercised" -eq 0 ]]; then
    printf 'FAIL: no mover carried ignore negations, so the failing direction was never exercised\n' >&2
    exit 1
  fi

  # The path arm is now proven sensitive. The mode and content arm has its own
  # hazard - a copy that follows symlinks - and its own code, so it needs its
  # own red.
  echo "self-test: a copy that follows symlinks must be reported as changing exactly the tracked symlinks"
  exercised=0
  for mover in "${MOVERS[@]}"; do
    IFS=':' read -r src dest ref <<< "$mover"
    name="$(basename "$src")"
    git -C "$src" ls-tree -r "$ref" | awk '$1 == "120000" { print $4 }' | sort > "$WORK/symlinks"
    if [[ ! -s "$WORK/symlinks" ]]; then
      printf '  --   %-12s tracks no symlinks; nothing to dereference\n' "$name"
      continue
    fi
    if compare_mover "$src" "$dest" "deref-symlinks" "deref-$name" "$ref"; then
      printf 'FAIL: %s arrived intact with its symlinks dereferenced; this check is blind to mode changes\n' "$name" >&2
      exit 1
    fi
    if ! diff -u "$WORK/symlinks" "$WORK/changed" > "$WORK/deref.diff"; then
      printf 'FAIL: %s reported a different set of changed files than the symlinks that were dereferenced.\n' "$name" >&2
      printf '      Left is the tracked symlinks, right is what the check reported changed:\n' >&2
      cat "$WORK/deref.diff" >&2
      exit 1
    fi
    printf '  ok   %-12s dereferencing reports exactly its %s tracked symlinks as changed\n' \
      "$name" "$(wc -l < "$WORK/symlinks" | tr -d ' ')"
    exercised=$((exercised + 1))
  done
  if [[ "$exercised" -eq 0 ]]; then
    printf 'FAIL: no mover tracked a symlink, so the mode and content arm was never exercised\n' >&2
    exit 1
  fi

  # The two arms above mutate the movers. The realistic future regression is the
  # other way in: aweb's root .gitignore gaining a rule no mover negates. aweb's
  # rules are edited far more often than the movers' are, so this direction is
  # the one most likely to be exercised for real.
  echo "self-test: a new rule in aweb's own root .gitignore must be reported as losing the files it matches"
  # check-ignore needs a repository to run in, so the mutated rules live in one.
  aweb_rules="$WORK/aweb-rules"
  mkdir -p "$aweb_rules"
  git -C "$aweb_rules" init -q .
  cp -f "$ROOT/.gitignore" "$aweb_rules/.gitignore"
  printf '\n# self-test probe\ndocs/\n' >> "$aweb_rules/.gitignore"

  exercised=0
  for mover in "${MOVERS[@]}"; do
    IFS=':' read -r src dest ref <<< "$mover"
    name="$(basename "$src")"
    # What the probe rule adds, rather than everything aweb's rules match: the
    # rest is rescued by the movers' own negations, which are still in place here.
    root_rule_casualties "$src" "$dest" "$ref" "$aweb_rules" > "$WORK/casualties-probe"
    root_rule_casualties "$src" "$dest" "$ref" "$ROOT" > "$WORK/casualties-base"
    comm -23 "$WORK/casualties-probe" "$WORK/casualties-base" > "$WORK/predicted-root"
    if [[ ! -s "$WORK/predicted-root" ]]; then
      printf '  --   %-12s the probe rule matches nothing it tracks\n' "$name"
      continue
    fi
    if compare_mover "$src" "$dest" "none" "rootrule-$name" "$ref" "$aweb_rules"; then
      printf 'FAIL: %s arrived intact with a root rule matching %s of its files; this check does not see aweb'"'"'s own rules\n' \
        "$name" "$(wc -l < "$WORK/predicted-root" | tr -d ' ')" >&2
      exit 1
    fi
    if ! diff -u "$WORK/predicted-root" "$WORK/loss" > "$WORK/rootrule.diff"; then
      printf 'FAIL: %s lost a different set of files than the probe rule predicts.\n' "$name" >&2
      cat "$WORK/rootrule.diff" >&2
      exit 1
    fi
    printf '  ok   %-12s a root docs/ rule loses exactly the %s paths it matches\n' \
      "$name" "$(wc -l < "$WORK/loss" | tr -d ' ')"
    exercised=$((exercised + 1))
  done
  if [[ "$exercised" -eq 0 ]]; then
    printf 'FAIL: the probe rule matched nothing in any mover, so aweb-side regressions were never exercised\n' >&2
    exit 1
  fi

  echo "self-test passed: the check goes red, and names the right files, for a lost path, a changed mode, and a new rule on aweb's side"
  echo
fi

echo "checking that every tracked file of each mover arrives intact at its destination in aweb"
status=0
for mover in "${MOVERS[@]}"; do
  IFS=':' read -r src dest ref <<< "$mover"
  name="$(basename "$src")"
  if compare_mover "$src" "$dest" "none" "check-$name" "$ref"; then
    printf '  ok   %-12s -> %-14s %s tracked entries arrive intact\n' "$name" "$dest" "$MOVER_TRACKED"
  else
    status=1
    printf '  LOST %-12s -> %-14s\n' "$name" "$dest"
    sed 's|^|         missing: |' "$WORK/loss"
    sed 's|^|         mode or content changed: |' "$WORK/changed"
  fi
done

if [[ "$status" -ne 0 ]]; then
  echo >&2
  echo "aweb's ignore rules would lose or alter the files listed above." >&2
  echo "Add negations to aweb's .gitignore, or to the mover's, before any history moves." >&2
  exit 1
fi

echo "all movers arrive intact: no file lost to an ignore rule, no mode or content changed"
