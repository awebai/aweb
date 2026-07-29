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

SIBLINGS="${AWEB_SIBLING_REPOS:-$HOME/prj/awebai}"

# Source repo : destination path inside aweb : source ref, from epic aweb-aauv.
#
# The ref is origin/main rather than the checkout's HEAD on purpose. A local
# checkout is not a reliable source: aweb-naapp's local main sits behind the
# commit both live services build on, and its checked-out branch is a third ref
# again, so reading HEAD would measure whichever branch someone last looked at.
#
# aweb-naapp's destination inside aweb is not yet decided. It is checked at the
# candidate path below, and the result does not depend on that choice: none of
# its tracked files match an aweb ignore rule at any candidate path.
MOVERS=(
  "${AWEB_LIBRARY_REPO:-$SIBLINGS/library}:naapp/library:origin/main"
  "${AWEB_FOLIO_REPO:-$SIBLINGS/folio}:naapp/folio:origin/main"
  "${AWEB_NAAPP_REPO:-$SIBLINGS/aweb-naapp}:naapp-lib:origin/main"
)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A scratch repository carrying aweb's ignore rules and nothing else, so the
# comparison measures the destination's rules rather than aweb's own contents.
build_scratch() {
  local scratch="$1" ignore_file
  mkdir -p "$scratch"
  git -C "$scratch" init -q .
  git -C "$scratch" config core.fileMode true
  git -C "$scratch" config core.autocrlf false

  while IFS= read -r ignore_file; do
    mkdir -p "$scratch/$(dirname "$ignore_file")"
    cp -f "$ROOT/$ignore_file" "$scratch/$ignore_file"
  done < <(git -C "$ROOT" ls-files '*.gitignore' '.gitignore')

  # A silent copy failure would leave the scratch repo with no rules at all,
  # and an empty rule set passes every comparison for the wrong reason.
  if [[ ! -s "$scratch/.gitignore" ]]; then
    printf 'FAIL: scratch repo has no root .gitignore; aweb ignore rules were not applied\n' >&2
    return 1
  fi
}

# The (mode, blob, path) triples a mover carries at $ref.
mover_index() {
  git -C "$1" ls-tree -r "$2" | awk '{printf "%s %s %s\n", $1, $3, $4}' | sort
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
  git -C "$scratch" ls-files -s -- "$dest" \
    | awk -v d="$dest/" '{sub("^" d, "", $4); printf "%s %s %s\n", $1, $2, $4}' \
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
root_rule_casualties() {
  local src="$1" dest="$2" ref="$3"
  git -C "$src" ls-tree -r --name-only "$ref" \
    | sed "s|^|$dest/|" \
    | git -C "$ROOT" check-ignore --no-index --stdin \
    | sed "s|^$dest/||" \
    | sort
}

# Writes the missing and changed paths to $WORK/loss; returns 1 on any difference.
compare_mover() {
  local src="$1" dest="$2" mutate="$3" label="$4" ref="$5"
  local scratch="$WORK/$label"
  local expected="$WORK/$label.expected" actual="$WORK/$label.actual"

  build_scratch "$scratch"
  mover_index "$src" "$ref" > "$expected"
  placed_index "$src" "$dest" "$scratch" "$mutate" "$ref" > "$actual"

  local n_expected
  n_expected="$(wc -l < "$expected" | tr -d ' ')"
  if [[ "$n_expected" -eq 0 ]]; then
    printf 'FAIL: %s tracks no files; the comparison would pass vacuously\n' "$src" >&2
    return 2
  fi
  MOVER_TRACKED="$n_expected"

  # comm and join both require input ordered by the path key, and $expected and
  # $actual are ordered by mode and blob.
  awk '{print $3, $1, $2}' "$expected" | sort > "$WORK/by-path.expected"
  awk '{print $3, $1, $2}' "$actual" | sort > "$WORK/by-path.actual"

  comm -23 <(cut -d' ' -f1 "$WORK/by-path.expected") <(cut -d' ' -f1 "$WORK/by-path.actual") > "$WORK/loss"
  join -j 1 "$WORK/by-path.expected" "$WORK/by-path.actual" \
    | awk '$2 != $4 || $3 != $5 {print $1}' > "$WORK/changed"

  [[ ! -s "$WORK/loss" && ! -s "$WORK/changed" ]]
}

for mover in "${MOVERS[@]}"; do
  IFS=':' read -r src dest ref <<< "$mover"
  if [[ ! -d "$src/.git" ]]; then
    printf 'FAIL: mover repository not found at %s\n' "$src" >&2
    printf '      set AWEB_SIBLING_REPOS, or the per-repo override, to the checkout root.\n' >&2
    printf '      A missing mover fails rather than skips: a skipped mover reads as a proven one.\n' >&2
    exit 1
  fi
  if ! git -C "$src" rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
    printf 'FAIL: %s has no ref %s to move\n' "$src" "$ref" >&2
    exit 1
  fi
done

# Both live services build on one pinned aweb-naapp commit. The move must carry
# that commit: a mover ref that resolves elsewhere downgrades or upgrades the
# shared library under both services, and every other check here still passes,
# because a different but coherent aweb-naapp loses no files.
naapp_src="$(IFS=':' read -r s _ _ <<< "${MOVERS[2]}"; echo "$s")"
naapp_ref="$(IFS=':' read -r _ _ r <<< "${MOVERS[2]}"; echo "$r")"
naapp_moving="$(git -C "$naapp_src" rev-parse "$naapp_ref^{commit}")"
pins=()
for mover in "${MOVERS[0]}" "${MOVERS[1]}"; do
  IFS=':' read -r src _ ref <<< "$mover"
  pin="$(git -C "$src" show "$ref:pyproject.toml" \
    | sed -n 's/.*aweb-naapp[[:space:]]*=[[:space:]]*{.*rev[[:space:]]*=[[:space:]]*"\([0-9a-f]\{7,40\}\)".*/\1/p' | head -1)"
  if [[ -z "$pin" ]]; then
    printf 'FAIL: no aweb-naapp git pin found in %s at %s; this check cannot confirm which commit production builds on\n' "$src" "$ref" >&2
    exit 1
  fi
  pins+=("$(basename "$src")=$pin")
  if [[ "$naapp_moving" != "$pin"* ]]; then
    printf 'FAIL: the aweb-naapp commit being moved is not the one %s pins.\n' "$(basename "$src")" >&2
    printf '      moving %s (%s)\n      pinned %s\n' "$naapp_moving" "$naapp_ref" "$pin" >&2
    exit 1
  fi
done
printf 'aweb-naapp: moving %s, which matches both pins (%s)\n\n' "${naapp_moving:0:12}" "${pins[*]}"

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

  echo "self-test passed: the check goes red, and names the right files, for both a lost path and a changed mode"
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
