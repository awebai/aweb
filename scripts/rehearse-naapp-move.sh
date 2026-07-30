#!/usr/bin/env bash
# Rehearse aweb-aauv.2's three subtree merges in a throwaway clone, and assert the
# two properties that make the real merge safe to perform in one command.
#
# The merge onto aweb main is irreversible: main is the shared sync branch and cannot
# be rewritten. So everything checkable is checked here first, against a clone that
# can be thrown away, and the real operation becomes a rehearsed procedure rather
# than a first attempt.
#
# CRITERION 1, tree equality per mover. After each merge, git ls-tree -r of the
# destination prefix must equal git ls-tree -r of the exact source commit as a set of
# path + mode + blob. Equality is mechanism-independent: it proves nothing was lost
# without depending on how the move was performed, and it catches mode and symlink
# changes - library carries 8 tracked symlinks, all inside golden fixtures whose
# tests compare them byte-exact.
#
# CRITERION 2, the root entry set. After the merges the set of root entries must equal
# the set before plus exactly {naapp, naapp-lib}, with every pre-existing root entry's
# blob unchanged. Stated as an expected set rather than a prohibition on purpose: "no
# new root path" false-fails on the three merges this task performs, and a guard that
# fires on the legitimate operation gets relaxed at the moment it was meant to hold.
# The unchanged-blob clause is what protects aweb's root .gitignore and README.md -
# the two halves of the add/add collision that a root-level aweb-naapp merge would
# resolve by stripping the rules shielding every agent's signing key.
#
# Run with --self-test to exercise both mutation arms required by criterion 2:
# merging aweb-naapp at the repo root must go RED naming .gitignore and README.md,
# and an unexpected root entry must go RED naming it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=scripts/lib/naapp-movers.sh
source "$ROOT/scripts/lib/naapp-movers.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The destinations this task decided. naapp-lib rather than the repo root is a
# security decision, recorded in the shared lib.
EXPECTED_NEW_ROOT_ENTRIES=("naapp" "naapp-lib")

fail() { printf 'FAIL: %s\n' "$1" >&2; return 1; }

# path<TAB>mode<TAB>blob for every entry under a tree, keyed on path and sorted.
# Tab-separated via git's own --format so a path containing a space cannot be misread
# as a field boundary.
tree_index() {
  local repo="$1" ref="$2" prefix="${3:-}"
  if [[ -n "$prefix" ]]; then
    git -C "$repo" ls-tree -r --format='%(path)	%(objectmode)	%(objectname)' "$ref" -- "$prefix" \
      | sed "s|^$prefix/||"
  else
    git -C "$repo" ls-tree -r --format='%(path)	%(objectmode)	%(objectname)' "$ref"
  fi | sort
}

root_index() {
  git -C "$1" ls-tree --format='%(path)	%(objectmode)	%(objectname)' "$2" | sort
}

# A clone of aweb that can be destroyed, with each mover fetched at its pinned ref.
prepare_clone() {
  local clone="$1"
  git clone -q --no-local --single-branch --branch "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)" \
    "$ROOT" "$clone"
  git -C "$clone" config user.email rehearsal@example.invalid
  git -C "$clone" config user.name "naapp move rehearsal"

  local mover src dest ref
  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    local name; name="$(basename "$dest")"
    git -C "$clone" remote add "mover-$name" "$src"
    git -C "$clone" fetch -q "mover-$name" "$ref"
    git -C "$clone" tag "source-$name" FETCH_HEAD
  done < <(naapp_movers)
}

# One subtree merge: history preserved, the tree grafted at a prefix.
subtree_merge() {
  local clone="$1" dest="$2" tag="$3"
  git -C "$clone" merge -q -s ours --no-commit --allow-unrelated-histories "$tag"
  git -C "$clone" read-tree --prefix="$dest/" -u "$tag"
  git -C "$clone" commit -q -m "Merge $dest at $tag"
}

assert_tree_equality() {
  local clone="$1" dest="$2" tag="$3" label="$4"
  tree_index "$clone" "$tag" > "$WORK/$label.source"
  tree_index "$clone" HEAD "$dest" > "$WORK/$label.merged"

  local n; n="$(wc -l < "$WORK/$label.source" | tr -d ' ')"
  if [[ "$n" -eq 0 ]]; then
    fail "$label: the source tree is empty, so equality would hold vacuously"
    return 1
  fi
  if ! diff -u "$WORK/$label.source" "$WORK/$label.merged" > "$WORK/$label.diff"; then
    printf 'FAIL %s: the merged tree at %s does not equal source %s\n' "$label" "$dest" "$tag" >&2
    head -40 "$WORK/$label.diff" >&2
    return 1
  fi
  printf '  ok   %-12s %s entries at %s equal source %s on path, mode and blob\n' \
    "$label" "$n" "$dest" "$(git -C "$clone" rev-parse --short "$tag")"
}

assert_root_entry_set() {
  local clone="$1" before="$2"
  root_index "$clone" HEAD > "$WORK/root.after"

  # Every pre-existing root entry must be byte-identical, including .gitignore and
  # README.md.
  local changed
  changed="$(comm -23 "$before" "$WORK/root.after" || true)"
  if [[ -n "$changed" ]]; then
    printf 'FAIL: pre-existing root entries were modified or removed:\n' >&2
    printf '%s\n' "$changed" | sed 's/^/         /' >&2
    return 1
  fi

  # And the additions must be exactly the expected set.
  local added expected
  added="$(comm -13 <(cut -f1 "$before") <(cut -f1 "$WORK/root.after") | sort)"
  expected="$(printf '%s\n' "${EXPECTED_NEW_ROOT_ENTRIES[@]}" | sort)"
  if [[ "$added" != "$expected" ]]; then
    printf 'FAIL: root additions are not exactly the expected set.\n' >&2
    printf '      expected: %s\n' "$(echo "$expected" | tr '\n' ' ')" >&2
    printf '      actual:   %s\n' "$(echo "$added" | tr '\n' ' ')" >&2
    return 1
  fi
  printf '  ok   root entries are the %s before plus exactly %s, all pre-existing blobs unchanged\n' \
    "$(wc -l < "$before" | tr -d ' ')" "$(echo "$expected" | tr '\n' ' ')"
}

# Rehearse: returns 0 only if both criteria hold. $2 optionally overrides a
# destination, which the self-test uses to point aweb-naapp at the repo root.
rehearse() {
  local clone="$WORK/$1" override_dest="${2:-}"
  prepare_clone "$clone"
  root_index "$clone" HEAD > "$WORK/root.before"

  local mover src dest ref name
  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    name="$(basename "$dest")"
    if [[ -n "$override_dest" && "$dest" == "$NAAPP_LIB_DEST" ]]; then
      dest="$override_dest"
    fi
    if [[ "$dest" == "." || -z "$dest" ]]; then
      # A root-level graft: read-tree with no prefix.
      git -C "$clone" merge -q -s ours --no-commit --allow-unrelated-histories "source-$name"
      git -C "$clone" read-tree -u --reset -m HEAD "source-$name" 2>/dev/null \
        || git -C "$clone" read-tree --prefix= -u "source-$name" 2>/dev/null \
        || git -C "$clone" checkout -q "source-$name" -- .
      git -C "$clone" commit -q -m "Merge $name at the repository root" || true
      continue
    fi
    subtree_merge "$clone" "$dest" "source-$name"
    assert_tree_equality "$clone" "$dest" "source-$name" "$name"
  done < <(naapp_movers)

  assert_root_entry_set "$clone" "$WORK/root.before"
}

if [[ "${1:-}" == "--self-test" ]]; then
  echo "self-test: criterion 2 must reject a root-level aweb-naapp merge, naming the collided files"
  if rehearse "mutation-root" "." > "$WORK/mutation.log" 2>&1; then
    fail "a root-level aweb-naapp merge was accepted; criterion 2 cannot reject the wrong destination"
    cat "$WORK/mutation.log" >&2
    exit 1
  fi
  if ! grep -qE '\.gitignore|README\.md' "$WORK/mutation.log"; then
    fail "the root-level merge was rejected but the red did not name .gitignore or README.md"
    cat "$WORK/mutation.log" >&2
    exit 1
  fi
  printf '  ok   root-level merge rejected, naming: %s\n' \
    "$(grep -oE '\.gitignore|README\.md' "$WORK/mutation.log" | sort -u | tr '\n' ' ')"

  echo "self-test: criterion 2 must reject an unexpected root entry, naming it"
  clone="$WORK/mutation-extra"
  prepare_clone "$clone"
  root_index "$clone" HEAD > "$WORK/root.before"
  echo "unexpected" > "$clone/an-unexpected-root-file"
  git -C "$clone" add an-unexpected-root-file
  git -C "$clone" commit -q -m "an unexpected root entry"
  if assert_root_entry_set "$clone" "$WORK/root.before" > "$WORK/extra.log" 2>&1; then
    fail "an unexpected root entry was accepted"
    exit 1
  fi
  if ! grep -q 'an-unexpected-root-file' "$WORK/extra.log"; then
    fail "the unexpected root entry was rejected but the red did not name it"
    cat "$WORK/extra.log" >&2
    exit 1
  fi
  printf '  ok   an unexpected root entry is rejected and named\n'
  echo "self-test passed: criterion 2 rejects both the wrong destination and an unexpected root entry"
  echo
fi

echo "rehearsing the three subtree merges in a throwaway clone"
rehearse "rehearsal"
echo
echo "rehearsal complete: every mover's tree is intact at its destination and aweb's root is unchanged"
