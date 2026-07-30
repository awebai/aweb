#!/usr/bin/env bash
# The repositories moving into aweb for epic aweb-aauv, and the ref facts every
# check of that move has to agree about.
#
# Sourced by scripts/check-naapp-move-addable.sh and
# scripts/check-naapp-move-images.sh so the two cannot disagree about which
# commit is being moved. A comment claiming a ref is the pinned one is true only
# by coincidence; the assertion below makes it true by construction.

# Source repo : destination path inside aweb : source ref.
#
# The ref is origin/main rather than the checkout's HEAD on purpose. A local
# checkout is not a reliable source: aweb-naapp's local main sits behind the
# commit both live services build on, and its checked-out branch is a third ref
# again, so reading HEAD would measure whichever branch someone last looked at.
#
# aweb-naapp's destination is naapp-lib/, decided in aweb-aauv as a security
# decision rather than a layout preference: at the aweb root its .gitignore
# collides with aweb's own, and a merge resolving toward it drops the
# /agents/instances/ rule that keeps every agent's signing key out of git.
#
# That destination is also the key identifying the aweb-naapp mover below, because
# a source directory name is not stable: every mover path is overridable by
# environment variable, so a checkout can sit under any name.
NAAPP_LIB_DEST="naapp-lib"

naapp_movers() {
  local siblings="${AWEB_SIBLING_REPOS:-$HOME/prj/awebai}"
  printf '%s\n' \
    "${AWEB_LIBRARY_REPO:-$siblings/library}:naapp/library:origin/main" \
    "${AWEB_FOLIO_REPO:-$siblings/folio}:naapp/folio:origin/main" \
    "${AWEB_NAAPP_REPO:-$siblings/aweb-naapp}:$NAAPP_LIB_DEST:origin/main"
}

# Pre-move test baselines for aweb-aauv.2 criterion 4, recorded before the first
# merge because the criterion compares two recorded numbers and after the merge the
# only tree left to read is the one under test.
#
# destination | source commit measured | command | expected tally
#
# The source commit is part of the baseline, not decoration: if a mover's origin/main
# has moved past the commit these numbers were taken at, the counts describe a
# different tree and comparing them silently measures the wrong thing.
#
# The command is recorded because a similar command is not the same measurement.
# library deselects its e2e tests. folio's default make target used to be the wrong
# command here - it resolved awid and pgdbm through sibling-relative paths and ran a
# bare python3 that never used the locked environment. Both are repaired, so
# `make test` and `uv run pytest -q` are now the same measurement.
#
# ONCE THE MOVE HAS LANDED THESE ROWS CHANGE MEANING, and the folio row already has.
# Before the merge they compared a pre-move tree against a post-move one, which is what
# criterion 4 needed. Afterwards the moved tree evolves on its own, so a row records the
# CURRENT expected tally of the tree in this repository - still able to catch a loss, no
# longer evidence about the move. The pre-move verification is historical and recorded on
# aweb-aauv.2: library 468/17 and folio 168/16, both from a fresh clone of the merge.
#
# So a divergence here now means "this tree changed", not "the move lost something", and
# whoever changes a mover's tests is the one who updates its row.
#
# THESE NUMBERS ARE INHERENTLY PERISHABLE AND UPDATING ONE IS A STOPGAP, NOT A FIX. An
# absolute count against a tree that is still being worked on goes stale on any legitimate
# test addition. The library row went stale within hours of the move, from ordinary work by
# two people, and it will do so again. Bumping it clears a false red, which is a real job -
# but it is a different job from making the check correct, and it must not be mistaken for
# one.
#
# Two hazards follow, and both are easy to walk into while doing the obviously-right thing:
#
#   RE-BASELINING TO THE MEASURED VALUE IS SELF-CONFIRMING. Writing down whatever the run
#   just reported makes the row assert that the tree is what it was last observed to be,
#   which is not a property and cannot fail for the reason the row exists. A row is evidence
#   only when the expected value is derived independently of the run being checked - from a
#   diff, from a count of added tests - and not from the failing output.
#
#   A COUNT ABSORBS OFFSETTING CHANGES. Remove three tests and add three and the row stays
#   green through a real deletion. This has already happened here: one commit removed an
#   assertion and added four, and only the net reached the number, so the removal was
#   invisible to this table.
#
# A count also cannot answer whether a moved subtree has DIVERGED FROM ITS SOURCE, which is
# a different question from whether it changed. Blob shas are content-addressed and compare
# directly across repositories, so that question is answered by a tree diff against the
# sibling remote at its current head - not by this table, and not by tree equality against a
# frozen merge parent, which cannot fail. Whether anything needs to answer it is open on
# aweb-aauv.4.
#
# ONE CONSEQUENCE FOR THE SECOND FIELD: it is now PROVENANCE, not a binding. It records the
# commit the pre-move verification was taken at, and assert_baseline_ref still checks the
# mover carries it - but passing that check no longer says anything about whether the tally
# is right, because the tally describes this repository's tree rather than that ref's. Do
# not read a passing ref assertion as confirming the number.
#
# aweb-naapp has no row on purpose. Both movers install it from git rather than from
# naapp-lib/, so nothing in this task executes the moved copy; its first execution
# belongs to the path-source conversion task.
naapp_parity_baselines() {
  printf '%s\n' \
    "naapp/library|833b4de6a9e9|uv run pytest -q -m \"not e2e\"|passed=471 deselected=17" \
    "naapp/folio|44e620f68425|uv run pytest -q|passed=171 skipped=16"
}

# Every mover must exist, carry the ref being moved, and not carry export-ignore.
#
# A missing mover fails rather than skips: a skipped mover reads as a proven one.
naapp_require_movers() {
  local mover src dest ref
  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    if [[ ! -d "$src/.git" ]]; then
      printf 'FAIL: mover repository not found at %s\n' "$src" >&2
      printf '      set AWEB_SIBLING_REPOS, or the per-repo override, to the checkout root.\n' >&2
      return 1
    fi
    if ! git -C "$src" rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
      printf 'FAIL: %s has no ref %s to move\n' "$src" "$ref" >&2
      return 1
    fi
    # A check that reads one side with ls-tree and the other with git archive
    # would report an export rule as a lost file, because archive honors
    # export-ignore and ls-tree does not.
    if git -C "$src" ls-tree -r --name-only "$ref" | grep -q '\.gitattributes$'; then
      if git -C "$src" grep -q 'export-ignore' "$ref" -- '*.gitattributes' 2>/dev/null; then
        printf 'FAIL: %s carries export-ignore in .gitattributes at %s.\n' "$src" "$ref" >&2
        printf '      git archive honors it and ls-tree does not, so a tree comparison would\n' >&2
        printf '      report an export rule as a lost file. Read both sides the same way first.\n' >&2
        return 1
      fi
    fi
  done < <(naapp_movers)
}

# The aweb-naapp commit being moved must be the one both live services pin.
#
# A different but coherent aweb-naapp loses no files and builds fine, so every
# other check here would still pass while the shared library both live services
# depend on moved underneath them.
naapp_assert_pin_agreement() {
  local mover src dest ref naapp_src="" naapp_ref="" moving pin pins=()

  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    if [[ "$dest" == "$NAAPP_LIB_DEST" ]]; then
      naapp_src="$src"; naapp_ref="$ref"
    fi
  done < <(naapp_movers)

  if [[ -z "$naapp_src" ]]; then
    printf 'FAIL: no aweb-naapp mover in the table; the pin cannot be checked\n' >&2
    return 1
  fi
  moving="$(git -C "$naapp_src" rev-parse "$naapp_ref^{commit}")"

  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    [[ "$dest" == "$NAAPP_LIB_DEST" ]] && continue
    pin="$(git -C "$src" show "$ref:pyproject.toml" \
      | sed -n 's/.*aweb-naapp[[:space:]]*=[[:space:]]*{.*rev[[:space:]]*=[[:space:]]*"\([0-9a-f]\{7,40\}\)".*/\1/p' \
      | head -1)"
    if [[ -z "$pin" ]]; then
      printf 'FAIL: no aweb-naapp git pin found in %s at %s; cannot confirm which commit production builds on\n' \
        "$src" "$ref" >&2
      return 1
    fi
    pins+=("$(basename "$src")=$pin")
    if [[ "$moving" != "$pin"* ]]; then
      printf 'FAIL: the aweb-naapp commit being moved is not the one %s pins.\n' "$(basename "$src")" >&2
      printf '      moving %s (%s)\n      pinned %s\n' "$moving" "$naapp_ref" "$pin" >&2
      return 1
    fi
  done < <(naapp_movers)

  printf 'aweb-naapp: moving %s, which matches both pins (%s)\n' "${moving:0:12}" "${pins[*]}"
}
