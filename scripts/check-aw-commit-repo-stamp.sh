#!/usr/bin/env bash
# aweb-aaun.7: `aw version` prints a commit that resolves only in the repository the
# release is built from, so the output names that repository. This asserts the name it
# prints is the repository the sync actually pushes to.
#
# The failure this prevents is silent: change the sync target and leave the stamp, and
# every shipped binary then names a repository its commit does not exist in - which is
# the original defect wearing a different hash. Nothing else would notice, because the
# build succeeds and the output looks well-formed.
#
# Both values are read from the files that decide them rather than restated here, so
# this cannot pass by agreeing with a copy of itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/aw-release.yml"
GORELEASER="$ROOT/cli/go/.goreleaser.yaml"

for f in "$WORKFLOW" "$GORELEASER"; do
  if [[ ! -f "$f" ]]; then
    printf 'FAIL: %s is missing, so the stamp cannot be checked against the sync target.\n' "$f" >&2
    exit 1
  fi
done

# Both extractions tolerate no-match on purpose. Under `set -o pipefail` a grep that
# finds nothing fails the whole pipeline and `set -e` would end the script HERE - exit 1
# with no output, before the checks below that say which value is missing and why it
# matters. Failing closed is right; failing closed silently is not.
#
# The repository the sync clones and pushes to.
push_target="$(grep -oE 'github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git' "$WORKFLOW" | head -1 | sed 's/\.git$//' || true)"

# The repository the AW BINARY will claim its commit resolves in.
#
# Bounded to the aw build block rather than read from the whole file. Reading the file
# and taking the first match passes while the stamp sits on a DIFFERENT binary's block:
# aw then ships a bare hash and this check affirms, by name, the property it no longer
# has. That is not hypothetical - aweb-a2a-gw is filed to gain its own commitRepo, and
# the moment it does, a file-wide read becomes an ordering accident.
#
# The anchor is exact because "- id: aw" is a prefix of "- id: aweb-a2a-gw".
#
# The block ends at the next build id OR at any unindented line - a top-level key such as
# archives:. Closing only on the next id is not the safe direction: with aw LAST and nothing
# matching "  - id: " after it, the extraction runs to end of file, and a commitRepo-shaped
# line anywhere below then satisfies a check on a block that does not contain one. That is
# this guard's own defect reintroduced through the boundary rather than through the anchor,
# and it was measured rather than argued.
aw_block="$(awk '/^  - id: aw$/{inblock=1; next} /^  - id: /{inblock=0} /^[^ ]/{inblock=0} inblock' "$GORELEASER")"

if [[ -z "$aw_block" ]]; then
  printf 'FAIL: no "- id: aw" build block found in %s.\n' "$GORELEASER" >&2
  printf '      This check reads the stamp from that block specifically, so it will not fall back\n' >&2
  printf '      to a file-wide search that could match another binary.\n' >&2
  exit 1
fi

stamped="$(printf '%s\n' "$aw_block" | grep -oE '\-X main\.commitRepo=[^[:space:]]+' | head -1 | sed 's/^-X main\.commitRepo=//' || true)"

if [[ -z "$push_target" ]]; then
  printf 'FAIL: no sync target found in %s.\n' "$WORKFLOW" >&2
  printf '      This check reads the push target from that file; if the sync moved, point it at the new one.\n' >&2
  exit 1
fi

if [[ -z "$stamped" ]]; then
  printf 'FAIL: no -X main.commitRepo stamp in the "- id: aw" build block of %s.\n' "$GORELEASER" >&2
  printf '      Without it `aw version` prints a bare commit that resolves in no repository a\n' >&2
  printf '      reader has, which is aweb-aaun.7.\n' >&2
  printf '      NOTE: the stamp may exist elsewhere in this file and still fail here - it is only\n' >&2
  printf '      read from the aw block, because a stamp on another binary does nothing for aw.\n' >&2
  exit 1
fi

if [[ "$push_target" != "$stamped" ]]; then
  printf 'FAIL: the version stamp names a different repository than the sync pushes to.\n' >&2
  printf '      sync pushes to : %s   (%s)\n' "$push_target" "${WORKFLOW#"$ROOT"/}" >&2
  printf '      binary claims  : %s   (%s)\n' "$stamped" "${GORELEASER#"$ROOT"/}" >&2
  printf '      Every binary built from this release would name a repository its commit is not in.\n' >&2
  exit 1
fi

printf 'ok   aw version names %s, which is where the sync pushes\n' "$stamped"
