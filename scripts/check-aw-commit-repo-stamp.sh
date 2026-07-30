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

# The repository the binary will claim its commit resolves in.
stamped="$(grep -oE '\-X main\.commitRepo=[^[:space:]]+' "$GORELEASER" | head -1 | sed 's/^-X main\.commitRepo=//' || true)"

if [[ -z "$push_target" ]]; then
  printf 'FAIL: no sync target found in %s.\n' "$WORKFLOW" >&2
  printf '      This check reads the push target from that file; if the sync moved, point it at the new one.\n' >&2
  exit 1
fi

if [[ -z "$stamped" ]]; then
  printf 'FAIL: no -X main.commitRepo stamp found in %s.\n' "$GORELEASER" >&2
  printf '      Without it `aw version` prints a bare commit that resolves in no repository a\n' >&2
  printf '      reader has, which is aweb-aaun.7.\n' >&2
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
