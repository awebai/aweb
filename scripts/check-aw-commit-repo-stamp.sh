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

# EVERY build block must say which repository its commit resolves in - not just aw.
#
# Every build in THIS file is produced by the one goreleaser run inside the synced clone,
# so every one of them resolves in the sync target and the same answer is right for all.
# Enumerating rather than naming `aw` is about coverage, not about differing answers:
# whoever adds a third build gets a signal instead of a guard that keeps quietly passing.
#
# A binary built somewhere else is a separate question with a separate answer - the
# gateway image is built from aweb by its own workflow and correctly names aweb. That
# path is stamped in its own files and is not what this file governs.
#
# Comments neither CLOSE a block nor SUPPLY a stamp. Excluding them from only one of those
# roles is a defect in whichever direction is left: closing on them ends a block early and
# refuses a stamp that is present; letting them supply means a commented-out stamp
# satisfies the check. Both were measured on the earlier aw-only form (aweb-aaun.7).
blocks="$(awk '
  /^builds:[[:space:]]*$/ { inbuilds = 1; next }
  /^[[:space:]]*#/        { next }
  /^[^ ]/                 { if (inbuilds && id != "") { print id "\t" stamp; id = "" } inbuilds = 0; next }
  !inbuilds               { next }
  /^  - id: /             { if (id != "") print id "\t" stamp; id = substr($0, 9); stamp = ""; next }
  /-X main\.commitRepo=/  { s = $0; sub(/.*-X main\.commitRepo=/, "", s); sub(/[[:space:]].*/, "", s); stamp = s }
  END                     { if (id != "") print id "\t" stamp }
' "$GORELEASER")"

if [[ -z "$blocks" ]]; then
  printf 'FAIL: no build blocks found under builds: in %s.\n' "$GORELEASER" >&2
  printf '      This check enumerates every build and asks each which repository its commit\n' >&2
  printf '      resolves in. Finding none means the file shape changed, not that all builds pass.\n' >&2
  exit 1
fi

if [[ -z "$push_target" ]]; then
  printf 'FAIL: no sync target found in %s.\n' "$WORKFLOW" >&2
  printf '      This check reads the push target from that file; if the sync moved, point it at the new one.\n' >&2
  exit 1
fi

rc=0
covered=""
while IFS=$'\t' read -r id stamp; do
  [[ -n "$id" ]] || continue
  covered="$covered $id"
  if [[ -z "$stamp" ]]; then
    printf 'FAIL: build %s carries no -X main.commitRepo stamp in %s.\n' "$id" "$GORELEASER" >&2
    printf '      Its binary would print a commit that resolves in no repository a reader has,\n' >&2
    printf '      which is aweb-aaun.7. A commented-out stamp does not count as one.\n' >&2
    rc=1
    continue
  fi
  if [[ "$stamp" != "$push_target" ]]; then
    printf 'FAIL: build %s names a different repository than the sync pushes to.\n' "$id" >&2
    printf '      sync pushes to : %s   (%s)\n' "$push_target" "${WORKFLOW#"$ROOT"/}" >&2
    printf '      binary claims  : %s   (%s)\n' "$stamp" "${GORELEASER#"$ROOT"/}" >&2
    rc=1
  fi
done <<< "$blocks"

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi

printf 'ok   every build names %s:%s\n' "$push_target" "$covered"
