#!/usr/bin/env bash
set -euo pipefail

# Release-tag monotonicity guard (aweb-aaun.3): a release tag may not publish a
# version that is not strictly newer than the highest version any prior tag of
# that surface carries.
#
# This is NOT the question check-server-version-bump.sh asks. That one asks
# "did this server/ change carry a version bump" - a change-time question, asked
# correctly by server-ci.yml on push and pull request. At a tag it cannot help:
# HEAD is the tag, so every comparison it makes is against itself.
#
# THE PREDECESSOR IS RESOLVED FROM THE REMOTE, NEVER FROM LOCAL TAGS. A local
# ref store is a partial view: a depth-1 checkout - which is what the release
# job gets from actions/checkout with no fetch-depth - sees zero tags, and even
# a normally-fetched worktree was measured at 94 against the remote's 106. A
# guard that reads local tags can therefore compare against a predecessor lower
# than the true highest and admit exactly the regression it exists to stop.
#
# The comparison is over TAG NAMES rather than each tag's manifest. Sound
# because the release workflow already refuses a tag whose name disagrees with
# the manifest at that commit, and measured: across all 94 server-v* tags
# reachable locally the name and server/pyproject.toml agree, 0 mismatches. It
# is also the more conservative reading - a tag that exists but never published
# still blocks a later tag from going backwards past it.
#
# Ordering uses packaging.version.Version, which is how PyPI itself orders
# releases. A shell string compare is wrong in both directions and silently:
# "0.9.0" > "0.10.0" is true as strings and false as versions, so a lexical
# guard admits the regression it exists to stop.
#
# THREE STATES, and they must not share a branch:
#   remote has prior tags          compare; refuse unless strictly newer
#   remote answered, has none      genuine first release; requires an explicit,
#                                  logged ALLOW_FIRST_RELEASE=1
#   remote could not be asked      REFUSE. "Could not ask" is not "nothing
#                                  there", and it is the state that most
#                                  resembles an empty result.
#
# Usage: check-release-tag-monotonic.sh <tag-prefix> <tag> [remote]
#   e.g. check-release-tag-monotonic.sh server-v "$GITHUB_REF_NAME"

PREFIX="${1:?usage: check-release-tag-monotonic.sh <tag-prefix> <tag> [remote]}"
TAG="${2:?usage: check-release-tag-monotonic.sh <tag-prefix> <tag> [remote]}"
REMOTE="${3:-origin}"

case "$TAG" in
  "$PREFIX"*) ;;
  *) echo "ERROR: tag '$TAG' does not start with prefix '$PREFIX'." >&2; exit 1 ;;
esac

NEW_VERSION="${TAG#"$PREFIX"}"
if [ -z "$NEW_VERSION" ]; then
  echo "ERROR: tag '$TAG' carries no version after prefix '$PREFIX'." >&2
  exit 1
fi

# Authoritative predecessor set. ls-remote exits 0 when it matches nothing, so
# a zero exit means the question was answered - not that tags exist.
# --refs drops the peeled `refs/tags/X^{}` entry git emits for every annotated
# tag. The `^{}` strip below is a fallback for git versions without --refs; it
# is deliberately belt-and-braces because a peeled name reaching the version
# parser is unparseable, and how an implementation handles that is a choice
# nobody should have to make.
REMOTE_ERR="$(mktemp)"
trap 'rm -f "$REMOTE_ERR"' EXIT
if ! REMOTE_REFS="$(git ls-remote --tags --refs "$REMOTE" "refs/tags/${PREFIX}*" 2>"$REMOTE_ERR")"; then
  echo "ERROR: could not ask $REMOTE for ${PREFIX}* tags." >&2
  sed 's/^/  /' "$REMOTE_ERR" >&2
  echo "A failed query is not an empty result. Refusing to publish." >&2
  exit 1
fi

PRIOR="$(
  printf '%s\n' "$REMOTE_REFS" \
    | sed -n 's#.*refs/tags/##p' \
    | sed 's/\^{}$//' \
    | sort -u \
    | grep -vxF "$TAG" || true
)"

if [ -z "$PRIOR" ]; then
  if [ "${ALLOW_FIRST_RELEASE:-}" != "1" ]; then
    echo "ERROR: $REMOTE has no ${PREFIX}* tag other than $TAG, so there is no predecessor." >&2
    echo "If this is genuinely the first release of this surface, set ALLOW_FIRST_RELEASE=1" >&2
    echo "deliberately for this run. Absence of a predecessor is never permission by default." >&2
    exit 1
  fi
  echo "BOOTSTRAP: $REMOTE carries no other ${PREFIX}* tag and ALLOW_FIRST_RELEASE=1 was set."
  echo "OK: publishing $TAG as the first release of this surface."
  exit 0
fi

# Highest prior version wins, not the most recent by ancestry: a tag reachable
# from an older commit can still carry a higher version, and going backwards
# past it is the harm.
# The prefix is stripped in python with a literal string operation. Doing it
# with `sed "s/^${PREFIX}//"` would interpolate the prefix into a regex, where a
# metacharacter in a future prefix - a `.` matching any character - would strip
# the wrong thing silently.
HIGHEST_PRIOR="$(
  printf '%s\n' "$PRIOR" \
    | uv run --quiet --with packaging python3 -c '
import sys
from packaging.version import InvalidVersion, Version
prefix = sys.argv[1]
best = None
for line in sys.stdin:
    raw = line.strip()
    if not raw or not raw.startswith(prefix):
        continue
    raw = raw[len(prefix):]
    try:
        v = Version(raw)
    except InvalidVersion:
        continue
    if best is None or v > best[0]:
        best = (v, raw)
print(best[1] if best else "")
' "$PREFIX"
)"

if [ -z "$HIGHEST_PRIOR" ]; then
  echo "ERROR: $REMOTE has ${PREFIX}* tags but none carried a parseable version." >&2
  echo "Refusing to publish rather than treating unreadable predecessors as absent." >&2
  exit 1
fi

if uv run --quiet --with packaging python3 -c '
import sys
from packaging.version import InvalidVersion, Version
try:
    new, prior = Version(sys.argv[1]), Version(sys.argv[2])
except InvalidVersion as exc:
    sys.stderr.write("ERROR: unparseable version: %s\n" % exc)
    sys.exit(2)
sys.exit(0 if new > prior else 1)
' "$NEW_VERSION" "$HIGHEST_PRIOR"; then
  echo "OK: $TAG publishes $NEW_VERSION, strictly newer than the highest tag on $REMOTE (${PREFIX}${HIGHEST_PRIOR})."
  exit 0
fi

echo "ERROR: $TAG would publish $NEW_VERSION, which is NOT strictly newer than ${PREFIX}${HIGHEST_PRIOR} on $REMOTE." >&2
echo "A release tag may only move this surface's version forward. Refusing to publish." >&2
exit 1
