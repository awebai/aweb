#!/usr/bin/env bash
set -euo pipefail

# Scenario self-test for check-release-tag-monotonic.sh (aweb-aaun.3).
#
# Every case here has been RUN RED before being written down. A guard that has
# never been shown to refuse is what aaun.3 exists to replace, so the refusal
# cases are the point and the passes are the control.
#
# The fixture uses a real bare remote and includes an ANNOTATED tag on purpose:
# `git ls-remote --tags` emits a peeled `refs/tags/X^{}` line for annotated tags
# and none for lightweight ones, so a fixture built only from lightweight tags
# never exercises the de-peeling and the bug stays invisible.

GUARD="$(cd "$(dirname "$0")" && pwd)/check-release-tag-monotonic.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

expect_refuse() {
  local label="$1"; shift
  if (cd "$WORK/work" && "$GUARD" "$@") >/dev/null 2>&1; then
    fail "$label - guard ADMITTED it; it must refuse"
  fi
  echo "  refused: $label"
}

expect_admit() {
  local label="$1"; shift
  if ! (cd "$WORK/work" && "$GUARD" "$@") >/dev/null 2>&1; then
    fail "$label - guard REFUSED it; it must admit"
  fi
  echo "  admitted: $label"
}

git init -q --bare "$WORK/remote.git"
git init -q "$WORK/work"
(
  cd "$WORK/work"
  git config user.email test@example.com
  git config user.name test
  echo x > f && git add -A && git commit -qm c1
  git remote add origin "$WORK/remote.git"
  git push -q origin HEAD:main
  git tag server-v0.9.0                              # lightweight
  git tag -a server-v0.10.0 -m "annotated"           # annotated -> peeled ref
  git push -q origin --tags
)

echo "Scenario: predecessors exist on the remote (0.9.0 lightweight, 0.10.0 annotated)"

# The lexical trap, both directions. A shell string compare gets BOTH wrong:
# "0.9.0" > "0.10.0" is true as strings and false as versions.
expect_refuse "regression 0.10.0 -> 0.9.0 (string compare would ADMIT this)" \
  server-v server-v0.9.0
expect_admit  "bump 0.10.0 -> 0.11.0 (string compare would REFUSE this)" \
  server-v server-v0.11.0

# The peeled annotated tag must be the resolved predecessor, de-peeled.
expect_refuse "regression against an ANNOTATED predecessor" server-v server-v0.9.5
expect_admit  "bump past an ANNOTATED predecessor"          server-v server-v0.13.0

# Malformed input is refused rather than defaulted.
expect_refuse "tag with no version after the prefix" server-v server-v
expect_refuse "tag not matching the prefix"          server-v awid-v1.0.0

# "Could not ask" must never read as "nothing there".
expect_refuse "unreachable remote is a refusal, not a bootstrap" \
  server-v server-v9.9.9 /nonexistent-remote-path

echo "Scenario: no predecessor anywhere"
git init -q --bare "$WORK/empty.git"
(
  cd "$WORK/work"
  git remote add empty "$WORK/empty.git"
  git push -q empty HEAD:main
)
expect_refuse "first release WITHOUT the explicit input" server-v server-v1.0.0 empty
if ! (cd "$WORK/work" && ALLOW_FIRST_RELEASE=1 "$GUARD" server-v server-v1.0.0 empty) >/dev/null 2>&1; then
  fail "first release WITH ALLOW_FIRST_RELEASE=1 - guard refused; it must admit"
fi
echo "  admitted: first release WITH the explicit input"

echo "OK: check-release-tag-monotonic.sh refuses every case it must and admits every case it must."
