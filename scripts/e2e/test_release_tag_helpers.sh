#!/usr/bin/env bash
# Executes remote_tag_sha from scripts/release-tag-helpers.sh against a real
# bare remote: lightweight and annotated tags must both resolve to the
# commit, and an absent tag must print empty. No network.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0
fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

tmp="$(mktemp -d)"
trap 'command rm -rf "$tmp"' EXIT
git init -q --bare "$tmp/remote.git"
git init -q "$tmp/work"
cd "$tmp/work"
git -c user.email=t@t -c user.name=t commit -q --allow-empty -m x
sha="$(git rev-parse HEAD)"
git remote add origin "$tmp/remote.git"
git push -q origin HEAD:main
git tag light "$sha" && git push -q origin refs/tags/light
git -c user.email=t@t -c user.name=t tag -a -m note heavy "$sha" && git push -q origin refs/tags/heavy

source "$ROOT/scripts/release-tag-helpers.sh"
[[ "$(remote_tag_sha light)" == "$sha" ]] || fail "lightweight tag did not resolve to the commit"
ok "lightweight tag resolves to the commit"
[[ "$(remote_tag_sha heavy)" == "$sha" ]] || fail "annotated tag did not peel to the commit"
ok "annotated tag peels to the commit"
[[ -z "$(remote_tag_sha absent)" ]] || fail "absent tag printed something"
ok "absent tag prints empty"
printf 'SELFTEST OK: %d assertions\n' "$PASS"
