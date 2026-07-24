#!/usr/bin/env bash
set -euo pipefail

# Scenario tests for check-server-version-bump.sh (default-aaed).
# Builds scratch git repos and asserts the guard passes/fails per the
# release-model invariant: server/ changes since the last server-v* tag
# require a strictly greater server/pyproject.toml version.

GUARD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-server-version-bump.sh"

if [ ! -x "$GUARD" ]; then
  echo "FAIL: guard script missing or not executable: $GUARD" >&2
  exit 1
fi

failures=0

make_repo() {
  local dir="$1" version="$2"
  git -C "$dir" init -q
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name test
  mkdir -p "$dir/server/src/aweb"
  printf '[project]\nname = "aweb"\nversion = "%s"\n' "$version" > "$dir/server/pyproject.toml"
  echo "print('hello')" > "$dir/server/src/aweb/app.py"
  git -C "$dir" add -A
  git -C "$dir" commit -qm "initial"
  git -C "$dir" tag "server-v$version"
}

set_version() {
  local dir="$1" version="$2"
  printf '[project]\nname = "aweb"\nversion = "%s"\n' "$version" > "$dir/server/pyproject.toml"
}

run_case() {
  local name="$1" expected="$2" dir="$3"
  shift 3
  local rc=0
  (cd "$dir" && "$GUARD" "$@") >/tmp/guard-test-out.txt 2>&1 || rc=$?
  if [ "$expected" = "pass" ] && [ "$rc" -ne 0 ]; then
    echo "FAIL: $name (expected pass, got exit $rc)"; cat /tmp/guard-test-out.txt
    failures=$((failures + 1))
  elif [ "$expected" = "fail" ] && [ "$rc" -eq 0 ]; then
    echo "FAIL: $name (expected fail, got exit 0)"; cat /tmp/guard-test-out.txt
    failures=$((failures + 1))
  else
    echo "ok: $name"
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. No server change since tag: pass.
d="$TMP/clean"; mkdir "$d"; make_repo "$d" 1.0.0
run_case "unchanged server passes" pass "$d"

# 2. Committed server change without bump: fail.
d="$TMP/unbumped"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
git -C "$d" commit -qam "server change, no bump"
run_case "committed change without bump fails" fail "$d"

# 3. Committed server change with committed bump: pass.
d="$TMP/bumped"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.1
git -C "$d" commit -qam "server change with bump"
run_case "committed change with bump passes" pass "$d"

# 4. Committed server change, bump only in working tree (release-check flow): pass.
d="$TMP/wt-bump"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
git -C "$d" commit -qam "server change, no bump yet"
set_version "$d" 1.0.1
run_case "working-tree bump passes" pass "$d"

# 5. Uncommitted server change without bump: fail (release-check runs pre-commit).
d="$TMP/wt-unbumped"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
run_case "uncommitted change without bump fails" fail "$d"

# 6. Version moved backwards with a change: fail.
d="$TMP/backwards"; mkdir "$d"; make_repo "$d" 1.0.1
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.0
git -C "$d" commit -qam "server change, version regressed"
run_case "version regression fails" fail "$d"

# 7. No reachable server-v* tag: fail loudly.
d="$TMP/notag"; mkdir "$d"
git -C "$d" init -q
git -C "$d" config user.email test@example.com
git -C "$d" config user.name test
mkdir -p "$d/server"
printf '[project]\nname = "aweb"\nversion = "1.0.0"\n' > "$d/server/pyproject.toml"
git -C "$d" add -A && git -C "$d" commit -qm "initial, untagged"
run_case "missing server tag fails" fail "$d"

# 8. Multi-digit version ordering (1.0.9 -> 1.0.10 is a valid bump): pass.
d="$TMP/verssort"; mkdir "$d"; make_repo "$d" 1.0.9
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.10
git -C "$d" commit -qam "server change with two-digit patch bump"
run_case "version-sort bump passes" pass "$d"

# Post-tag inherited bump: main already carries an unreleased bump, then a
# later server change lands without its own bump. The tag floor alone
# false-passes this; the change-base comparison must catch it.
make_inherited_repo() {
  local dir="$1"
  mkdir "$dir"; make_repo "$dir" 1.0.0
  echo "print('changed')" > "$dir/server/src/aweb/app.py"
  set_version "$dir" 1.0.1
  git -C "$dir" commit -qam "server change with bump"
  echo "def test_new(): pass" > "$dir/server/tests_test_new.py"
  git -C "$dir" add -A
  git -C "$dir" commit -qm "later server change, no bump"
}

# 9. Inherited bump, checked against the change base: fail.
d="$TMP/inherited"; make_inherited_repo "$d"
run_case "inherited bump fails against change base" fail "$d" HEAD~1

# 10. Change range contains both the server change and its own bump: pass.
d="$TMP/range-bumped"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.1
git -C "$d" commit -qam "server change with bump"
run_case "range with own bump passes" pass "$d" HEAD~1

# 11. Base given but server unchanged in the range (inherited version state,
# non-server commit): pass.
d="$TMP/range-clean"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.1
git -C "$d" commit -qam "server change with bump"
echo "docs" > "$d/README.md"
git -C "$d" add -A
git -C "$d" commit -qm "non-server change"
run_case "range without server change passes" pass "$d" HEAD~1

# 12. Unresolvable base (branch-create push sends all zeros): warn, fall back
# to the tag floor, which is satisfied here.
d="$TMP/zero-base"; mkdir "$d"; make_repo "$d" 1.0.0
echo "print('changed')" > "$d/server/src/aweb/app.py"
set_version "$d" 1.0.1
git -C "$d" commit -qam "server change with bump"
run_case "unresolvable base falls back to tag floor" pass "$d" 0000000000000000000000000000000000000000

if [ "$failures" -ne 0 ]; then
  echo "$failures scenario(s) failed" >&2
  exit 1
fi
echo "All guard scenarios passed."
