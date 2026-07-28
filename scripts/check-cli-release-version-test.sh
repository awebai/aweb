#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAKEFILE="$ROOT/Makefile"
VERSION_TOOL="$ROOT/scripts/cli-release-version.sh"

failures=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

make_repo() {
  local work="$1" bare="$2" server_version="$3" cli_version="$4"
  git init --bare -q "$bare"
  git init -q "$work"
  git -C "$work" config user.email test@example.com
  git -C "$work" config user.name test
  git -C "$work" remote add origin "$bare"
  mkdir -p "$work/server" "$work/awid" "$work/scripts"
  printf '[project]\nname = "aweb"\nversion = "%s"\n' "$server_version" > "$work/server/pyproject.toml"
  printf '[project]\nname = "awid-service"\nversion = "0.0.0"\n' > "$work/awid/pyproject.toml"
  ln -s "$VERSION_TOOL" "$work/scripts/cli-release-version.sh"
  printf 'include %s\nprint-cli-version:\n\t@echo $(CLI_VERSION)\n' "$MAKEFILE" > "$work/TestMakefile"
  git -C "$work" add server/pyproject.toml
  git -C "$work" commit -qm "initial server metadata"
  git -C "$work" tag "aw-v$cli_version"
  git -C "$work" push -q origin HEAD:main "refs/tags/aw-v$cli_version"
}

make_cli_version() {
  local work="$1"
  make -s -C "$work" -f TestMakefile print-cli-version
}

run_guard() {
  local work="$1" proposal="$2"
  make -s -C "$work" -f TestMakefile \
    release-cli-version-check CLI_VERSION="$proposal"
}

work="$TMP/work"
bare="$TMP/origin.git"
make_repo "$work" "$bare" "1.26.30" "1.34.0"

# The fixture deliberately matches production's divergent direction: CLI is
# far ahead of server. A server-derived implementation returns 1.26.30 here.
actual="$(make_cli_version "$work")"
if [ "$actual" = "1.34.1" ]; then
  echo "ok: divergent versions propose next CLI patch"
else
  fail "server 1.26.30 with latest CLI 1.34.0 proposed '$actual', want '1.34.1'"
fi

out="$TMP/nonmonotonic.out"
rc=0
run_guard "$work" "1.26.30" >"$out" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  fail "non-monotonic 1.26.30 proposal was accepted"
elif grep -Fq "proposed CLI version 1.26.30 is not strictly greater than latest published CLI version 1.34.0" "$out"; then
  echo "ok: non-monotonic proposal refused with both versions"
else
  fail "non-monotonic refusal did not name proposed 1.26.30 and latest 1.34.0"
  cat "$out"
fi

if run_guard "$work" "1.34.0" >/dev/null 2>&1; then
  fail "equal-to-latest 1.34.0 proposal was accepted"
else
  echo "ok: equal-to-latest proposal refused"
fi

if run_guard "$work" "1.34.1" >/dev/null; then
  echo "ok: next CLI patch accepted"
else
  fail "next CLI patch 1.34.1 was refused"
fi

# Creating the candidate locally must not change the version used by the
# separate release-cli-push invocation; published origin history is the floor.
git -C "$work" tag aw-v1.34.1
actual="$(make_cli_version "$work")"
if [ "$actual" = "1.34.1" ]; then
  echo "ok: local unpushed candidate does not advance published history"
else
  fail "local unpushed aw-v1.34.1 changed proposal to '$actual'"
fi

git -C "$work" push -q origin refs/tags/aw-v1.34.1
actual="$(make_cli_version "$work")"
if [ "$actual" = "1.34.2" ]; then
  echo "ok: published candidate advances next patch"
else
  fail "published aw-v1.34.1 produced '$actual', want '1.34.2'"
fi

git -C "$work" tag aw-v1.34.10
git -C "$work" push -q origin refs/tags/aw-v1.34.10
actual="$(make_cli_version "$work")"
if [ "$actual" = "1.34.11" ]; then
  echo "ok: multi-digit patch ordering"
else
  fail "published aw-v1.34.10 produced '$actual', want '1.34.11'"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures scenario(s) failed" >&2
  exit 1
fi

echo "All CLI release-version scenarios passed."
