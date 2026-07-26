#!/usr/bin/env bash
# Prove the AWID public-doc mirror gate accepts clean copies and rejects every
# configured mirror when stale. The document list comes from the same Makefile
# variable used by the production sync and check targets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/aweb-awid-site-docs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FIXTURE_ROOT="$TMP/repo"
# Pin the public repository shape independently of the Makefile default. If the
# fixture reused that setting, a wrong path would move the check and its control
# together and leave both green.
EXPECTED_MIRROR_DIR="$FIXTURE_ROOT/awid/site/static"
mkdir -p "$FIXTURE_ROOT/docs" "$EXPECTED_MIRROR_DIR" \
  "$FIXTURE_ROOT/server" "$FIXTURE_ROOT/awid"
touch "$FIXTURE_ROOT/server/pyproject.toml" "$FIXTURE_ROOT/awid/pyproject.toml"

make_for_fixture() {
  make --no-print-directory -C "$FIXTURE_ROOT" -f "$ROOT/Makefile" "$@"
}

doc_names=()
while IFS= read -r name; do
  [ -n "$name" ] && doc_names+=("$name")
done < <(make_for_fixture list-awid-site-docs)

if [ "${#doc_names[@]}" -eq 0 ]; then
  echo "FAIL: Makefile configured no AWID site document mirrors" >&2
  exit 1
fi

for name in "${doc_names[@]}"; do
  cp "$ROOT/docs/$name" "$FIXTURE_ROOT/docs/$name"
  cp "$ROOT/docs/$name" "$EXPECTED_MIRROR_DIR/$name"
done

if ! output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
  printf 'FAIL: clean AWID site document mirrors did not pass:\n%s\n' "$output" >&2
  exit 1
fi

for name in "${doc_names[@]}"; do
  printf '\nstale fixture\n' >>"$EXPECTED_MIRROR_DIR/$name"
  if output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
    printf 'FAIL: stale AWID site document mirror passed: %s\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  expected="awid/site/static/$name differs from docs/$name"
  if ! grep -Fq "$expected" <<<"$output"; then
    printf 'FAIL: stale AWID site document mirror failed for the wrong reason: %s\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  cp "$FIXTURE_ROOT/docs/$name" "$EXPECTED_MIRROR_DIR/$name"
  if ! output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
    printf 'FAIL: restored AWID site document mirrors did not pass after seeding %s:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
done

echo "self-test passed: clean AWID site document mirrors pass and every configured stale copy fails"
