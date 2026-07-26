#!/usr/bin/env bash
# Prove the AWID public-doc mirror gate accepts clean copies and rejects every
# configured mirror when stale. The document list comes from the same Makefile
# variable used by the production sync and check targets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/aweb-awid-site-docs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
MIRROR_DIR="$TMP/static"

make_for_fixture() {
  make --no-print-directory "$@" \
    AWID_SITE_DOC_SOURCE_DIR="$ROOT/docs" \
    AWID_SITE_DOC_MIRROR_DIR="$MIRROR_DIR"
}

doc_names=()
while IFS= read -r name; do
  [ -n "$name" ] && doc_names+=("$name")
done < <(make_for_fixture list-awid-site-docs)

if [ "${#doc_names[@]}" -eq 0 ]; then
  echo "FAIL: Makefile configured no AWID site document mirrors" >&2
  exit 1
fi

make_for_fixture sync-awid-site-docs
if ! output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
  printf 'FAIL: clean AWID site document mirrors did not pass:\n%s\n' "$output" >&2
  exit 1
fi

for name in "${doc_names[@]}"; do
  printf '\nstale fixture\n' >>"$MIRROR_DIR/$name"
  if output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
    printf 'FAIL: stale AWID site document mirror passed: %s\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  if ! grep -Fq "$MIRROR_DIR/$name differs from" <<<"$output"; then
    printf 'FAIL: stale AWID site document mirror failed for the wrong reason: %s\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  make_for_fixture sync-awid-site-docs
  if ! output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
    printf 'FAIL: restored AWID site document mirrors did not pass after seeding %s:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
done

echo "self-test passed: clean AWID site document mirrors pass and every configured stale copy fails"
