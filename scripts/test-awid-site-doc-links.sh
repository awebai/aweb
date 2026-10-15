#!/usr/bin/env bash
# Check publication-context links after generating AWID public-doc copies.
# The document list comes from the production sync target.
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
  "$FIXTURE_ROOT/server" "$FIXTURE_ROOT/awid" "$FIXTURE_ROOT/scripts"
touch "$FIXTURE_ROOT/server/pyproject.toml" "$FIXTURE_ROOT/awid/pyproject.toml"
cp "$ROOT/scripts/check-awid-site-doc-links.py" "$FIXTURE_ROOT/scripts/check-awid-site-doc-links.py"

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
done

if ! output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
  printf 'FAIL: clean AWID site document mirrors did not pass:\n%s\n' "$output" >&2
  exit 1
fi

# A generated document can still link to an unpublished target. The link
# check must reject it after syncing from the canonical source.
broken_name="${doc_names[0]}"
printf '\n[unpublished target](not-published.md)\n' >>"$FIXTURE_ROOT/docs/$broken_name"
if output="$(make_for_fixture check-awid-site-docs 2>&1)"; then
  printf 'FAIL: generated AWID site documents passed with a dead relative link:\n%s\n' "$output" >&2
  exit 1
fi
if ! grep -Fq "broken relative Markdown link in AWID site context: not-published.md" <<<"$output"; then
  printf 'FAIL: dead relative-link fixture failed for the wrong reason:\n%s\n' "$output" >&2
  exit 1
fi

echo "self-test passed: generated documents pass; dead publication-context links fail"
