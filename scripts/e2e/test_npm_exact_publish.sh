#!/usr/bin/env bash
# Self-test for scripts/npm-exact-publish.sh, no network.
#
#   green: pack-inspect stages one tgz from a coherent package and reports
#          its digest; verify-published (against a supplied observed file)
#          adopts byte-identical bytes
#   reds:  declared version mismatch, missing declared main entry inside
#          the tgz, a files[] entry with no content in the tgz, observed
#          published bytes differing from staged

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/npm-exact-publish.sh"
PASS=0

fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  rm -rf "$tmp/pkg"
  mkdir -p "$tmp/pkg/dist"
  cat > "$tmp/pkg/package.json" <<'EOF'
{
  "name": "@awebai/lane-fixture",
  "version": "1.2.3",
  "main": "./dist/index.js",
  "files": ["dist", "README.md"]
}
EOF
  echo 'module.exports = 1' > "$tmp/pkg/dist/index.js"
  echo 'fixture' > "$tmp/pkg/README.md"
}

# ── green: coherent package stages exactly one inspected tgz ────────
make_fixture
out="$(bash "$LANE" pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged")" \
  || fail "pack-inspect refused a coherent package: $out"
grep -q "sha256" <<<"$out" || fail "pack-inspect did not report a digest: $out"
[[ -f "$tmp/staged/awebai-lane-fixture-1.2.3.tgz" ]] \
  || fail "staged tgz missing from the out directory"
ok "pack-inspect stages a coherent package and reports its digest"

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$(bash "$LANE" "$@" 2>&1)"; then
    fail "$label: accepted what it must refuse"
  fi
  grep -qi "$needle" <<<"$out" \
    || fail "$label: refusal does not name the item ($needle): $out"
  ok "$label refused, naming: $needle"
}

# ── red: declared version does not match the package ────────────────
make_fixture
expect_refusal "version mismatch" "version" \
  pack-inspect --dir "$tmp/pkg" --version 9.9.9 --out "$tmp/staged-red"

# ── red: declared main entry missing from the packed bytes ──────────
make_fixture
rm "$tmp/pkg/dist/index.js"
expect_refusal "missing main entry" "dist/index.js" \
  pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged-red"

# ── red: a files[] entry contributes nothing to the tgz ─────────────
make_fixture
rm "$tmp/pkg/README.md"
expect_refusal "empty files entry" "README.md" \
  pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged-red"

# ── verify-published: identical adopts, different refuses ───────────
staged="$tmp/staged/awebai-lane-fixture-1.2.3.tgz"
cp "$staged" "$tmp/observed.tgz"
bash "$LANE" verify-published --tgz "$staged" --observed "$tmp/observed.tgz" \
  || fail "verify-published refused byte-identical observed bytes"
ok "verify-published adopts byte-identical observed bytes"
printf 'x' >> "$tmp/observed.tgz"
expect_refusal "published bytes differ" "not.*equal\|does not equal" \
  verify-published --tgz "$staged" --observed "$tmp/observed.tgz"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
