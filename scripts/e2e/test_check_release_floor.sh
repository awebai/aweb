#!/usr/bin/env bash
# Self-test for scripts/check-release-floor.sh - the extracted
# declared-floor==expected-version predicate (aben R2, design section 1).
# No network. The predicate parses exactly one awid-service>= literal from
# a pyproject and compares equality against the expected version; multi,
# absent, and malformed floors are their own refusals.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/check-release-floor.sh"
PASS=0
fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

tmp="$(mktemp -d)"
trap 'command rm -rf "$tmp"' EXIT

write_pyproject() {
  # $1 path, $2... dependency lines
  local path="$1"; shift
  {
    printf '[project]\nname = "x"\nversion = "0.0.1"\ndependencies = [\n'
    for dep in "$@"; do printf '    "%s",\n' "$dep"; done
    printf ']\n'
  } > "$path"
}

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then fail "$label: accepted what it must refuse"; fi
  grep -qi "$needle" <<<"$out" || fail "$label: refusal does not name ($needle): $out"
  ok "$label refused, naming: $needle"
}

# green: exact equality
write_pyproject "$tmp/ok.toml" "fastapi>=0.1" "awid-service>=0.5.16" "uvicorn"
bash "$LANE" --pyproject "$tmp/ok.toml" --package awid-service --expected 0.5.16 \
  || fail "exact equality refused"
ok "floor equal to expected passes"

# red: floor behind expected (the 0.5.15-vs-0.5.16 stop, reconstructed)
write_pyproject "$tmp/behind.toml" "awid-service>=0.5.15"
expect_refusal "floor behind release" "0.5.15" \
  bash "$LANE" --pyproject "$tmp/behind.toml" --package awid-service --expected 0.5.16

# red: floor ahead is also inequality
write_pyproject "$tmp/ahead.toml" "awid-service>=0.5.17"
expect_refusal "floor ahead of release" "0.5.17" \
  bash "$LANE" --pyproject "$tmp/ahead.toml" --package awid-service --expected 0.5.16

# red: absent floor
write_pyproject "$tmp/absent.toml" "fastapi>=0.1"
expect_refusal "absent floor" "one literal" \
  bash "$LANE" --pyproject "$tmp/absent.toml" --package awid-service --expected 0.5.16

# red: multiple floor literals
write_pyproject "$tmp/multi.toml" "awid-service>=0.5.15" "awid-service>=0.5.16"
expect_refusal "multiple floors" "one literal" \
  bash "$LANE" --pyproject "$tmp/multi.toml" --package awid-service --expected 0.5.16

# red: malformed floor expression (range, not a literal)
write_pyproject "$tmp/range.toml" "awid-service>=0.5.15,<0.6"
expect_refusal "non-literal floor" "one literal" \
  bash "$LANE" --pyproject "$tmp/range.toml" --package awid-service --expected 0.5.16

# the real repository file passes against its committed floor
current="$(python3 -c "
import re, tomllib
deps = tomllib.load(open('$ROOT/server/pyproject.toml','rb'))['project']['dependencies']
dep = next(d for d in deps if d.startswith('awid-service>='))
print(re.fullmatch(r'awid-service>=([^,; ]+)', dep).group(1))")"
bash "$LANE" --pyproject "$ROOT/server/pyproject.toml" --package awid-service \
  --expected "$current" || fail "real pyproject refused its own floor"
ok "real server/pyproject.toml floor passes against its committed value"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
