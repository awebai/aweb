#!/usr/bin/env bash
# Check Python lock freshness without rewriting the worktree. The self-test uses
# the real uv checker against an isolated copy, in both the clean and stale-AWID
# directions (default-aajc.5).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/pycache}"

check_locks() {
  local root="$1"
  (cd "$root/awid" && uv lock --check)
  (cd "$root/server" && uv lock --check)
}

self_test() (
  local tmp out status
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/aweb-lock-freshness.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/awid" "$tmp/server"
  cp "$ROOT/awid/pyproject.toml" "$ROOT/awid/uv.lock" "$ROOT/awid/README.md" "$tmp/awid/"
  cp "$ROOT/server/pyproject.toml" "$ROOT/server/uv.lock" "$ROOT/server/README.md" "$tmp/server/"

  if ! check_locks "$tmp" >/dev/null; then
    echo "SELF-TEST FAIL: clean copied locks were rejected" >&2
    return 1
  fi

  python3 - "$tmp/server/uv.lock" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r'(?ms)(^\[\[package\]\]\nname = "awid-service"\nversion = ")[^"]+'
    r'("\nsource = \{ editable = "\.\./awid" \})'
)
stale, count = pattern.subn(r'\g<1>0.0.0\2', text)
if count != 1:
    raise SystemExit(f"expected one editable awid-service lock entry, found {count}")
path.write_text(stale, encoding="utf-8")
PY

  set +e
  out="$(check_locks "$tmp" 2>&1)"
  status=$?
  set -e

  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: a stale server lock accepted AWID version 0.0.0" >&2
    return 1
  fi
  if ! grep -Fq "needs to be updated" <<<"$out"; then
    printf 'SELF-TEST INCONCLUSIVE: stale fixture failed for the wrong reason:\n%s\n' "$out" >&2
    return 1
  fi

  (cd "$tmp/server" && uv lock >/dev/null)
  if ! check_locks "$tmp" >/dev/null; then
    echo "SELF-TEST FAIL: the regenerated stale lock did not pass" >&2
    return 1
  fi

  python3 - "$tmp/server/uv.lock" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
row = '    { name = "trustme", specifier = ">=1.2.1" },\n'
if text.count(row) != 1:
    raise SystemExit("expected one AWID trustme dev-dependency lock row")
path.write_text(text.replace(row, ""), encoding="utf-8")
PY

  set +e
  out="$(check_locks "$tmp" 2>&1)"
  status=$?
  set -e

  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: server lock accepted a missing AWID dev dependency" >&2
    return 1
  fi
  if ! grep -Fq "needs to be updated" <<<"$out"; then
    printf 'SELF-TEST INCONCLUSIVE: missing AWID dependency failed for the wrong reason:\n%s\n' "$out" >&2
    return 1
  fi

  (cd "$tmp/server" && uv lock >/dev/null)
  if ! check_locks "$tmp" >/dev/null; then
    echo "SELF-TEST FAIL: the dependency-regenerated lock did not pass" >&2
    return 1
  fi

  echo "self-test passed: clean locks pass; stale AWID version and missing dependent-lock dependency fail"
)

case "${1:-}" in
  "")
    check_locks "$ROOT"
    echo "Python locks are up to date"
    ;;
  --self-test)
    self_test
    ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
