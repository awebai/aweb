#!/usr/bin/env bash
# Check Python lock freshness without rewriting the worktree. The self-test uses
# the real uv checker against an isolated copy, in both the clean and stale-AWID
# directions (default-aajc.5). Every lock that takes the in-repo awid as a source
# is checked: awid, server, naapp-lib, naapp/folio, naapp/library, naapp/secrets
# and naapp/logs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/pycache}"

# Every lock that takes the in-repo awid as a source, with the path its
# awid-service entry records.
LOCKS=(awid server naapp-lib naapp/folio naapp/library naapp/secrets naapp/logs)

# Each check returns on failure itself: the self-test calls this with errexit
# off, where only the last command's status would otherwise be reported.
check_locks() {
  local root="$1" lock
  for lock in "${LOCKS[@]}"; do
    (cd "$root/$lock" && uv lock --check) || return
  done
}

# The awid source path a package's lock records: ../awid or ../../awid.
awid_source() {
  local lock="$1"
  if [[ "$lock" == */* ]]; then
    printf '../../awid'
  else
    printf '../awid'
  fi
}

# Rewrite one package's locked AWID version to 0.0.0, require the check to
# refuse it for that reason, then relock and require it to pass again.
stale_awid_self_test() {
  local tmp="$1" lock="$2" out status
  python3 - "$tmp/$lock/uv.lock" "$(awid_source "$lock")" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = re.escape(sys.argv[2])
text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r'(?ms)(^\[\[package\]\]\nname = "awid-service"\nversion = ")[^"]+'
    r'("\nsource = \{ editable = "' + source + r'" \})'
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
    echo "SELF-TEST FAIL: a stale $lock lock accepted AWID version 0.0.0" >&2
    return 1
  fi
  if ! grep -Fq "needs to be updated" <<<"$out"; then
    printf 'SELF-TEST INCONCLUSIVE: stale %s fixture failed for the wrong reason:\n%s\n' "$lock" "$out" >&2
    return 1
  fi

  (cd "$tmp/$lock" && uv lock >/dev/null)
  if ! check_locks "$tmp" >/dev/null; then
    echo "SELF-TEST FAIL: the regenerated stale $lock lock did not pass" >&2
    return 1
  fi
}

self_test() (
  local tmp out status lock
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/aweb-lock-freshness.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  for lock in "${LOCKS[@]}"; do
    mkdir -p "$tmp/$lock"
    cp "$ROOT/$lock/pyproject.toml" "$ROOT/$lock/uv.lock" "$ROOT/$lock/README.md" "$tmp/$lock/"
  done
  # Include the local source closure, including newly declared (not yet locked)
  # paths, so a missing fixture cannot mask a genuinely stale lock.
  python3 - "$ROOT" "$tmp" "${LOCKS[@]}" <<'PY'
import shutil
import sys
import tomllib
from pathlib import Path

root, target = (Path(arg).resolve() for arg in sys.argv[1:3])
pending = [root / lock for lock in sys.argv[3:]]
copied = set(pending)
while pending:
    project = pending.pop()
    metadata = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    paths = []
    for source in metadata.get("tool", {}).get("uv", {}).get("sources", {}).values():
        for entry in source if isinstance(source, list) else [source]:
            if "path" in entry:
                paths.append(entry["path"])
    lock = project / "uv.lock"
    if lock.is_file():
        for package in tomllib.loads(lock.read_text(encoding="utf-8")).get("package", []):
            source = package.get("source", {})
            for kind in ("editable", "directory", "virtual", "path"):
                if kind in source:
                    paths.append(source[kind])
    for path in paths:
        dependency = (project / path).resolve()
        if not dependency.is_relative_to(root):
            raise SystemExit(f"self-test local dependency is outside repository: {dependency}")
        if dependency in copied:
            continue
        copied.add(dependency)
        destination = target / dependency.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if dependency.is_dir():
            shutil.copytree(
                dependency,
                destination,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
                    ".ruff_cache", "node_modules",
                ),
            )
            if (dependency / "pyproject.toml").is_file():
                pending.append(dependency)
        else:
            shutil.copy2(dependency, destination)
PY

  if ! check_locks "$tmp" >/dev/null; then
    echo "SELF-TEST FAIL: clean copied locks were rejected" >&2
    return 1
  fi

  stale_awid_self_test "$tmp" server

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

  for lock in naapp-lib naapp/folio naapp/library naapp/secrets naapp/logs; do
    stale_awid_self_test "$tmp" "$lock"
  done

  echo "self-test passed: clean locks pass; stale AWID versions in server, naapp-lib, naapp/folio, naapp/library, naapp/secrets and naapp/logs and a missing dependent-lock dependency fail"
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
