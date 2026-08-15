#!/usr/bin/env bash
# The declared-floor==expected-version predicate used by the PyPI workflow.
# It reads only committed source; public registry verification is separate.
#
# Usage: check-release-floor.sh --pyproject <path> --package <name> --expected <version>
# Exit 0 iff the pyproject declares exactly one literal "<name>>=<version>"
# floor and it equals <version>. Multi, absent, and non-literal floors are
# refusals of their own, matching the workflow's original inline rules.

set -euo pipefail

PYPROJECT="" PACKAGE="" EXPECTED=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pyproject) PYPROJECT="$2"; shift 2 ;;
    --package)   PACKAGE="$2";   shift 2 ;;
    --expected)  EXPECTED="$2";  shift 2 ;;
    *) echo "check-release-floor: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PYPROJECT" && -n "$PACKAGE" && -n "$EXPECTED" ]] \
  || { echo "check-release-floor: --pyproject --package --expected are required" >&2; exit 2; }

python3 - "$PYPROJECT" "$PACKAGE" "$EXPECTED" <<'PY'
import re
import sys
import tomllib

pyproject, package, expected = sys.argv[1:4]
dependencies = tomllib.load(open(pyproject, "rb"))["project"]["dependencies"]
literals = [item for item in dependencies if item.startswith(f"{package}>=")]
if len(literals) != 1:
    raise SystemExit(
        f"REFUSE: expected exactly one literal {package}>= floor in "
        f"{pyproject}, found {literals!r}"
    )
match = re.fullmatch(re.escape(package) + r">=([^,;< ]+)", literals[0])
if match is None:
    raise SystemExit(
        f"REFUSE: expected exactly one literal {package}>= floor, "
        f"found non-literal {literals[0]!r}"
    )
floor = match.group(1)
if floor != expected:
    raise SystemExit(
        f"REFUSE: declared floor {package}>={floor} is not the expected "
        f"{package} {expected}"
    )
print(f"floor ok: {package}>={floor} equals expected {expected}")
PY
