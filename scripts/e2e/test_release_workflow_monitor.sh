#!/usr/bin/env bash
# The workflow monitor's stdout IS the typed remote-completion record
# (aben A8): exactly one JSON line {workflow, run_sha, conclusion}, with
# the release SHA it actually watched. Driven with a stub gh so the
# record's shape is pinned without the network.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/release-workflow-monitor.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/monitor-record.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/sh
case "$2" in
  list) echo "12345" ;;
  watch) exit "${GH_STUB_WATCH_EXIT:-0}" ;;
  view) echo "${GH_STUB_CONCLUSION:-success}" ;;
esac
EOF
chmod +x "$tmp/bin/gh"

repo="$tmp/repo"
mkdir -p "$repo" && cd "$repo"
git init -q -b main .
git config user.email t@t
git config user.name t
git commit -q --allow-empty -m base
git branch release
git remote add origin "$repo"
git fetch -q origin
sha="$(git rev-parse HEAD)"

out="$(PATH="$tmp/bin:$PATH" bash "$script" aweb-server 1.27.2 2>/dev/null)"
expected="{\"workflow\":\"pypi-release.yml\",\"run_sha\":\"$sha\",\"conclusion\":\"success\"}"
if [ "$out" = "$expected" ]; then
  echo "ok   success record is exactly the typed shape"
else
  echo "FAIL: record was: $out" >&2
  exit 1
fi

set +e
out="$(GH_STUB_WATCH_EXIT=1 GH_STUB_CONCLUSION=failure PATH="$tmp/bin:$PATH" \
  bash "$script" aweb-server 1.27.2 2>/dev/null)"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  echo "FAIL: a failed watch exited 0" >&2
  exit 1
fi
case "$out" in
  *'"conclusion":"failure"'*) echo "ok   failure still emits the record and exits nonzero" ;;
  *) echo "FAIL: failure record was: $out" >&2; exit 1 ;;
esac

echo "SELFTEST OK: 2 assertions"
