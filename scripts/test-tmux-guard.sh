#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/aweb-tmux-guard-test.XXXXXX")
FAKE_BIN="$ROOT/bin"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/tmux" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$TMUX_TEST_TMUX_LOG"
if [[ ${TMUX_TEST_GUARD_PROBE:-} == 1 ]]; then
  printf 'called\n' >> "$TMUX_TEST_GUARD_CALLS"
  printf '<%s>\n' "$@" > "$TMUX_TEST_GUARD_ARGV"
  exit "${TMUX_TEST_GUARD_STATUS:-0}"
fi
EOF
chmod +x "$FAKE_BIN/tmux"

export PATH="$FAKE_BIN:/usr/bin:/bin"
export TMUX_TEST_TMUX_LOG="$ROOT/tmux.log"
: > "$TMUX_TEST_TMUX_LOG"

set +e
PATH="$REPO_ROOT/scripts/guard-bin:$FAKE_BIN:/usr/bin:/bin" tmux kill-serv > "$ROOT/guard.out" 2>&1
guard_status=$?
set -e
[[ $guard_status == 86 ]]
grep -q 'kill-server REFUSED' "$ROOT/guard.out"
! grep -q 'kill-serv' "$ROOT/tmux.log"

# A checkout reached lexically through /tmp is physically /private/tmp on
# macOS. The guard must remove that PATH entry by identity, not spelling.
TMP_CHECKOUT=$(mktemp -d /tmp/aweb-tmux-guard-checkout.XXXXXX)
mkdir -p "$TMP_CHECKOUT/worktree/scripts"
cp -R "$REPO_ROOT/scripts/guard-bin" "$TMP_CHECKOUT/worktree/scripts/guard-bin"
run_guard_probe() {
  local guard_path=$1 label=$2
  : > "$ROOT/$label.calls"
  set +e
  python3 - "$TMP_CHECKOUT/worktree" "$guard_path:$FAKE_BIN:/usr/bin:/bin" "$ROOT/$label.calls" "$ROOT/$label.argv" <<'PY'
import os
import subprocess
import sys

env = {
    **os.environ,
    "PATH": sys.argv[2],
    "TMUX_TEST_GUARD_PROBE": "1",
    "TMUX_TEST_GUARD_CALLS": sys.argv[3],
    "TMUX_TEST_GUARD_ARGV": sys.argv[4],
    "TMUX_TEST_GUARD_STATUS": "37",
}
try:
    result = subprocess.run(
        ["tmux", "guard-probe", "argument with spaces", "--flag"],
        cwd=sys.argv[1],
        env=env,
        timeout=3,
        check=False,
    )
except subprocess.TimeoutExpired:
    sys.exit(124)
sys.exit(result.returncode)
PY
  local status=$?
  set -e
  [[ $status == 37 ]]
  [[ $(wc -l < "$ROOT/$label.calls" | tr -d ' ') == 1 ]]
  printf '<guard-probe>\n<argument with spaces>\n<--flag>\n' > "$ROOT/$label.expected"
  cmp "$ROOT/$label.expected" "$ROOT/$label.argv"
}
run_guard_probe "$TMP_CHECKOUT/worktree/scripts/guard-bin" tmp-physical-alias

# An arbitrary symlinked PATH entry has the same identity mismatch even where
# /tmp itself is not aliased.
ln -s "$TMP_CHECKOUT/worktree/scripts/guard-bin" "$ROOT/guard-path-alias"
run_guard_probe "$ROOT/guard-path-alias" symlink-path-alias

rm -rf "$ROOT" "$TMP_CHECKOUT"
echo "tmux guard tests passed"
