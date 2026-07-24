#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/aweb-tmux-migration-test.XXXXXX")
HOME_DIR="$ROOT/home"
WORKSPACE="$ROOT/workspace"
FAKE_BIN="$ROOT/bin"
STATE="$ROOT/state"
mkdir -p "$HOME_DIR" "$WORKSPACE/.aw" "$FAKE_BIN" "$STATE/new" "$STATE/old"
printf 'aweb_url: https://example.test\nmemberships: []\n' > "$WORKSPACE/.aw/workspace.yaml"

cat > "$FAKE_BIN/aw" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$TMUX_TEST_AW_LOG"
[[ "$1 $2" == "team up" ]]
session=
while [[ $# -gt 0 ]]; do
  if [[ $1 == --session ]]; then session=$2; shift 2; else shift; fi
done
mkdir -p "$TMUX_TEST_STATE/new"
printf '0:coordinator\n1:developer\n' > "$TMUX_TEST_STATE/new/$session.windows"
EOF

cat > "$FAKE_BIN/tmux" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$TMUX_TEST_TMUX_LOG"
scope=new
while [[ ${1:-} == -* ]]; do
  if [[ $1 == -S ]]; then scope=old; shift 2; else shift; fi
done
operation=${1:-}
shift || true
session=
while [[ $# -gt 0 ]]; do
  if [[ $1 == -t ]]; then session=$2; shift 2; else shift; fi
done
case "$operation" in has-session|list-windows|kill-session) ;; *) echo "unexpected fake tmux operation: $operation" >&2; exit 2 ;; esac
[[ $session == =* ]] || { echo "tmux target is not exact: $session" >&2; exit 3; }
session=${session#=}
state_file="$TMUX_TEST_STATE/$scope/$session.windows"
case "$operation" in
  has-session) [[ -f "$state_file" ]] ;;
  list-windows) cat "$state_file" ;;
  kill-session) rm -f "$state_file" ;;
esac
EOF
chmod +x "$FAKE_BIN/aw" "$FAKE_BIN/tmux"

export HOME="$HOME_DIR"
export PATH="$FAKE_BIN:/usr/bin:/bin"
export TMUX_TEST_STATE="$STATE"
export TMUX_TEST_AW_LOG="$ROOT/aw.log"
export TMUX_TEST_TMUX_LOG="$ROOT/tmux.log"
HARNESS="$REPO_ROOT/scripts/migrate-agent-tmux.sh"
BASE=(--team cli --workspace "$WORKSPACE" --session cli)

"$HARNESS" "${BASE[@]}" --phase launch > "$ROOT/dry-run.out"
grep -q 'mode: dry-run' "$ROOT/dry-run.out"
! grep -q '^aweb_tmux_tmpdir:' "$WORKSPACE/.aw/workspace.yaml"

"$HARNESS" "${BASE[@]}" --phase launch --apply > "$ROOT/launch.out"
grep -q '^aweb_tmux_tmpdir: ' "$WORKSPACE/.aw/workspace.yaml"
grep -q '0:coordinator' "$ROOT/launch.out"
[[ $(wc -l < "$ROOT/aw.log" | tr -d ' ') == 1 ]]

"$HARNESS" "${BASE[@]}" --phase launch --apply > "$ROOT/relaunch.out"
grep -q 'idempotently skipped' "$ROOT/relaunch.out"
[[ $(wc -l < "$ROOT/aw.log" | tr -d ' ') == 1 ]]

set +e
PATH="$REPO_ROOT/scripts/guard-bin:$FAKE_BIN:/usr/bin:/bin" tmux kill-serv > "$ROOT/guard.out" 2>&1
guard_status=$?
set -e
[[ $guard_status == 86 ]]
grep -q 'kill-server REFUSED' "$ROOT/guard.out"
! grep -q 'kill-serv' "$ROOT/tmux.log"

OLD_SOCKET="$ROOT/old.sock"
python3 - "$OLD_SOCKET" <<'PY' &
import socket
import sys
import time
sock = socket.socket(socket.AF_UNIX)
sock.bind(sys.argv[1])
time.sleep(60)
PY
socket_pid=$!
for _ in $(seq 1 50); do [[ -S "$OLD_SOCKET" ]] && break; sleep 0.02; done
[[ -S "$OLD_SOCKET" ]]
printf '0:coordinator\n1:developer\n' > "$STATE/old/cli.windows"

set +e
"$HARNESS" "${BASE[@]}" --phase retire-old --old-socket "$OLD_SOCKET" --confirm-session wrong --apply > "$ROOT/retire-mismatch.out" 2>&1
mismatch_status=$?
"$HARNESS" "${BASE[@]}" --phase retire-old --old-socket relative.sock --confirm-session cli --apply > "$ROOT/retire-relative.out" 2>&1
relative_status=$?
touch "$ROOT/not-a-socket"
"$HARNESS" "${BASE[@]}" --phase retire-old --old-socket "$ROOT/not-a-socket" --confirm-session cli --apply > "$ROOT/retire-nonsocket.out" 2>&1
nonsocket_status=$?
set -e
[[ $mismatch_status == 2 && $relative_status == 2 && $nonsocket_status == 2 ]]
[[ -f "$STATE/old/cli.windows" ]]

ln -s "$ROOT" "$ROOT-alias"
set +e
TMUX="$ROOT/old.sock,123,0" "$HARNESS" "${BASE[@]}" --phase retire-old --old-socket "$ROOT-alias/old.sock" --confirm-session cli --apply > "$ROOT/retire-self.out" 2>&1
self_status=$?
set -e
[[ $self_status == 1 ]]
grep -q "own tmux session" "$ROOT/retire-self.out"
[[ -f "$STATE/old/cli.windows" ]]

TMUX= "$HARNESS" "${BASE[@]}" --phase retire-old --old-socket "$OLD_SOCKET" --confirm-session cli --apply > "$ROOT/retire.out"
[[ ! -f "$STATE/old/cli.windows" ]]
TMUX= "$HARNESS" "${BASE[@]}" --phase retire-old --old-socket "$OLD_SOCKET" --confirm-session cli --apply > "$ROOT/reretire.out"
grep -q 'already absent' "$ROOT/reretire.out"

set +e
"$HARNESS" "${BASE[@]}" --phase rollback-new --confirm-session wrong --apply > "$ROOT/rollback-mismatch.out" 2>&1
rollback_mismatch_status=$?
TMUX="$HOME/.aweb/tmux/cli/tmux-501/default,321,0" "$HARNESS" "${BASE[@]}" --phase rollback-new --confirm-session cli --apply > "$ROOT/rollback-self.out" 2>&1
rollback_self_status=$?
set -e
[[ $rollback_mismatch_status == 2 && $rollback_self_status == 1 ]]
grep -q "own dedicated tmux session" "$ROOT/rollback-self.out"
[[ -f "$STATE/new/cli.windows" ]]

TMUX= "$HARNESS" "${BASE[@]}" --phase rollback-new --confirm-session cli --apply > "$ROOT/rollback.out"
[[ ! -f "$STATE/new/cli.windows" ]]
TMUX= "$HARNESS" "${BASE[@]}" --phase rollback-new --confirm-session cli --apply > "$ROOT/rerollback.out"
grep -q 'already absent' "$ROOT/rerollback.out"

kill "$socket_pid"
wait "$socket_pid" 2>/dev/null || true
rm -rf "$ROOT" "$ROOT-alias"
echo "tmux migration harness tests passed"
