#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/migrate-agent-tmux.sh --team cli|atext|ac --workspace PATH \
    --session NAME [--phase plan|launch|verify|retire-old|rollback-new] [--apply] \
    [--old-socket PATH] [--confirm-session NAME]

Dry-run is the default. --apply is required for mutation. The script always
uses the reviewed tmux PATH guard, a per-team ~/.aweb/tmux/<team> socket dir,
and named-session teardown only. retire-old also requires an explicit old
socket path and refuses to kill the session from inside that same socket.
EOF
}

TEAM=
WORKSPACE=
SESSION=
PHASE=plan
APPLY=0
OLD_SOCKET=
CONFIRM_SESSION=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --team) TEAM=${2:-}; shift 2 ;;
    --workspace) WORKSPACE=${2:-}; shift 2 ;;
    --session) SESSION=${2:-}; shift 2 ;;
    --phase) PHASE=${2:-}; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --old-socket) OLD_SOCKET=${2:-}; shift 2 ;;
    --confirm-session) CONFIRM_SESSION=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$TEAM" in cli|atext|ac) ;; *) echo "--team must be cli, atext, or ac" >&2; exit 2 ;; esac
case "$PHASE" in plan|launch|verify|retire-old|rollback-new) ;; *) echo "invalid --phase: $PHASE" >&2; exit 2 ;; esac
[[ -n "$WORKSPACE" && -n "$SESSION" ]] || { echo "--workspace and --session are required" >&2; exit 2; }
WORKSPACE=$(cd "$WORKSPACE" && pwd -P)
[[ -f "$WORKSPACE/.aw/workspace.yaml" ]] || { echo "workspace has no .aw/workspace.yaml: $WORKSPACE" >&2; exit 2; }

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
GUARD_DIR="$REPO_ROOT/scripts/guard-bin"
export PATH="$GUARD_DIR:$PATH"
[[ $(command -v tmux) == "$GUARD_DIR/tmux" ]] || { echo "tmux PATH guard is not first" >&2; exit 1; }

SOCKET_DIR="$HOME/.aweb/tmux/$TEAM"
WORKSPACE_FILE="$WORKSPACE/.aw/workspace.yaml"
AW_BIN=$(command -v aw || true)
[[ -n "$AW_BIN" ]] || { echo "aw is required" >&2; exit 1; }

print_plan() {
  cat <<EOF
team: $TEAM
workspace: $WORKSPACE
session: $SESSION
new TMUX_TMPDIR: $SOCKET_DIR
workspace binding: aweb_tmux_tmpdir: $SOCKET_DIR
phase: $PHASE
mode: $([[ $APPLY -eq 1 ]] && echo apply || echo dry-run)
guard: $GUARD_DIR/tmux
EOF
}

set_workspace_socket() {
  python3 - "$WORKSPACE_FILE" "$SOCKET_DIR" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
value = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
indexes = [i for i, line in enumerate(lines) if line.startswith("aweb_tmux_tmpdir:")]
if len(indexes) > 1:
    raise SystemExit("workspace has duplicate aweb_tmux_tmpdir keys")
entry = f"aweb_tmux_tmpdir: {json.dumps(value)}"
if indexes:
    lines[indexes[0]] = entry
else:
    insert_at = next((i + 1 for i, line in enumerate(lines) if line.startswith("aweb_url:")), 0)
    lines.insert(insert_at, entry)
data = "\n".join(lines) + "\n"
fd, tmp = tempfile.mkstemp(prefix=".workspace-tmux-", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, path.stat().st_mode & 0o777)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
}

new_tmux() {
  TMUX_TMPDIR="$SOCKET_DIR" TMUX= tmux "$@"
}

new_session_exists() {
  new_tmux has-session -t "=$SESSION" >/dev/null 2>&1
}

verify_new() {
  new_session_exists || { echo "dedicated session does not exist: $SESSION" >&2; return 1; }
  echo "dedicated session windows:"
  new_tmux list-windows -t "=$SESSION" -F '#I:#W'
}

canonical_path() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
}

path_is_within() {
  python3 - "$1" "$2" <<'PY'
import os
import sys
path = os.path.realpath(sys.argv[1])
directory = os.path.realpath(sys.argv[2])
try:
    inside = os.path.commonpath((path, directory)) == directory
except ValueError:
    inside = False
raise SystemExit(0 if inside else 1)
PY
}

print_plan
if [[ $APPLY -eq 0 ]]; then
  case "$PHASE" in
    launch) echo "would persist workspace socket, create $SOCKET_DIR, and run: aw team up --session $SESSION --force --no-attach" ;;
    verify) echo "would verify named session $SESSION on $SOCKET_DIR" ;;
    retire-old) echo "would verify the new session, then kill only old named session $SESSION via --old-socket" ;;
    rollback-new) echo "would kill only new named session $SESSION on $SOCKET_DIR; workspace binding remains dedicated" ;;
  esac
  exit 0
fi

case "$PHASE" in
  plan)
    echo "plan is non-mutating; omit --apply"
    ;;
  launch)
    mkdir -p "$SOCKET_DIR"
    chmod 700 "$SOCKET_DIR"
    set_workspace_socket
    if new_session_exists; then
      echo "dedicated session already exists; launch is idempotently skipped"
    else
      (cd "$WORKSPACE" && AWEB_TMUX_TMPDIR="$SOCKET_DIR" "$AW_BIN" team up --session "$SESSION" --force --no-attach)
    fi
    verify_new
    ;;
  verify)
    verify_new
    ;;
  retire-old)
    [[ -n "$OLD_SOCKET" && "$OLD_SOCKET" = /* && -S "$OLD_SOCKET" ]] || { echo "retire-old requires --old-socket with an absolute tmux socket" >&2; exit 2; }
    [[ "$CONFIRM_SESSION" == "$SESSION" ]] || { echo "retire-old requires --confirm-session $SESSION" >&2; exit 2; }
    verify_new
    OLD_SOCKET=$(canonical_path "$OLD_SOCKET")
    CURRENT_SOCKET=${TMUX:-}
    CURRENT_SOCKET=${CURRENT_SOCKET%%,*}
    if [[ -n "$CURRENT_SOCKET" && $(canonical_path "$CURRENT_SOCKET") == "$OLD_SOCKET" ]]; then
      echo "refusing to retire the current process's own tmux session; run this phase from Juan's outside/default terminal" >&2
      exit 1
    fi
    if TMUX= tmux -S "$OLD_SOCKET" has-session -t "=$SESSION" >/dev/null 2>&1; then
      TMUX= tmux -S "$OLD_SOCKET" kill-session -t "=$SESSION"
      echo "retired old named session $SESSION; no server-wide teardown was used"
    else
      echo "old named session is already absent; retire is idempotently complete"
    fi
    ;;
  rollback-new)
    [[ "$CONFIRM_SESSION" == "$SESSION" ]] || { echo "rollback-new requires --confirm-session $SESSION" >&2; exit 2; }
    CURRENT_SOCKET=${TMUX:-}
    CURRENT_SOCKET=${CURRENT_SOCKET%%,*}
    if [[ -n "$CURRENT_SOCKET" ]] && path_is_within "$CURRENT_SOCKET" "$SOCKET_DIR"; then
      echo "refusing to roll back the current process's own dedicated tmux session; run this phase from an outside terminal" >&2
      exit 1
    fi
    if new_session_exists; then
      new_tmux kill-session -t "=$SESSION"
      echo "removed only new named session $SESSION; workspace remains bound to $SOCKET_DIR"
    else
      echo "new named session is already absent; rollback is idempotently complete"
    fi
    ;;
esac
