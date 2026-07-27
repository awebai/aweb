#!/usr/bin/env bash
# Fail-closed tmux observations and session-only cleanup for the resident proof.

DEFAULT_TMUX_SOCKET_ROOT=/tmp

proof_tmux_socket_path() {
  printf '%s/tmux-%s/default\n' "$1" "$(id -u)"
}

default_tmux_socket_path() {
  printf '%s/tmux-%s/default\n' "${DEFAULT_TMUX_SOCKET_ROOT%/}" "$(id -u)"
}

snapshot_default_tmux_topology() {
  local output="$1" raw="$output.raw" status socket
  if env -u TMUX -u TMUX_TMPDIR PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux list-panes -a -F '#{session_name}|#{window_id}|#{window_name}|#{pane_id}|#{pane_pid}|#{pane_dead}' \
      > "$raw" 2>/dev/null; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" == "0" ]]; then
    LC_ALL=C sort -u "$raw" > "$output"
    rm -f "$raw"
    return 0
  fi
  socket="$(default_tmux_socket_path)"
  if [[ "$status" == "1" && ! -e "$socket" && ! -S "$socket" ]]; then
    : > "$output"
    rm -f "$raw"
    return 0
  fi
  rm -f "$raw"
  echo "FAIL: could not authoritatively snapshot default tmux topology (exit $status, socket $socket)" >&2
  return 1
}

remove_proof_tmux_session() {
  local socket sessions kill_status probe_status attempt
  socket="$(proof_tmux_socket_path "$PROOF_TMUX_DIR")"
  if [[ ! -e "$socket" && ! -S "$socket" ]]; then
    return 0
  fi
  if [[ ! -S "$socket" ]]; then
    echo "FAIL: isolated proof tmux socket has unexpected type: $socket" >&2
    return 1
  fi
  if sessions="$(env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux list-sessions -F '#{session_name}' 2>/dev/null)"; then
    :
  else
    probe_status=$?
    echo "FAIL: could not enumerate isolated proof tmux socket before cleanup (exit $probe_status): $socket" >&2
    return 1
  fi
  if [[ "$sessions" != "$PROOF_TMUX_SESSION" ]]; then
    echo "FAIL: isolated proof tmux socket does not contain exactly the expected session: ${sessions:-<none>}" >&2
    return 1
  fi
  if env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux kill-session -t "=$PROOF_TMUX_SESSION" >/dev/null 2>&1; then
    kill_status=0
  else
    kill_status=$?
  fi
  attempt=0
  while (( attempt < 50 )); do
    if [[ ! -e "$socket" && ! -S "$socket" ]]; then
      return 0
    fi
    sleep 0.05
    ((attempt += 1))
  done
  if sessions="$(env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux list-sessions -F '#{session_name}' 2>/dev/null)"; then
    echo "FAIL: isolated proof tmux socket remains after exact-session cleanup (kill exit $kill_status, sessions ${sessions:-<none>}): $socket" >&2
  else
    probe_status=$?
    echo "FAIL: isolated proof tmux socket remains but cannot be queried after cleanup (kill exit $kill_status, probe exit $probe_status): $socket" >&2
  fi
  return 1
}
