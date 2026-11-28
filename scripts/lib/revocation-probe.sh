# The OSS journey's revocation probe, sourced by scripts/e2e-oss-user-journey.sh
# and by scripts/test_revocation_probe.py. The caller provides run_aw_in and
# BOB_DIR. monotonic_ms, probe_sleep and probe_poll are the probe's clock.

# Milliseconds on the monotonic clock, which every process on the host shares.
monotonic_ms() {
  python3 -c 'import time; print(time.monotonic_ns() // 1000000)'
}

probe_sleep() {
  sleep "$1"
}

# How often a wait looks at a process it is waiting for.
probe_poll() {
  sleep 0.1
}

# Polls (of probe_poll) a process gets after TERM before KILL, and after KILL
# before the probe reports that it could not end it.
PROBE_GRACE_POLLS=20

# True while process $1 exists and is not a zombie.
process_alive() {
  local state
  state="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
  [[ -n "$state" && "$state" != Z* ]]
}

# True while any live process is in process group $1.
group_alive() {
  ps -A -o pgid=,stat= | awk -v group="$1" '$1 == group && $2 !~ /^Z/ { found = 1 } END { exit !found }'
}

# Process $1 and every descendant, recorded while the tree is still whole.
process_tree() {
  local pid
  echo "$1"
  for pid in $(pgrep -P "$1" 2>/dev/null); do
    process_tree "$pid"
  done
}

# Ends process $1 and its descendants: TERM, then KILL after the grace. The
# tree is recorded first, so a descendant orphaned by its parent's exit is
# still ended. Returns zero once none is alive and $1 is reaped, non-zero if
# any still lives.
end_process_tree() {
  local tree pid signal live _
  tree="$(process_tree "$1")"
  for signal in TERM KILL; do
    for pid in $tree; do
      kill "-$signal" "$pid" 2>/dev/null || true
    done
    for _ in $(seq 1 "$PROBE_GRACE_POLLS"); do
      live=""
      for pid in $tree; do
        process_alive "$pid" && live=1
      done
      if [[ -z "$live" ]]; then
        wait "$1" 2>/dev/null || true
        return 0
      fi
      probe_poll
    done
  done
  return 1
}

# Waits for the attempt $1 to finish or the monotonic deadline $2 (ms) to pass.
# Returns the attempt's status, or 124 once the deadline passed and the
# attempt was ended and observed gone, or 125 when it could not be ended.
wait_bounded() {
  local child="$1" deadline="$2"
  while process_alive "$child"; do
    if (($(monotonic_ms) >= deadline)); then
      end_process_tree "$child" && return 124
      return 125
    fi
    probe_poll
  done
  wait "$child"
}

# probe_revocation DIR ANCHOR_MS WINDOW polls bob's sends from his removal at
# the monotonic millisecond ANCHOR_MS. A refusal counts only when its attempt
# completed by ANCHOR_MS + (WINDOW + 5) s; each attempt and each pause gets
# only the budget left. DIR/verdict ends as refused, late, accepted or, when an
# attempt past the deadline could not be ended, uncertain.
probe_revocation() {
  local dir="$1" anchor="$2" window="$3" deadline attempt=0 status now child
  deadline=$((anchor + (window + 5) * 1000))
  while :; do
    now="$(monotonic_ms)"
    if ((now >= deadline)); then
      printf 'accepted\n' >"$dir/verdict"
      return 0
    fi
    attempt=$((attempt + 1))
    run_aw_in "$BOB_DIR" mail send --plaintext --to alice \
      --subject "after-revocation-$attempt" --body "must not arrive" --json \
      >"$dir/out" 2>"$dir/stderr" &
    child=$!
    if wait_bounded "$child" "$deadline"; then
      status=0
    else
      status=$?
    fi
    now="$(monotonic_ms)"
    printf '%s\n' "$((now - anchor))" >"$dir/elapsed-ms"
    if ((status == 125)); then
      printf 'uncertain\n' >"$dir/verdict"
      return 0
    fi
    if ((status == 124 || now > deadline)); then
      printf 'late\n' >"$dir/verdict"
      return 0
    fi
    if ((status != 0)); then
      cp "$dir/out" "$dir/refusal.json"
      printf 'after-revocation-%s\n' "$attempt" >"$dir/refused-subject"
      printf 'refused\n' >"$dir/verdict"
      return 0
    fi
    probe_sleep "$(python3 -c 'import sys; print(min(5, max(0, int(sys.argv[1])) / 1000))' "$((deadline - now))")"
  done
}

# start_revocation_probe DIR ANCHOR_MS WINDOW runs the probe in the background
# as its own process group, which holds every command it starts.
start_revocation_probe() {
  set -m
  probe_revocation "$@" >"$1/probe.log" 2>&1 &
  REVOCATION_PROBE_PID=$!
  set +m
}

# Ends the probe's process group, an attempt in flight included, escalating to
# KILL, and keeps ownership until the group is observed gone; returns non-zero,
# still owning it, when processes of the group remain.
stop_revocation_probe() {
  local signal _
  [[ -n "${REVOCATION_PROBE_PID:-}" ]] || return 0
  for signal in TERM KILL; do
    kill "-$signal" -- "-$REVOCATION_PROBE_PID" 2>/dev/null || true
    for _ in $(seq 1 "$PROBE_GRACE_POLLS"); do
      if ! group_alive "$REVOCATION_PROBE_PID"; then
        wait "$REVOCATION_PROBE_PID" 2>/dev/null || true
        REVOCATION_PROBE_PID=""
        return 0
      fi
      probe_poll
    done
  done
  echo "UNCERTAIN: revocation probe group $REVOCATION_PROBE_PID still has live processes" >&2
  return 1
}
