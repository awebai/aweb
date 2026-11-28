# The OSS journey's revocation probe, sourced by scripts/e2e-oss-user-journey.sh
# and by scripts/test_revocation_probe.py. The caller provides run_aw_in and
# BOB_DIR. monotonic_seconds and probe_sleep are the probe's clock.

# Seconds on the monotonic clock, which every process on the host shares.
monotonic_seconds() {
  python3 -c 'import time; print(int(time.monotonic()))'
}

probe_sleep() {
  sleep "$1"
}

# How often wait_bounded looks at an attempt in flight.
probe_poll() {
  sleep 1
}

# Waits for the attempt $1 to finish or the monotonic deadline $2 to pass.
# Returns the attempt's status, or 124 when the deadline passed first.
wait_bounded() {
  local child="$1" deadline="$2"
  while kill -0 "$child" 2>/dev/null; do
    if (($(monotonic_seconds) >= deadline)); then
      return 124
    fi
    probe_poll
  done
  wait "$child"
}

# probe_revocation DIR ANCHOR WINDOW polls bob's sends from his removal at the
# monotonic second ANCHOR. A refusal counts only when its attempt completed by
# ANCHOR + WINDOW + 5; each attempt and each pause gets only the budget left.
# DIR/verdict ends as refused, late or accepted.
probe_revocation() {
  local dir="$1" anchor="$2" window="$3" deadline attempt=0 status now child
  deadline=$((anchor + window + 5))
  while :; do
    now="$(monotonic_seconds)"
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
    now="$(monotonic_seconds)"
    if ((status == 124 || now > deadline)); then
      printf '%s\n' "$((now - anchor))" >"$dir/seconds"
      printf 'late\n' >"$dir/verdict"
      return 0
    fi
    if ((status != 0)); then
      cp "$dir/out" "$dir/refusal.json"
      printf 'after-revocation-%s\n' "$attempt" >"$dir/refused-subject"
      printf '%s\n' "$((now - anchor))" >"$dir/seconds"
      printf 'refused\n' >"$dir/verdict"
      return 0
    fi
    probe_sleep "$((deadline - now < 5 ? deadline - now : 5))"
  done
}

# start_revocation_probe DIR ANCHOR WINDOW runs the probe in the background as
# its own process group, which holds every command it starts.
start_revocation_probe() {
  set -m
  probe_revocation "$@" >"$1/probe.log" 2>&1 &
  REVOCATION_PROBE_PID=$!
  set +m
}

# Ends the probe's process group, an attempt still in flight included, and
# reaps the probe.
stop_revocation_probe() {
  [[ -n "${REVOCATION_PROBE_PID:-}" ]] || return 0
  kill -TERM -- "-$REVOCATION_PROBE_PID" 2>/dev/null || true
  wait "$REVOCATION_PROBE_PID" 2>/dev/null || true
  REVOCATION_PROBE_PID=""
}
