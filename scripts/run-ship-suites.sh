#!/usr/bin/env bash
# Run the ship gate's independent suites so that one failing suite does not
# remove the evidence the others would have produced.
#
# make stops a recipe at the first failing line, so a flaky suite sitting ahead
# of another in `ship` silently takes the second one's coverage with it. The
# suites here do not depend on each other - nothing consumes another's output -
# so their results should be independent too.
#
# Two properties matter more than the running:
#
#   the exit status is nonzero if ANY suite failed. Continuing past a failure is
#   only safe if the aggregate still reports red, otherwise this is strictly
#   worse than stopping.
#
#   a suite that did not run is distinguishable from one that ran and passed.
#   Every suite is recorded as NOT RUN before anything starts, so a partial run
#   - a timeout, a cancelled CI job, an interrupt - reports the suites it never
#   reached rather than omitting them. Absence is how a partial run reads as a
#   full green.
#
# The summary prints from an EXIT trap for that reason: the ship gate runs under
# a 120-minute timeout with cancel-in-progress, so being killed part-way is a
# normal outcome and needs to be legible.
#
# That covers a graceful cancellation. SIGKILL runs no trap, so a hard kill - where
# a timeout or a cancellation ends up after its grace period - prints no summary at
# all. The exposure is bounded rather than closed: a hard-killed run is not green,
# so the CI conclusion still carries what the summary would have said.
#
# Usage: run-ship-suites.sh <make-target>...
#        MAKE=... to override the make used for each suite (the self-test does).
#
# Run with --self-test to prove the properties above against stub suites: one
# deliberate failure, and the suites behind it must still run and report.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAKE="${MAKE:-make}"

STATE=""

# Written before any suite starts, so the summary can name suites that never ran.
init_state() {
  STATE="$(mktemp)" || STATE=""
  if [[ -z "$STATE" || ! -f "$STATE" ]]; then
    printf 'FAIL: could not create the suite state file, so which suites ran could not be tracked\n' >&2
    return 1
  fi
  local suite
  for suite in "$@"; do
    printf '%s\tNOT RUN\n' "$suite" >> "$STATE"
  done
}

record() {
  local suite="$1" result="$2" tmp
  # An empty $STATE would make awk below read stdin and block rather than fail.
  if [[ -z "$STATE" || ! -f "$STATE" ]]; then
    printf 'FAIL: suite state vanished mid-run; results cannot be recorded\n' >&2
    exit 1
  fi
  tmp="$(mktemp)"
  awk -F'\t' -v s="$suite" -v r="$result" \
    'BEGIN { OFS="\t" } $1 == s { $2 = r } { print }' "$STATE" > "$tmp"
  mv -f "$tmp" "$STATE"
}

summarize() {
  # Criterion 3's whole deliverable is this summary, so losing it must complain
  # rather than produce nothing. Reachable only through an mktemp failure, but a
  # silent skip in a reporting path is what makes a partial run look like a full one.
  #
  # exit rather than return: this runs from the EXIT trap, and a trap's return value
  # does not set the script's exit status - measured, `return 1` here leaves a run
  # that printed FAIL exiting 0, which is the same defect one level down. `exit`
  # inside an EXIT trap overrides the status without re-entering the trap.
  if [[ -z "$STATE" || ! -f "$STATE" ]]; then
    printf '\nFAIL: no suite state was recorded, so which suites ran cannot be reported\n' >&2
    exit 1
  fi
  printf '\n=== ship suites: which ran and what they reported ===\n'
  local suite result failed=0 notrun=0
  while IFS=$'\t' read -r suite result; do
    printf '  %-10s %s\n' "$result" "$suite"
    [[ "$result" == "FAILED" ]] && failed=$((failed + 1))
    [[ "$result" == "NOT RUN" ]] && notrun=$((notrun + 1))
  done < "$STATE"
  printf '  ----\n'
  printf '  %s suite(s) failed, %s never ran\n' "$failed" "$notrun"
  if [[ "$notrun" -gt 0 ]]; then
    printf '  a suite reported NOT RUN did not execute; this run is not full evidence\n'
  fi
}

run_suites() {
  local suite status overall=0
  init_state "$@" || return 1
  # The summary must appear even when this script is killed part-way, which is
  # what a CI timeout or a concurrency cancellation looks like.
  trap summarize EXIT

  for suite in "$@"; do
    printf '\n=== ship suite: %s ===\n' "$suite"
    # Deliberately not `set -e`-guarded: a failure here must not stop the loop.
    "$MAKE" "$suite" && status=0 || status=$?
    if [[ "$status" -eq 0 ]]; then
      record "$suite" "PASSED"
      printf '=== ship suite %s: PASSED ===\n' "$suite"
    else
      record "$suite" "FAILED"
      overall=1
      printf '=== ship suite %s: FAILED (status %s) - continuing so the remaining suites still report ===\n' \
        "$suite" "$status"
    fi
  done

  # Any suite still NOT RUN after the loop means the list and the run disagree,
  # which would otherwise be invisible.
  if grep -q $'\tNOT RUN$' "$STATE"; then
    overall=1
  fi
  return "$overall"
}

# ------------------------------------------------------------------- self-test
#
# Stub suites rather than the real ones: the real gate takes over an hour and
# needs Docker plus sibling checkouts, and what changed here is the sequencing
# and the aggregation, which stubs exercise exactly.
self_test() {
  local work stub out status
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN

  # A make that fails for one named target and succeeds for the others.
  stub="$work/make-stub"
  cat > "$stub" <<'STUB'
#!/usr/bin/env bash
echo "stub suite running: $1"
[[ "$1" == "suite-b" ]] && { echo "stub suite failing: $1" >&2; exit 3; }
exit 0
STUB
  chmod +x "$stub"

  echo "self-test: one failing suite must not stop the suites behind it, and the run must still be red"
  out="$(MAKE="$stub" bash "${BASH_SOURCE[0]}" suite-a suite-b suite-c 2>&1)" && status=0 || status=$?

  local problems=0

  # The whole point: nonzero overall.
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL: a failing suite produced exit 0, which is worse than stopping at the failure\n' >&2
    problems=1
  fi

  # The suites behind the failure must have run, not merely been listed.
  local expected
  for expected in 'PASSED     suite-a' 'FAILED     suite-b' 'PASSED     suite-c'; do
    if ! grep -Fq "$expected" <<< "$out"; then
      printf 'FAIL: summary does not report "%s"; the suites behind a failure did not run or did not report\n' "$expected" >&2
      problems=1
    fi
  done
  if ! grep -Fq 'stub suite running: suite-c' <<< "$out"; then
    printf 'FAIL: suite-c never executed, so a failure ahead of it still removes its coverage\n' >&2
    problems=1
  fi
  if ! grep -Fq '1 suite(s) failed, 0 never ran' <<< "$out"; then
    printf 'FAIL: the aggregate count does not name one failure and no unrun suites\n' >&2
    problems=1
  fi

  if [[ "$problems" -ne 0 ]]; then
    printf -- '--- the run being judged ---\n%s\n' "$out" >&2
    return 1
  fi
  printf '  ok   suite-b failed, suite-c still ran, exit was %s, summary named all three\n' "$status"

  # A suite whose command cannot be executed at all must still be reported,
  # rather than counting as a suite that passed quietly.
  echo "self-test: a suite whose command cannot be executed must report FAILED, not pass quietly"
  out="$(MAKE="$work/no-such-make" bash "${BASH_SOURCE[0]}" suite-a suite-b 2>&1)" && status=0 || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL: every suite failed to launch and the run still exited 0\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$out" >&2
    return 1
  fi
  if ! grep -Fq 'FAILED     suite-a' <<< "$out"; then
    printf 'FAIL: a suite whose command could not be executed is not reported\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$out" >&2
    return 1
  fi
  printf '  ok   an unlaunchable suite reports FAILED and the run is red\n'

  # The NOT RUN path, which is the one that makes a partial run legible. A CI
  # timeout or a concurrency cancellation kills this script part-way, and the
  # suites it never reached have to say so rather than be omitted.
  echo "self-test: a run killed part-way must report the suites it never reached as NOT RUN"
  cat > "$stub" <<'STUB'
#!/usr/bin/env bash
echo "stub suite running: $1"
[[ "$1" == "suite-b" ]] && sleep 60
exit 0
STUB
  chmod +x "$stub"

  local log="$work/killed.log" pid
  MAKE="$stub" bash "${BASH_SOURCE[0]}" suite-a suite-b suite-c > "$log" 2>&1 &
  pid="$!"
  # Wait for the blocking suite to be under way, then interrupt the run itself.
  local waited=0
  while ! grep -Fq 'stub suite running: suite-b' "$log" 2>/dev/null; do
    sleep 0.2
    waited=$((waited + 1))
    if [[ "$waited" -gt 100 ]]; then
      printf 'FAIL: the blocking suite never started, so this arm never reached the state it tests\n' >&2
      kill "$pid" 2>/dev/null
      return 1
    fi
  done
  kill -TERM "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null && status=0 || status=$?

  if ! grep -Fq 'NOT RUN    suite-c' "$log"; then
    printf 'FAIL: a suite the run never reached is not reported as NOT RUN; absence is how a partial run reads as a full green\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$(cat "$log")" >&2
    return 1
  fi
  if ! grep -Fq 'PASSED     suite-a' "$log"; then
    printf 'FAIL: the suite that did complete before the interrupt is not reported\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$(cat "$log")" >&2
    return 1
  fi
  if ! grep -Fq 'this run is not full evidence' "$log"; then
    printf 'FAIL: a run with an unreached suite does not say so\n' >&2
    return 1
  fi
  printf '  ok   an interrupted run reports suite-a PASSED and suite-c NOT RUN, and says it is not full evidence\n'

  # The summary is criterion 3's deliverable, so losing it must be red rather than
  # quiet. My first attempt at that guard used `return 1` from the EXIT trap, which
  # printed FAIL and exited 0 - the same shape as the defect this runner exists to
  # remove, one level down. So this arm asserts the status, not the text.
  echo "self-test: losing the suite state must be red, not a missing summary"
  local probe="$work/no-state.sh"
  sed 's|^  STATE="\$(mktemp)" \|\| STATE=""|  STATE=""|' "${BASH_SOURCE[0]}" > "$probe"
  if ! grep -Fq '  STATE=""' "$probe"; then
    printf 'FAIL: the no-state probe did not apply, so this arm never reached the state it tests\n' >&2
    return 1
  fi
  out="$(MAKE="$stub" bash "$probe" suite-a 2>&1)" && status=0 || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL: a run that could not report which suites ran still exited 0\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$out" >&2
    return 1
  fi
  # Either guard may catch it - init_state at creation, or summarize as a backstop -
  # so the arm asserts the property rather than which one fired.
  if ! grep -q 'suite state' <<< "$out"; then
    printf 'FAIL: the run was red but did not say the suite state was lost\n' >&2
    printf -- '--- the run being judged ---\n%s\n' "$out" >&2
    return 1
  fi
  printf '  ok   a lost summary is red and says so, rather than printing nothing\n'

  echo "self-test passed: a failure does not stop the others, the aggregate stays red, an unreached suite reads as NOT RUN, a lost summary is red"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit "$?"
fi

if [[ "$#" -eq 0 ]]; then
  echo "usage: $(basename "$0") <make-target>..." >&2
  exit 2
fi

cd "$ROOT"
run_suites "$@"
