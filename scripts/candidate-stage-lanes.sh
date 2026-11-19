#!/usr/bin/env bash
# docs/release.md: every selected stage keeps its own outcome and evidence.
# Sourced by candidate-suite.sh after defining the stages and prepare_stage.
run_stage() (
  local stage="$1" started=$SECONDS status result=PASSED coverage=""
  local -a statuses
  set +e
  ( set -e; prepare_stage "$stage"; "$stage" ) 2>&1 | tee "$log_dir/$stage.log"
  statuses=("${PIPESTATUS[@]}")
  status="${statuses[0]}"
  [[ "${statuses[1]}" == 0 ]] || status="${statuses[1]}"
  if [[ "$stage" == user-paths && -f "$log_dir/user-paths/coverage-summary.txt" ]]; then
    coverage="$(cat "$log_dir/user-paths/coverage-summary.txt")" || exit 1
    printf 'user-paths coverage: %s\n' "$coverage"
  fi
  [[ "$status" == 0 ]] || result=FAILED
  printf '%s\t%s\t%s.log\t%ss\t%s\n' "$stage" "$result" "$stage" "$((SECONDS-started))" "$coverage" \
    > "$log_dir/$stage.result" || exit 1
  exit "$status"
)

run_parallel_stages() (
  local unit_pid integration_pid="" event status=0
  # Unit's driver sends READY only after source/image preparation and private
  # services exist. Until then integration must not mutate the source/builder.
  mkfifo "$log_dir/unit-ready.fifo"
  exec 8<> "$log_dir/unit-ready.fifo"
  trap 'rm -f "$log_dir/unit-ready.fifo"' EXIT
  (
    trap 'printf "FINISHED\n" >&8' EXIT
    export AWEB_UNIT_READY_FD=8
    run_stage unit
  ) &
  unit_pid=$!
  IFS= read -r event <&8
  if [[ "$event" == READY ]]; then
    node_ready=1
    run_stage integration &
    integration_pid=$!
  else
    printf 'Unit isolation was not established. Inspect unit.log and fix preparation before running integration.\n' >&2
    status=1
  fi
  # Both lanes finish before their parent removes any run-owned resource.
  wait "$unit_pid" || status=1
  if [[ -n "$integration_pid" ]]; then wait "$integration_pid" || status=1; fi
  exec 8>&-
  exit "$status"
)

collect_stage_results() {
  local stage
  : > "$log_dir/summary.tsv"
  for stage in $stages; do
    if [[ -f "$log_dir/$stage.result" ]]; then
      cat "$log_dir/$stage.result" >> "$log_dir/summary.tsv" || return 1
    fi
  done
}

record_completed_stages() {
  local stage saw_failure=0 missing=0
  for stage in $pending; do
    if [[ -f "$LOG_DIR/summary.tsv" ]] && grep -q "^$stage"$'\tPASSED\t' "$LOG_DIR/summary.tsv"; then
      record "$stage" passed "$LOG_DIR/$stage.log" || return 1
    elif [[ -f "$LOG_DIR/$stage.log" ]]; then
      record "$stage" failed "$LOG_DIR/$stage.log" || return 1
      saw_failure=1
    else
      missing=1
    fi
  done
  if [[ "$missing" == 1 && "$saw_failure" == 0 ]]; then
    record setup failed "$run_log" || return 1
    return 1
  fi
  [[ "$saw_failure" == 0 ]]
}
