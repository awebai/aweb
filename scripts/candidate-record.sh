#!/usr/bin/env bash
# Sourced by the tree-lock holder. Only this invocation's completed proof is reusable.
candidate_recorded=0
record_candidate_row() {
  local stage="$1" result="$2" source="$3" log note=""
  log="$LEDGER_LOGS/${KEY:0:12}-$stage-$run_id.log"
  cp "$source" "$log" || return 1
  [[ -z "${GATE_RERUN_REASON:-}" ]] || note="rerun after $GATE_RERUN_REASON"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$KEY" "$stage" "$result" "$SOURCE_SHA" "" "$log" "$OWNER" "$started" "$finished" "$note" >>"$LEDGER"
}
finalize_candidate() {
  local status="$1" interrupted=0 stage
  [[ "$candidate_recorded" == 0 ]] || return "$status"
  candidate_recorded=1
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [[ "$status" != 130 && "$status" != 143 ]] || interrupted=1
  if [[ ! -f "$LOG_DIR/run-id" || "$(cat "$LOG_DIR/run-id")" != "$run_id" ]]; then
    printf 'gate: no matching invocation; nothing recorded\n' >&2
    [[ "$status" != 0 ]] || status=1
    return "$status"
  fi
  if [[ "$interrupted" == 1 ]]; then
    # A partial run must never be read as complete, even if all its completed
    # stages passed. The interrupted stage has no manufactured code verdict.
    write_candidate_interruption "$status"
  fi
  for stage in $pending; do
    if [[ -s "$LOG_DIR/$stage.log" && -f "$LOG_DIR/summary.tsv" ]] && \
       awk -F'\t' -v stage="$stage" '$1 == stage && $2 == "PASSED" && $3 == stage ".log" && $4 ~ /^[0-9]+s$/ {n++} END {exit !(n == 1)}' "$LOG_DIR/summary.tsv"; then
      record_candidate_row "$stage" passed "$LOG_DIR/$stage.log" || return 1
    elif [[ "$interrupted" == 1 ]]; then
      continue
    elif [[ -s "$LOG_DIR/$stage.log" ]]; then
      record_candidate_row "$stage" failed "$LOG_DIR/$stage.log" || return 1
      status=1
      break
    else
      printf 'gate: missing completed proof for %s\n' "$stage" >> "$run_log"
      record_candidate_row setup failed "$run_log" || return 1
      status=1
      break
    fi
  done
  # Cleanup remains an independent receipt on interrupted runs; a missing
  # verdict is not a product failure and cannot erase the raw interruption.
  if [[ "$interrupted" == 0 ]] && { [[ ! -f "$LOG_DIR/wrapper-verdict.log" ]] \
     || ! grep -q '^candidate gate cleanup PASSED$' "$LOG_DIR/wrapper-verdict.log"; }; then
    record_candidate_row cleanup failed "$run_log" || return 1
    status=1
  fi
  return "$status"
}
write_candidate_interruption() {
  local status="$1" cleanup=absent observed
  observed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! grep -q $'^run\tINTERRUPTED\t' "$LOG_DIR/summary.tsv" 2>/dev/null; then
    printf 'run\tINTERRUPTED\tinterruption.tsv\t0s\texit=%s\n' "$status" >> "$LOG_DIR/summary.tsv"
  fi
  if [[ -f "$LOG_DIR/wrapper-verdict.log" ]]; then
    if grep -q '^candidate gate cleanup PASSED$' "$LOG_DIR/wrapper-verdict.log"; then
      cleanup=passed
    elif grep -q '^candidate gate cleanup FAILED$' "$LOG_DIR/wrapper-verdict.log"; then
      cleanup=failed
    fi
  fi
  printf '%s\t%s\t%s\tcleanup=%s\tchild_exit=%s\twriter_exit=%s\n' \
    "$run_id" "$status" "$observed" "$cleanup" "${candidate_child_status:-unobserved}" "${candidate_writer_status:-unobserved}" > "$LOG_DIR/interruption.tsv"
}
finish_candidate_output() {
  candidate_writer_status=0
  if [[ -n "${candidate_writer:-}" ]]; then
    wait "$candidate_writer" || candidate_writer_status=$?
  fi
  [[ -z "${output_pipe:-}" ]] || rm -f "$output_pipe"
}
candidate_interrupted() {
  local status="$1" stop_signal="$2"
  trap '' INT TERM
  finalize_candidate "$status" || true
  if [[ -n "${candidate_job:-}" ]]; then
    kill -s "$stop_signal" "$candidate_job" 2>/dev/null || true
    candidate_child_status=0
    wait "$candidate_job" || candidate_child_status=$?
  fi
  finish_candidate_output
  # Only the final child-owned verdict establishes cleanup. Waiting for a
  # vanished process alone never supplies a successful cleanup receipt.
  if [[ -f "$LOG_DIR/run-id" && "$(cat "$LOG_DIR/run-id")" == "$run_id" ]]; then
    write_candidate_interruption "$status"
  fi
  exit "$status"
}
