#!/usr/bin/env bash
# Sourced by the tree-lock holder. Only this invocation's completed proof is reusable.
candidate_recorded=0
record_candidate_row() {
  local entry="$1" result="$2" log="$3" note="${4:-}"
  if [[ -n "${GATE_RERUN_REASON:-}" ]]; then
    note="${note:+$note, }rerun after $GATE_RERUN_REASON"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$KEY" "$entry" "$result" "$SOURCE_SHA" "" "$log" "$OWNER" "$started" "$finished" "$note" >>"$LEDGER"
}
retain_candidate_evidence() {
  local relative source target="$LEDGER_LOGS/${KEY:0:12}-evidence-$run_id"
  # The stage output contains only the child's tail. Keep its original report
  # beside the ledger on every outcome, before an ephemeral VM is deleted.
  for relative in summary.tsv test-egress/suite.log; do
    source="$LOG_DIR/$relative"
    [[ -e "$source" || -L "$source" ]] || continue
    [[ -f "$source" && ! -L "$source" ]] || return 1
    mkdir -p "$(dirname "$target/$relative")" || return 1
    cp "$source" "$target/$relative" || return 1
  done
}
finalize_candidate() {
  local status="$1" interrupted=0 incomplete=0 target_error=0 stage stage_log
  local entry verdict relative elapsed note result target_log
  local retained="$LEDGER_LOGS/${KEY:0:12}-evidence-$run_id"
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
  retain_candidate_evidence || return 1
  for stage in $pending; do
    stage_log="$LEDGER_LOGS/${KEY:0:12}-$stage-$run_id.log"
    if [[ ! -f "$LOG_DIR/$stage.log" ]]; then
      if [[ "$interrupted" == 0 ]]; then
        incomplete=1
        printf 'gate: missing completed proof for %s\n' "$stage" >> "$run_log"
      fi
      continue
    fi
    cp "$LOG_DIR/$stage.log" "$stage_log" || return 1
    if [[ -s "$stage_log" && -f "$retained/summary.tsv" ]] && \
       awk -F'\t' -v stage="$stage" '$1 == stage && $2 == "PASSED" && $3 == stage ".log" && $4 ~ /^[0-9]+s$/ {n++} END {exit !(n == 1)}' "$retained/summary.tsv"; then
      record_candidate_row "$stage" passed "$stage_log" || return 1
    elif [[ "$interrupted" == 0 ]]; then
      record_candidate_row "$stage" failed "$stage_log" || return 1
      status=1
    fi
  done
  if [[ "$incomplete" == 1 ]]; then
    record_candidate_row setup failed "$run_log" || return 1
    status=1
  fi
  if [[ -f "$retained/summary.tsv" ]]; then
    while IFS=$'\t' read -r entry verdict relative elapsed note; do
      [[ "$entry" =~ ^(checks|user-paths|unit|artifacts|integration)/[A-Za-z0-9_.-]+$ ]] || continue
      stage="${entry%%/*}"
      [[ " $pending " == *" $stage "* ]] || continue
      case "$relative" in
        "$stage.log") target_log="$LEDGER_LOGS/${KEY:0:12}-$stage-$run_id.log" ;;
        test-egress/suite.log) target_log="$retained/$relative" ;;
        *) target_error=1; continue ;;
      esac
      if [[ ! -f "$target_log" ]]; then target_error=1; continue; fi
      case "$verdict" in
        PASSED) result=passed ;;
        FAILED) result=failed ;;
        SKIPPED) result=skipped ;;
        *) target_error=1; continue ;;
      esac
      record_candidate_row "$entry" "$result" "$target_log" "${note:+$note, }${elapsed}" || return 1
      if [[ "$result" != passed && "$interrupted" == 0 ]]; then status=1; fi
    done < "$retained/summary.tsv"
    if [[ "$target_error" != 0 && "$interrupted" == 0 ]]; then status=1; fi
  fi
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
    retain_candidate_evidence || printf 'gate: evidence retention failed after interruption\n' >&2
  fi
  exit "$status"
}
