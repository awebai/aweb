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
candidate_stage_passed() {
  local stage="$1" summary="$2" log="$3"
  [[ -s "$log" && -f "$summary" ]] && \
    awk -F'\t' -v stage="$stage" '$1 == stage && $2 == "PASSED" && $3 == stage ".log" && $4 ~ /^[0-9]+s$/ {n++} END {exit !(n == 1)}' "$summary"
}
finalize_candidate() {
  local status="$1" interrupted=0 incomplete=0 target_error=0 stage stage_log
  local entry verdict relative elapsed note result target_log cleanup=absent
  local eligible="${2-$pending}"
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
  if [[ -f "$LOG_DIR/wrapper-verdict.log" ]]; then
    if grep -qx 'candidate gate cleanup FAILED' "$LOG_DIR/wrapper-verdict.log"; then
      cleanup=failed
    elif grep -qx 'candidate gate cleanup PASSED' "$LOG_DIR/wrapper-verdict.log"; then
      cleanup=passed
    fi
  fi
  if [[ "$interrupted" == 1 ]]; then
    if [[ "$cleanup" == passed ]]; then
      record_candidate_row cleanup passed "$run_log" || return 1
    else
      record_candidate_row cleanup failed "$run_log" "cleanup=$cleanup" || return 1
      eligible=""
    fi
    write_candidate_interruption "$status" "$cleanup" || return 1
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
    if [[ " $eligible " == *" $stage "* ]] && candidate_stage_passed "$stage" "$retained/summary.tsv" "$stage_log"; then
      # The checks-only caller needs to know whether the native harness
      # pytest was delegated to unit before it reuses this stage.
      local stage_note=""
      if [[ "$stage" == checks ]]; then
        stage_note="$(awk -F '\t' '$1 == "checks" { print $5 }' "$retained/summary.tsv")" || return 1
      fi
      record_candidate_row "$stage" passed "$stage_log" "$stage_note" || return 1
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
  if [[ "$interrupted" == 0 && "$cleanup" != passed ]]; then
    record_candidate_row cleanup failed "$run_log" || return 1
    status=1
  fi
  return "$status"
}
write_candidate_interruption() {
  local status="$1" cleanup="$2" observed
  observed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! grep -q $'^run\tINTERRUPTED\t' "$LOG_DIR/summary.tsv" 2>/dev/null; then
    printf 'run\tINTERRUPTED\tinterruption.tsv\t0s\texit=%s\n' "$status" >> "$LOG_DIR/summary.tsv"
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
  local status="$1" stop_signal="$2" stage eligible=""
  trap '' INT TERM
  # Freeze the eligible stages before signalling the child. Its final cleanup
  # verdict determines whether any of these stages can be reused.
  if [[ -f "$LOG_DIR/run-id" && "$(cat "$LOG_DIR/run-id")" == "$run_id" ]]; then
    for stage in $pending; do
      if candidate_stage_passed "$stage" "$LOG_DIR/summary.tsv" "$LOG_DIR/$stage.log"; then
        eligible="$eligible $stage"
      fi
    done
  fi
  if [[ -n "${candidate_job:-}" ]]; then
    kill -s "$stop_signal" "$candidate_job" 2>/dev/null || true
    candidate_child_status=0
    wait "$candidate_job" || candidate_child_status=$?
  fi
  finish_candidate_output
  finalize_candidate "$status" "$eligible" || true
  exit "$status"
}
