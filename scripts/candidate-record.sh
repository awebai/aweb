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
stage_already_recorded() {
  grep -qx -- "$1" "$LOG_DIR/recorded-stages" 2>/dev/null
}
record_stage_targets() {
  local only="$1" retained="$2" entry verdict relative elapsed note stage result target_log target_error=0
  [[ -f "$retained/summary.tsv" ]] || return 0
  while IFS=$'\t' read -r entry verdict relative elapsed note; do
    [[ "$entry" =~ ^[a-z-]+/[A-Za-z0-9_.-]+$ ]] || continue
    stage="${entry%%/*}"
    [[ " $pending " == *" $stage "* ]] || continue
    if [[ -n "$only" ]]; then
      [[ "$stage" == "$only" ]] || continue
    elif stage_already_recorded "$stage"; then
      continue
    fi
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
    record_candidate_row "$entry" "$result" "$target_log" "${note:+$note, }${elapsed}" || return 2
    [[ "$result" == passed ]] || target_error=1
  done < "$retained/summary.tsv"
  return "$target_error"
}
# The output reader: copies the gate's output to the run log and records each
# stage in the ledger as soon as it passes, so a later kill keeps its proof.
record_stages_as_they_pass() {
  local line
  exec 3>>"$run_log"
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s\n' "$line" >&3
    if [[ "$line" =~ ^candidate\ stage-verdict:\ ([a-z-]+)\ PASSED$ ]]; then
      record_passed_stage "${BASH_REMATCH[1]}" || printf 'gate: could not record %s as it passed\n' "${BASH_REMATCH[1]}" >&3
    fi
  done
}
record_passed_stage() {
  local stage="$1" stage_log="$LEDGER_LOGS/${KEY:0:12}-$1-$run_id.log"
  local retained="$LEDGER_LOGS/${KEY:0:12}-evidence-$run_id"
  [[ " $pending " == *" $stage "* ]] || return 0
  [[ -f "$LOG_DIR/run-id" && "$(cat "$LOG_DIR/run-id")" == "$run_id" ]] || return 0
  candidate_stage_passed "$stage" "$LOG_DIR/summary.tsv" "$LOG_DIR/$stage.log" || return 0
  # An interruption closes recording before it freezes the eligible stages.
  [[ ! -e "$LOG_DIR/recording-closed" ]] || return 0
  retain_candidate_evidence || return 1
  cp "$LOG_DIR/$stage.log" "$stage_log" || return 1
  candidate_stage_passed "$stage" "$retained/summary.tsv" "$stage_log" || return 1
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  record_candidate_row "$stage" passed "$stage_log" || return 1
  printf '%s\n' "$stage" >> "$LOG_DIR/recorded-stages" || return 1
  record_stage_targets "$stage" "$retained"
  case "$?" in
    0) ;;
    1) printf '%s\n' "$stage" >> "$LOG_DIR/recorded-target-failures" || return 1 ;;
    *) return 1 ;;
  esac
}
candidate_stage_passed() {
  local stage="$1" summary="$2" log="$3"
  [[ -s "$log" && -f "$summary" ]] && \
    awk -F'\t' -v stage="$stage" '$1 == stage && $2 == "PASSED" && $3 == stage ".log" && $4 ~ /^[0-9]+s$/ {n++} END {exit !(n == 1)}' "$summary"
}
finalize_candidate() {
  local status="$1" interrupted=0 incomplete=0 stage stage_log targets cleanup=absent
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
    stage_already_recorded "$stage" && continue
    stage_log="$LEDGER_LOGS/${KEY:0:12}-$stage-$run_id.log"
    if [[ ! -f "$LOG_DIR/$stage.log" ]]; then
      if grep -q "^$stage"$'\tNOT-RUN\t' "$retained/summary.tsv" 2>/dev/null; then
        # The suite stopped after a failed static stage; that failure is recorded.
        printf 'gate: %s not run after static FAILED\n' "$stage" >> "$run_log"
      elif [[ "$interrupted" == 0 ]]; then
        incomplete=1
        printf 'gate: missing completed proof for %s\n' "$stage" >> "$run_log"
      fi
      continue
    fi
    cp "$LOG_DIR/$stage.log" "$stage_log" || return 1
    if [[ " $eligible " == *" $stage "* ]] && candidate_stage_passed "$stage" "$retained/summary.tsv" "$stage_log"; then
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
  record_stage_targets "" "$retained"
  targets=$?
  [[ "$targets" != 2 ]] || return 1
  if [[ -s "$LOG_DIR/recorded-target-failures" ]]; then targets=1; fi
  if [[ "$targets" != 0 && "$interrupted" == 0 ]]; then status=1; fi
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
  [[ ! -d "$LOG_DIR" ]] || : > "$LOG_DIR/recording-closed"
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
