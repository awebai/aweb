#!/usr/bin/env bash
# Sourced by the gate after declaring its per-run resource names.
cleanup_work() {
  case "$work" in
    /|"$ROOT"|"$ROOT"/*) return 1 ;;
    */aweb-candidate-work.*) rm -rf -- "$work" || return 1 ;;
    *) return 1 ;;
  esac
  # Includes run-owned Compose overlays, even after their CLI was SIGKILLed.
  [[ ! -e "$work" ]]
}

# Records why cleanup failed beside the resources it checked.
cleanup_failure() {
  cleanup_status=1
  printf 'cleanup-failure\t%s\n' "$1" >> "$LOG_DIR/owned-resources.tsv"
}

cleanup() {
  local original_status="${1:-$?}" cleanup_status=0 resource filter ids item
  local -a filters list remove
  trap - EXIT
  trap '' INT TERM
  set +e
  filters=("aweb.candidate-gate=$resource_label")
  for item in "${suite_projects[@]}"; do filters+=("com.docker.compose.project=$item"); done
  # Stop the runner before removing anything it could recreate.
  # A signal that reached the runner's docker run --rm CLI also makes the
  # daemon remove it, so this removal can fail with "already in progress"
  # while the runner disappears. Here and below, absence is the proof, not the
  # removal command's exit.
  if docker container inspect "$runner_name" >/dev/null 2>&1; then
    docker rm -fv "$runner_name" >/dev/null 2>&1
    for _ in {1..100}; do
      docker container inspect "$runner_name" >/dev/null 2>&1 || break
      sleep .1
    done
    ! docker container inspect "$runner_name" >/dev/null 2>&1 || cleanup_failure "runner still present"
  fi
  while IFS=$'\t' read -r resource item; do
    [[ "$resource" != compose-project ]] || filters+=("com.docker.compose.project=$item")
  done < "$LOG_DIR/owned-resources.tsv"
  for resource in container network volume image; do
    case "$resource" in
      container) list=(docker ps -aq); remove=(docker rm -fv) ;;
      network) list=(docker network ls -q); remove=(docker network rm) ;;
      volume) list=(docker volume ls -q); remove=(docker volume rm) ;;
      image) list=(docker images -q); remove=(docker image rm -f) ;;
    esac
    for filter in "${filters[@]}"; do
      ids="$("${list[@]}" --filter "label=$filter" | sort -u)" || cleanup_failure "cannot list $resource $filter"
      for item in $ids; do
        printf '%s\t%s\n' "$resource" "$item" >> "$LOG_DIR/owned-resources.tsv"
        "${remove[@]}" "$item" >/dev/null 2>&1
      done
      ids="$("${list[@]}" --filter "label=$filter")" || cleanup_failure "cannot list $resource $filter"
      printf 'absence-filter\t%s\t%s\t%s\n' "$resource" "$filter" "${ids:-none}" >> "$LOG_DIR/owned-resources.tsv"
      if [[ -n "$ids" ]]; then
        printf 'candidate gate cleanup residue: %s %s %s\n' "$resource" "$filter" "$ids" >&2
        cleanup_failure "$resource residue $filter"
      fi
    done
  done
  # Every builder name in this manifest was allocated by this run's wrapper.
  # The host owns its own buildx config; nested configs may already be gone.
  while IFS=$'\t' read -r resource item; do
    [[ "$resource" == builder ]] || continue
    BUILDX_CONFIG="$buildx_config" docker buildx rm --force "$item" >/dev/null 2>&1
    if docker container inspect "buildx_buildkit_${item}0" >/dev/null 2>&1; then
      docker rm -fv "buildx_buildkit_${item}0" >/dev/null 2>&1
    fi
    if docker volume inspect "buildx_buildkit_${item}0_state" >/dev/null 2>&1; then
      docker volume rm "buildx_buildkit_${item}0_state" >/dev/null 2>&1
    fi
    ! docker container inspect "buildx_buildkit_${item}0" >/dev/null 2>&1 || cleanup_failure "builder container $item still present"
    ! docker volume inspect "buildx_buildkit_${item}0_state" >/dev/null 2>&1 || cleanup_failure "builder volume $item still present"
    ! BUILDX_CONFIG="$buildx_config" docker buildx inspect "$item" >/dev/null 2>&1 || cleanup_failure "builder $item still present"
  done < "$LOG_DIR/owned-resources.tsv"
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker image rm "$IMAGE" >/dev/null 2>&1
  fi
  ! docker image inspect "$IMAGE" >/dev/null 2>&1 || cleanup_failure "gate image still present"
  # A daemon outage must not look like successful absence checks.
  docker info >/dev/null 2>&1 || cleanup_failure "docker daemon unavailable"
  cleanup_work || cleanup_failure "work directory not removed"
  printf 'absence-check\tstatus=%s\n' "$cleanup_status" >> "$LOG_DIR/owned-resources.tsv"
  if [[ -f "$LOG_DIR/host-before.json" ]]; then
    python3 "$ROOT/scripts/candidate-host-pressure.py" settle \
      "$LOG_DIR/host-before.json" "$LOG_DIR" || cleanup_failure "host resources not recovered"
  else
    cleanup_failure "no host baseline"
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    printf 'candidate gate cleanup FAILED\n' | tee -a "$LOG_DIR/wrapper-verdict.log" >&2
  else
    printf 'candidate gate cleanup PASSED\n' | tee -a "$LOG_DIR/wrapper-verdict.log"
  fi
  [[ "$original_status" -ne 0 ]] && exit "$original_status"
  exit "$cleanup_status"
}
