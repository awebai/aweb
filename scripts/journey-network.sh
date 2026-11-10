#!/usr/bin/env bash
# Candidate runner endpoints agree with candidate-network.py's scoped aliases.
# Standalone host journeys retain their explicitly selected published endpoints.
journey_url() {
  local project="$1" service="$2" internal="$3" published="$4"
  if [[ -n "${CANDIDATE_RUNNER_NAME:-}" ]]; then
    printf 'http://%s-%s.test:%s\n' "$project" "$service" "$internal"
  else
    printf '%s\n' "$published"
  fi
}

journey_wait_health() {
  local service="$1" url="$2" attempts="${3:-60}" body error rc=0 attempt path=published-port
  [[ -z "${CANDIDATE_RUNNER_NAME:-}" ]] || path=compose-network
  error="$(mktemp)"
  for ((attempt=0; attempt<attempts; attempt++)); do
    if body="$(curl -fsS --connect-timeout 2 --max-time 5 "$url/health" 2>"$error")"; then
      rm -f "$error"
      printf '%s\n' "$body"
      return 0
    else
      rc=$?
    fi
    [[ "$attempt" == "$((attempts-1))" ]] || sleep 2
  done
  printf 'service reachability failure: service=%s address=%s/health path=%s curl_exit=%s\n' \
    "$service" "$url" "$path" "$rc" >&2
  cat "$error" >&2
  rm -f "$error"
  return 1
}
