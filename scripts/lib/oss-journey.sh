# Helpers of scripts/e2e-oss-user-journey.sh, sourced by the journey and by its
# focused tests (scripts/test_oss_user_journey.py), so both run the same code.
# They use the journey's globals (pass, fail, PROJECT, the port and customer
# directory variables) and its set -euo pipefail.

canonicalize_dir() {
  local dir="$1"
  bash -c 'cd "$1" && pwd -P' _ "$dir"
}

# Docker resolves a bind source on the daemon's host. Inside the candidate
# runner the daemon is the host's, and only the run-owned bind root has the same
# path on both sides, so the journey's files live there when it is set.
journey_temp_root() {
  local root="${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}"
  if [[ -n "${AWEB_DOCKER_BIND_ROOT:-}" && ( "$root" != /* || ! -d "$root" ) ]]; then
    echo "FATAL: AWEB_DOCKER_BIND_ROOT must be an existing absolute directory: $root" >&2
    return 2
  fi
  canonicalize_dir "$root"
}

allocate_service_ports() {
  if [[ -n "${CANDIDATE_RUNNER_NAME:-}" ]]; then
    AWEB_PORT=8000
    AWID_PORT=8010
    return 0
  fi
  # Replacing a service behind the same published port can leave stale TCP
  # forwarding tuples on Docker Desktop. Back-to-back journeys must not reuse
  # fixed ports. Allocate on the daemon, not in the runner's network namespace.
  if [[ -n "$AWEB_PORT" && -n "$AWID_PORT" ]]; then
    return 0
  fi
  PORT_ALLOCATOR="$PROJECT-ports"
  docker run -d --name "$PORT_ALLOCATOR" \
    --label "aweb.e2e.project=$PROJECT" \
    --memory 32m --pids-limit 16 \
    -p "${AWEB_PORT:-0}:8000" -p "${AWID_PORT:-0}:8010" \
    --entrypoint /bin/sleep redis:7-alpine infinity >/dev/null
  AWEB_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8000/tcp") 0).HostPort}}' "$PORT_ALLOCATOR")"
  AWID_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8010/tcp") 0).HostPort}}' "$PORT_ALLOCATOR")"
  [[ "$AWEB_PORT" =~ ^[0-9]+$ && "$AWID_PORT" =~ ^[0-9]+$ \
    && "$AWEB_PORT" -gt 0 && "$AWEB_PORT" -le 65535 \
    && "$AWID_PORT" -gt 0 && "$AWID_PORT" -le 65535 \
    && "$AWEB_PORT" != "$AWID_PORT" ]]
}

release_service_ports() {
  if [[ -n "$PORT_ALLOCATOR" ]]; then
    docker rm -fv "$PORT_ALLOCATOR" >/dev/null || return
    PORT_ALLOCATOR=""
  fi
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    pass=$((pass + 1))
  else
    echo "  FAIL: $label (expected '$expected', got '$actual')"
    fail=$((fail + 1))
  fi
}

capture_success() {
  local output_var="$1" label="$2"
  shift 2
  local output status
  # Successful commands can emit retry/warning diagnostics on stderr. Keep
  # those in the journey log, outside the machine-readable stdout we parse.
  if output="$("$@")"; then
    status=0
  else
    status=$?
  fi
  assert_eq "$label exit" "0" "$status"
  if [[ "$status" == "0" ]]; then
    printf -v "$output_var" "%s" "$output"
  else
    printf -v "$output_var" "%s" ""
    if [[ -n "$output" ]]; then
      echo "  $label output: ${output:0:240}"
    fi
  fi
  return 0
}

run_success() {
  local label="$1"
  shift
  local output status
  if output="$("$@" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  assert_eq "$label exit" "0" "$status"
  if [[ "$status" != "0" && -n "$output" ]]; then
    echo "  $label output: ${output:0:240}"
  fi
  return 0
}

write_staged_file() {
  local path="$1" content="$2"
  printf '%s' "$content" >"$path"
}

# stage_customer_secrets writes the customer server's credentials. The key map
# names the key by a path relative to itself. The key and the database URL are
# given to the image's uid 1001 with mode 0400. The ownership change runs in a
# container, which sees the directory through the Docker daemon, so it first
# checks that every staged file is a regular file visible there. What is
# asserted is that the files are mode 0400 and that uid 1001 actually reads
# them. The owner is reported, not asserted: Docker Desktop file sharing
# accepts chown without storing it, and enforces neither owner nor mode
# between container uids, so this phase makes no claim that other uids cannot
# read the files. Diagnostics name files, owners and modes, never contents.
# Returns non-zero after a recorded failure.
stage_customer_secrets() {
  local failures_before="$fail" ownership
  run_success "customer server key staged" \
    cp "$CUSTOMER_IDENTITY_DIR/.aw/signing.key" "$CUSTOMER_KEYS_DIR/customerteam.key"
  run_success "customer server key map staged" write_staged_file "$CUSTOMER_KEYS_DIR/member-keys.json" \
    $'{"customerteam:test.local": "customerteam.key"}\n'
  run_success "customer server database url staged" write_staged_file "$CUSTOMER_KEYS_DIR/database-url" \
    $'postgresql://aweb:customer-e2e-test@postgres:5432/aweb\n'
  run_success "customer postgres secrets directory" mkdir -p "$CUSTOMER_SECRETS_DIR/postgres"
  run_success "customer postgres password staged" write_staged_file "$CUSTOMER_SECRETS_DIR/postgres/password" \
    'customer-e2e-test'
  [[ "$fail" == "$failures_before" ]] || return 1
  capture_success ownership "customer secrets ownership" \
    docker run --rm -v "$CUSTOMER_KEYS_DIR:/keys" --entrypoint /bin/sh redis:7-alpine -c '
      set -e
      for f in customerteam.key database-url member-keys.json; do
        if [ ! -f "/keys/$f" ]; then
          echo "missing in the daemon view of the customer secrets: $f"
          ls -ln /keys
          exit 3
        fi
      done
      chown 1001:1001 /keys/customerteam.key /keys/database-url
      chmod 0400 /keys/customerteam.key /keys/database-url
      stat -c "%n %u:%g %a" /keys/customerteam.key /keys/database-url'
  [[ "$fail" == "$failures_before" ]] || return 1
  echo "$ownership" | while read -r name owner mode; do
    echo "  customer secrets owner (not asserted): $name $owner"
  done
  assert_eq "customer secrets are mode 0400" "400 400" "$(echo "$ownership" | awk '{print $3}' | paste -sd' ' -)"
  [[ "$fail" == "$failures_before" ]] || return 1
  run_success "customer secrets are readable by the image user" \
    docker run --rm --user 1001:1001 -v "$CUSTOMER_KEYS_DIR:/keys:ro" --entrypoint /bin/sh redis:7-alpine -c '
      for f in customerteam.key database-url; do
        if ! cat "/keys/$f" >/dev/null; then
          echo "unreadable by uid 1001: $f"
          exit 4
        fi
      done'
  [[ "$fail" == "$failures_before" ]]
}

# inbox_message_body prints the body of the first message with the given
# subject from `aw mail inbox --json` on stdin, or an empty line when none
# matches. Malformed JSON is a non-zero exit, never an empty message.
inbox_message_body() {
  python3 -c "import sys,json; msgs=json.load(sys.stdin)['messages']; print(next((m['body'] for m in msgs if m.get('subject')==sys.argv[1]), ''))" "$1"
}
