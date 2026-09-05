#!/usr/bin/env bash
#
# End-to-end for the terminal wake broker (docs/terminal-wake-broker.md §7).
#
# One machine, no Docker. It drives the production `aw` binary against:
#
#   - a stand-in aweb server (cli/go/tools/wake-e2e-standin) that mints a real
#     certificate-authenticated identity home, serves GET /v1/events/stream from
#     a file this script appends to, and records the path of every request it
#     receives;
#   - a fake `oats` that returns scripted inspect/input envelopes and logs every
#     line the broker types.
#
# What it asserts, in order:
#
#   1. a pending registration is typed into never — not before the first
#      confirmed live inspect, whatever E_RUNTIME_ENDPOINT_UNKNOWN says;
#   2. hints kept while pending are delivered once the instance is present, as
#      one coalesced message carrying no subject and no body;
#   3. the broker acknowledged nothing: the server saw the event stream and
#      nothing else, on any path, for any reason;
#   4. a broker restart mid-cycle loses no wake — the reconnect snapshot
#      re-raises the still-unread item rather than a presented mark suppressing
#      it;
#   5. pause is durable and suppresses typing; resume restores it;
#   6. a GUI close (stopped, after a confirmed live observation) marks the
#      registration inactive and leaves it for the retire hook;
#   7. deregister is idempotent, because the retire hook may run twice.
#
# What it cannot assert is a real harness reading real typed text. That is the
# by-hand runbook in section 13 of the note.
#
# Usage:  ./scripts/e2e-wake-broker.sh
# Needs:  Go toolchain. No network, no Docker, no credentials.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CLI_DIR="$REPO_ROOT/cli/go"

# A unix socket path is bounded by sun_path (104 bytes on macOS), and the
# broker's control socket lives under the state directory, so the run root has
# to be short. The broker says so itself if this is ever wrong.
E2E_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/awwk.XXXXXX")"
E2E_ROOT="$(cd "$E2E_ROOT" && pwd -P)"

STANDIN_PID=""
BROKER_PID=""

cleanup() {
  [[ -n "$BROKER_PID" ]] && kill "$BROKER_PID" 2>/dev/null || true
  [[ -n "$STANDIN_PID" ]] && kill "$STANDIN_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  case "$E2E_ROOT" in
    /|"$REPO_ROOT"|"$REPO_ROOT"/*) echo "REFUSED unsafe cleanup: $E2E_ROOT" >&2 ;;
    *) rm -rf -- "$E2E_ROOT" ;;
  esac
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "=== $* ==="; }

# wait_until <seconds> <description> <command...>
wait_until() {
  local limit="$1"; shift
  local what="$1"; shift
  local deadline=$((SECONDS + limit))
  while (( SECONDS < deadline )); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  fail "timed out waiting for $what"
}

STATE_DIR="$E2E_ROOT/state"
SERVER_DIR="$E2E_ROOT/server"
OATS_DIR="$E2E_ROOT/oats"
HOME_DIR="$E2E_ROOT/home"
mkdir -p "$STATE_DIR" "$SERVER_DIR" "$OATS_DIR" "$HOME_DIR"

INSTANCE_HOME="$SERVER_DIR/instance"
IDENTITY_HOME="$INSTANCE_HOME/.aw"
INPUT_LOG="$OATS_DIR/input.log"
STATE_FILE="$OATS_DIR/state"
: > "$INPUT_LOG"
echo pending > "$STATE_FILE"

step "Build the production binary and the stand-in"
AW_BIN="$E2E_ROOT/aw"
STANDIN_BIN="$E2E_ROOT/wake-e2e-standin"
(cd "$CLI_DIR" && go build -o "$AW_BIN" ./cmd/aw && go build -o "$STANDIN_BIN" ./tools/wake-e2e-standin)

step "Write the fake oats"
# Reads its verdict from $STATE_FILE, so the script can move the instance
# between pending, live and stopped without restarting anything. `input` reads
# the text from stdin exactly as the real contract does, so nothing this
# harness types ever reaches a shell as an argument.
cat > "$OATS_DIR/oats" <<'FAKE_OATS'
#!/usr/bin/env bash
set -euo pipefail
OATS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
op="${2:-}"
home=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) home="$2"; shift 2 ;;
    *) shift ;;
  esac
done
state="$(cat "$OATS_DIR/state")"

case "$op" in
  inspect)
    case "$state" in
      pending)
        printf '%s\n' '{"schemaVersion":1,"ok":false,"error":{"code":"E_RUNTIME_ENDPOINT_UNKNOWN","message":"cannot read session receipt"}}'
        exit 1
        ;;
      stopped)
        printf '{"schemaVersion":1,"ok":true,"result":{"home":"%s","backend":"tmux","present":false,"state":"stopped","paneId":"%%625"}}\n' "$home"
        ;;
      *)
        printf '{"schemaVersion":1,"ok":true,"result":{"home":"%s","backend":"tmux","present":true,"state":"%s","paneId":"%%625"}}\n' "$home" "$state"
        ;;
    esac
    ;;
  input)
    {
      printf '===INPUT %s===\n' "$home"
      cat
      printf '\n'
    } >> "$OATS_DIR/input.log"
    printf '{"schemaVersion":1,"ok":true,"result":{"home":"%s","backend":"tmux","submitted":true}}\n' "$home"
    ;;
  *)
    printf '%s\n' '{"schemaVersion":1,"ok":false,"error":{"code":"E_UNKNOWN_OP","message":"fake oats"}}'
    exit 2
    ;;
esac
FAKE_OATS
chmod +x "$OATS_DIR/oats"
grep -q 'E_RUNTIME_ENDPOINT_UNKNOWN' "$OATS_DIR/oats" || fail "the fake oats was written wrong"

step "Start the stand-in aweb server and mint the identity home"
"$STANDIN_BIN" --root "$SERVER_DIR" >"$E2E_ROOT/standin.out" 2>&1 &
STANDIN_PID=$!
wait_until 30 "the stand-in to mint the identity home" test -f "$SERVER_DIR/ready"
AWEB_URL="$(cat "$SERVER_DIR/aweb-url")"
echo "stand-in: $AWEB_URL   identity home: $IDENTITY_HOME"
[[ -d "$IDENTITY_HOME" ]] || fail "the stand-in did not mint an identity home"

EVENTS="$SERVER_DIR/events.jsonl"
REQUESTS="$SERVER_DIR/requests.log"

aw() {
  env HOME="$HOME_DIR" AW_NO_UPDATE_CHECK=1 AWEB_IDENTITY_HOME= \
    "$AW_BIN" "$@"
}

start_broker() {
  env HOME="$HOME_DIR" AW_NO_UPDATE_CHECK=1 AWEB_IDENTITY_HOME= AW_WAKE_OATS_BIN="$OATS_DIR/oats" \
    "$AW_BIN" wake run --state-dir "$STATE_DIR" --coalesce 300 --rate-limit 1500 \
    >>"$E2E_ROOT/broker.log" 2>&1 &
  BROKER_PID=$!
  wait_until 30 "the broker control socket" test -S "$STATE_DIR/control.sock"
}

stop_broker() {
  [[ -n "$BROKER_PID" ]] || return 0
  kill "$BROKER_PID" 2>/dev/null || true
  wait "$BROKER_PID" 2>/dev/null || true
  BROKER_PID=""
}

inputs() { grep -c '^===INPUT' "$INPUT_LOG" || true; }

step "Start the broker"
start_broker

step "1. A registration without --delivery session is refused"
if aw wake register --home "$INSTANCE_HOME" --identity-home "$IDENTITY_HOME" \
     --state-dir "$STATE_DIR" >"$E2E_ROOT/refusal.out" 2>&1; then
  fail "a registration without --delivery session succeeded"
fi
grep -q 'doubles every wake' "$E2E_ROOT/refusal.out" \
  || fail "the refusal did not name the conflict: $(cat "$E2E_ROOT/refusal.out")"

step "2. Register the pending home, the way the OATS spawn hook does"
aw wake register --home "$INSTANCE_HOME" --identity-home "$IDENTITY_HOME" \
  --delivery session --backend tmux --state-dir "$STATE_DIR"
wait_until 20 "the registration to reach the daemon" \
  bash -c "aw() { env HOME='$HOME_DIR' AW_NO_UPDATE_CHECK=1 '$AW_BIN' \"\$@\"; }; aw wake status --json --state-dir '$STATE_DIR' | grep -q '\"phase\": \"pending\"'"

step "3. Mail arrives while the home is still pending: nothing is typed"
printf 'actionable_mail\t{"message_id":"m1","conversation_id":"conv-1","from_alias":"alice","subject":"SECRET-SUBJECT","unread_count":1}\n' >> "$EVENTS"
sleep 4
[[ "$(inputs)" == "0" ]] || fail "the broker typed into a home it had never seen live"
aw wake status --json --state-dir "$STATE_DIR" | grep -q '"pending_hints": 1' \
  || fail "the hint for a pending home was dropped instead of kept"
echo "ok: nothing typed, one hint kept"

step "4. The instance comes up: the kept hint is delivered, once"
echo idle > "$STATE_FILE"
wait_until 30 "the first wake" bash -c "grep -q '^===INPUT' '$INPUT_LOG'"
[[ "$(inputs)" == "1" ]] || fail "expected exactly one wake, got $(inputs)"
grep -q 'mail from alice' "$INPUT_LOG" || fail "the wake did not name the sender: $(cat "$INPUT_LOG")"
grep -q '1 item waiting' "$INPUT_LOG" || fail "the wake did not carry the count: $(cat "$INPUT_LOG")"
grep -q 'aw mail inbox' "$INPUT_LOG" || fail "the wake carried no fetch instruction"
if grep -q 'SECRET-SUBJECT' "$INPUT_LOG"; then
  fail "a subject reached the terminal: $(cat "$INPUT_LOG")"
fi
echo "ok: one coalesced wake, metadata only"

step "5. The broker acknowledged nothing, on any path"
if [[ -s "$REQUESTS" ]] && awk '{print $2}' "$REQUESTS" | sort -u | grep -qv '^/v1/events/stream$'; then
  fail "the broker called something other than the event stream:
$(sort -u "$REQUESTS")"
fi
grep -q 'certificate' "$REQUESTS" || fail "the broker streamed unauthenticated"
echo "ok: only GET /v1/events/stream, certificate-authenticated"

step "6. Restart the broker mid-cycle: no wake is lost"
stop_broker
[[ ! -S "$STATE_DIR/control.sock" ]] || fail "the socket outlived the daemon"
before="$(inputs)"
start_broker
# The stand-in re-emits every event to a new stream, which is the reconnect
# snapshot. The item is still unread, so it is raised again — nothing durable
# suppresses it — and the second wake arrives under the rate limit.
wait_until 30 "the unread item to be re-raised after the restart" \
  bash -c "[[ \$(grep -c '^===INPUT' '$INPUT_LOG') -gt $before ]]"
echo "ok: the restarted daemon re-raised the still-unread item"

step "7. Pause is durable and suppresses typing; resume restores it"
aw wake pause --home "$INSTANCE_HOME" --state-dir "$STATE_DIR"
paused_at="$(inputs)"
printf 'actionable_mail\t{"message_id":"m2","from_alias":"bob","unread_count":2}\n' >> "$EVENTS"
sleep 4
[[ "$(inputs)" == "$paused_at" ]] || fail "a paused instance was typed into"
stop_broker
start_broker
sleep 3
[[ "$(inputs)" == "$paused_at" ]] || fail "pause did not survive the restart"
aw wake resume --home "$INSTANCE_HOME" --state-dir "$STATE_DIR"
wait_until 30 "the held hint after resume" \
  bash -c "[[ \$(grep -c '^===INPUT' '$INPUT_LOG') -gt $paused_at ]]"
grep -q 'mail from bob' "$INPUT_LOG" || fail "the hint held across the pause was lost"
echo "ok: pause durable, resume delivers what was held"

step "8. GUI close: stopped after a confirmed live observation marks it inactive"
echo stopped > "$STATE_FILE"
wait_until 40 "the instance to be marked inactive" \
  bash -c "env HOME='$HOME_DIR' AW_NO_UPDATE_CHECK=1 '$AW_BIN' wake status --json --state-dir '$STATE_DIR' | grep -q '\"phase\": \"inactive\"'"
aw wake status --json --state-dir "$STATE_DIR" | grep -q "$INSTANCE_HOME" \
  || fail "the broker removed the registration; removal belongs to the retire hook"
grep -q 'inactive home=' "$E2E_ROOT/broker.log" || fail "no log line at the inactive transition"
echo "ok: inactive, registration kept"

step "9. Deregister, twice, the way a retire hook may run"
aw wake deregister --home "$INSTANCE_HOME" --state-dir "$STATE_DIR" | grep -q 'deregistered' \
  || fail "the first deregister did not report success"
aw wake deregister --home "$INSTANCE_HOME" --state-dir "$STATE_DIR" >"$E2E_ROOT/dereg2.out" 2>&1 \
  || fail "deregistering an already-retired home exited non-zero"
grep -q 'nothing to deregister' "$E2E_ROOT/dereg2.out" \
  || fail "the second deregister did not say the home was unknown"
echo "ok: idempotent"

step "10. Final check: the server still saw nothing but the event stream"
if awk '{print $2}' "$REQUESTS" | sort -u | grep -qv '^/v1/events/stream$'; then
  fail "the broker called something other than the event stream:
$(sort -u "$REQUESTS")"
fi

echo
echo "PASS: terminal wake broker end-to-end"
echo "  wakes typed:      $(inputs)"
echo "  server requests:  $(awk '{print $2}' "$REQUESTS" | sort | uniq -c | tr '\n' ' ')"
