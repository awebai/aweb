#!/usr/bin/env bash
#
# Dogfood harness for `aw team extend` (default-aaeq.26).
#
# Exercises the three call sites from docs/team-extend-sot.md against a
# THROWAWAY team, plus the documented negative cases:
#   1. team root:   extend from the dir holding agents/instances
#   2. agent home:  extend from inside a member's home
#   3. clean dir:   extend in an empty dir with --api-key only
#   N1. clean dir without any key -> authority-discovery error
#   N2. --team-id mismatching the key's team -> rollback, no residue
#
# Usage:
#   AWEB_URL=... AWEB_API_KEY=... ./scripts/dogfood-team-extend.sh
#
# Requirements:
#   - an `aw` binary with `team extend` (probed up front; fails fast before
#     the command exists)
#   - AWEB_URL and AWEB_API_KEY for a THROWAWAY team only; never point this
#     at a team you care about — it creates and abandons members
#
# Environment:
#   AW_BIN         aw binary to exercise (default: aw)
#   DOGFOOD_TMUX   set to 1 to also exercise --start. The aw launcher receives
#                  AWEB_TMUX_TMPDIR; every raw tmux probe receives TMUX_TMPDIR.
#                  Raw tmux ignores the aweb-prefixed variable.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export PATH="$REPO_ROOT/scripts/guard-bin:$PATH"
if [ "$(command -v tmux)" != "$REPO_ROOT/scripts/guard-bin/tmux" ]; then
  echo "error: reviewed tmux PATH guard is not active" >&2
  exit 2
fi

AW_BIN="${AW_BIN:-aw}"
FAILURES=0

say()  { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

for var in AWEB_URL AWEB_API_KEY; do
  if [ -z "${!var:-}" ]; then
    echo "error: $var is required, and must be scoped to a THROWAWAY team" >&2
    exit 2
  fi
done

# `aw team extend --help` on an extend-less binary prints the parent help
# with exit 0 (cobra treats extend as a positional arg), so probe the
# subcommand listing instead.
if ! "$AW_BIN" team --help 2>/dev/null | grep -Eq '^[[:space:]]+extend[[:space:]]'; then
  echo "error: this $AW_BIN has no 'team extend'; build one before dogfooding" >&2
  exit 2
fi

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aw-extend-dogfood.XXXXXX")"
DOGFOOD_TMUX_TMPDIR="$WORK_ROOT/tmux"
mkdir -p "$DOGFOOD_TMUX_TMPDIR"
cleanup() {
  # NEVER `tmux kill-server`: it nukes EVERY session on the target socket, and an
  # empty/unset TMUX_TMPDIR silently targets the DEFAULT socket where the live
  # team runs — that is exactly how a dogfood run took the whole team down once.
  # Only touch the isolated throwaway socket, only kill the specific session, and
  # only after proving the socket dir is a real directory under our mktemp WORK_ROOT.
  if [ "${DOGFOOD_TMUX:-0}" = "1" ] \
     && [ -n "${WORK_ROOT:-}" ] \
     && [ -n "${DOGFOOD_TMUX_TMPDIR:-}" ] \
     && [ -d "$DOGFOOD_TMUX_TMPDIR" ] \
     && case "$DOGFOOD_TMUX_TMPDIR" in "$WORK_ROOT"/*) true ;; *) false ;; esac; then
    TMUX_TMPDIR="$DOGFOOD_TMUX_TMPDIR" tmux kill-session -t aw-extend-dogfood 2>/dev/null || true
  fi
  [ -n "${WORK_ROOT:-}" ] && rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

# jq-free JSON field probe: extract "field":"value".
json_field() { sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1; }

TEAM_ROOT="$WORK_ROOT/team-root"
mkdir -p "$TEAM_ROOT"

say "seed: throwaway team with one member (aw team create)"
(
  cd "$TEAM_ROOT"
  "$AW_BIN" team create dogfood-extend --json >create.json
)
SEED_TEAM_ID="$(json_field team_id <"$TEAM_ROOT/create.json")"
if [ -n "$SEED_TEAM_ID" ]; then
  pass "seed team created ($SEED_TEAM_ID)"
else
  fail "seed team create produced no team_id"
  exit 1
fi

say "1. team-root call site"
(
  cd "$TEAM_ROOT"
  "$AW_BIN" team extend extend-from-root --json >extend-root.json
)
if [ -d "$TEAM_ROOT/agents/instances/extend-from-root/.aw" ] &&
   [ "$(json_field status <"$TEAM_ROOT/extend-root.json")" = "extended" ]; then
  pass "team-root extend created agents/instances/extend-from-root"
else
  fail "team-root extend did not produce the expected member home"
fi

say "2. agent-home call site"
(
  cd "$TEAM_ROOT/agents/instances/extend-from-root"
  "$AW_BIN" team extend extend-from-home --json >extend-home.json
)
if [ -d "$TEAM_ROOT/agents/instances/extend-from-home/.aw" ]; then
  pass "agent-home extend placed the member as a sibling, not nested"
else
  fail "agent-home extend did not place the member next to its sibling"
fi
if [ -e "$TEAM_ROOT/agents/instances/extend-from-root/agents" ]; then
  fail "agent-home extend nested a layout under the calling home"
fi

say "3. clean-dir call site (--api-key)"
CLEAN_DIR="$WORK_ROOT/clean-dir"
mkdir -p "$CLEAN_DIR"
(
  cd "$CLEAN_DIR"
  env -u AWEB_API_KEY "$AW_BIN" team extend extend-clean \
    --api-key "$AWEB_API_KEY" --json >extend-clean.json
)
CLEAN_TEAM_ID="$(json_field team_id <"$CLEAN_DIR/extend-clean.json")"
if [ -d "$CLEAN_DIR/agents/instances/extend-clean/.aw" ] && [ -n "$CLEAN_TEAM_ID" ]; then
  pass "clean-dir extend built the layout and joined $CLEAN_TEAM_ID"
else
  fail "clean-dir extend did not build agents/instances/extend-clean"
fi

say "N1. clean dir without any key errors and names the fix"
NOAUTH_DIR="$WORK_ROOT/noauth-dir"
mkdir -p "$NOAUTH_DIR"
if out="$(cd "$NOAUTH_DIR" && env -u AWEB_API_KEY "$AW_BIN" team extend nope 2>&1)"; then
  fail "extend with no authority succeeded; it must error"
else
  if printf '%s' "$out" | grep -q -- "--api-key" &&
     printf '%s' "$out" | grep -q "aw team create"; then
    pass "no-authority error names --api-key and suggests aw team create"
  else
    fail "no-authority error is missing --api-key or the create suggestion: $out"
  fi
fi

say "N2. --team-id mismatch with the key rolls back and leaves no residue"
MISMATCH_DIR="$WORK_ROOT/mismatch-dir"
mkdir -p "$MISMATCH_DIR"
if out="$(cd "$MISMATCH_DIR" && env -u AWEB_API_KEY "$AW_BIN" team extend leftover \
    --api-key "$AWEB_API_KEY" --team-id not-this-team:example.com 2>&1)"; then
  fail "mismatching --team-id succeeded; it must error"
else
  if [ -e "$MISMATCH_DIR/agents/instances/leftover" ]; then
    fail "mismatch rollback left the local home behind"
  else
    pass "mismatch errored and removed the local home"
  fi
  # Server-side check: the rolled-back member must not be on the roster.
  if (cd "$CLEAN_DIR/agents/instances/extend-clean" && "$AW_BIN" workspace status 2>/dev/null) |
      grep -q "leftover"; then
    fail "mismatch rollback left the member on the team roster"
  else
    pass "no rolled-back member visible on the roster"
  fi
fi

if [ "${DOGFOOD_TMUX:-0}" = "1" ]; then
  say "optional: --start on an isolated tmux server (TMUX_TMPDIR)"
  (
    cd "$TEAM_ROOT"
    AWEB_TMUX_TMPDIR="$DOGFOOD_TMUX_TMPDIR" TMUX_TMPDIR="$DOGFOOD_TMUX_TMPDIR" "$AW_BIN" team extend extend-started \
      --start --no-attach --session aw-extend-dogfood --json >extend-started.json
  )
  if TMUX_TMPDIR="$DOGFOOD_TMUX_TMPDIR" tmux list-sessions 2>/dev/null |
      grep -q aw-extend-dogfood; then
    pass "--start launched on the isolated tmux server"
  else
    fail "--start did not produce a session on the isolated tmux server"
  fi
  if tmux list-sessions 2>/dev/null | grep -q aw-extend-dogfood; then
    fail "--start leaked a session onto the DEFAULT tmux server"
  fi
fi

say "summary"
if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES scenario(s) failed" >&2
  exit 1
fi
echo "all extend dogfood scenarios passed"
