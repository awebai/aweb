#!/usr/bin/env bash
# Self-test for scripts/npm-exact-publish.sh, no network.
#
#   green: pack-inspect stages one tgz from a coherent package and reports
#          its digest; verify-published (against a supplied observed file)
#          adopts byte-identical bytes; publish-exact gives npm an absolute
#          physical file path without changing the staged bytes
#   reds:  declared version mismatch, missing declared main entry inside
#          the tgz, a files[] entry with no content in the tgz, observed
#          published bytes differing from staged, and missing/non-file tgz paths

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/npm-exact-publish.sh"
PASS=0

fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }
file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  rm -rf "$tmp/pkg"
  mkdir -p "$tmp/pkg/dist"
  cat > "$tmp/pkg/package.json" <<'EOF'
{
  "name": "@awebai/lane-fixture",
  "version": "1.2.3",
  "main": "./dist/index.js",
  "files": ["dist", "README.md"]
}
EOF
  echo 'module.exports = 1' > "$tmp/pkg/dist/index.js"
  echo 'fixture' > "$tmp/pkg/README.md"
}

# ── green: coherent package stages exactly one inspected tgz ────────
make_fixture
out="$(bash "$LANE" pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged")" \
  || fail "pack-inspect refused a coherent package: $out"
grep -q "sha256" <<<"$out" || fail "pack-inspect did not report a digest: $out"
[[ -f "$tmp/staged/awebai-lane-fixture-1.2.3.tgz" ]] \
  || fail "staged tgz missing from the out directory"
ok "pack-inspect stages a coherent package and reports its digest"

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$(bash "$LANE" "$@" 2>&1)"; then
    fail "$label: accepted what it must refuse"
  fi
  grep -qi "$needle" <<<"$out" \
    || fail "$label: refusal does not name the item ($needle): $out"
  ok "$label refused, naming: $needle"
}

# ── red: declared version does not match the package ────────────────
make_fixture
expect_refusal "version mismatch" "version" \
  pack-inspect --dir "$tmp/pkg" --version 9.9.9 --out "$tmp/staged-red"

# ── red: declared main entry missing from the packed bytes ──────────
make_fixture
rm "$tmp/pkg/dist/index.js"
expect_refusal "missing main entry" "dist/index.js" \
  pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged-red"

# ── red: a files[] entry contributes nothing to the tgz ─────────────
make_fixture
rm "$tmp/pkg/README.md"
expect_refusal "empty files entry" "README.md" \
  pack-inspect --dir "$tmp/pkg" --version 1.2.3 --out "$tmp/staged-red"

# ── verify-published: identical adopts, different refuses ───────────
staged="$tmp/staged/awebai-lane-fixture-1.2.3.tgz"
cp "$staged" "$tmp/observed.tgz"
bash "$LANE" verify-published --tgz "$staged" --observed "$tmp/observed.tgz" \
  || fail "verify-published refused byte-identical observed bytes"
ok "verify-published adopts byte-identical observed bytes"
printf 'x' >> "$tmp/observed.tgz"
expect_refusal "published bytes differ" "not.*equal\|does not equal" \
  verify-published --tgz "$staged" --observed "$tmp/observed.tgz"

# ── publish-exact: npm receives only an absolute physical file path ─
mkdir -p "$tmp/fake-bin"
cat > "$tmp/fake-bin/npm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${NPM_ARGV_LOG:?}"
printf '%s\0' "$@" > "$NPM_ARGV_LOG"
EOF
chmod +x "$tmp/fake-bin/npm"

assert_published_path() {
  local label="$1" supplied="$2" expected="$3"
  local log="$tmp/npm-argv-$PASS"
  local before after
  before="$(file_sha256 "$expected")"
  (
    cd "$tmp"
    PATH="$tmp/fake-bin:$PATH" NPM_ARGV_LOG="$log" \
      bash "$LANE" publish-exact --tgz "$supplied"
  ) || fail "$label: publish-exact refused a valid tgz"
  after="$(file_sha256 "$expected")"
  [[ "$after" == "$before" ]] || fail "$label: publish-exact changed the tgz bytes"
  python3 - "$log" "$expected" <<'PY'
import os
import sys

args = open(sys.argv[1], "rb").read().split(b"\0")
if args and args[-1] == b"":
    args.pop()
args = [arg.decode() for arg in args]
expected = os.path.realpath(sys.argv[2])
if args != ["publish", expected, "--access", "public"]:
    raise SystemExit(f"npm argv {args!r} does not name exact physical tgz {expected!r}")
if not os.path.isabs(args[1]):
    raise SystemExit(f"npm tgz argument is not absolute: {args[1]!r}")
PY
  ok "$label"
}

relative_staged="staged/$(basename "$staged")"
assert_published_path "publish-exact canonicalizes a relative tgz without package-spec interpretation" \
  "$relative_staged" "$staged"
assert_published_path "publish-exact preserves an absolute tgz path" "$staged" "$staged"
mkdir -p "$tmp/staged with spaces"
spaced="$tmp/staged with spaces/package file.tgz"
cp "$staged" "$spaced"
assert_published_path "publish-exact canonicalizes a tgz path with spaces" \
  "staged with spaces/package file.tgz" "$spaced"
ln -s "$staged" "$tmp/staged-link.tgz"
assert_published_path "publish-exact resolves an absolute tgz symlink to its physical file" \
  "$tmp/staged-link.tgz" "$staged"
expect_refusal "missing tgz path" "regular file\|existing" \
  publish-exact --tgz "$tmp/missing.tgz"
expect_refusal "non-file tgz path" "regular file\|existing" \
  publish-exact --tgz "$tmp"

# ── package-profile fixtures ────────────────────────────────────────
CHANNEL_MARKERS='const stableID = certificateStableID || identityStableID
case "app_event"
kind: "app"
stableIdentityStateHash
seq>1 requires rotate_key operation
did:aw not derived from genesis key
verifyStableIdentityViaFullLog
pin store is empty or has no document
msg.encrypted_envelope != null
msg.subject = decrypted.subject
msg.body = decrypted.body
["--team", options.teamID.trim()]
selected active team ${config.teamID} is missing certificate signing authentication
event stream local deadline reached
event stream heartbeat timed out
function sleep(ms, signal) {
  signal.removeEventListener("abort", onAbort);
}
{ name: "aweb-channel", version: "0.1.0" }'
SENTINEL='aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1'
SKILLS='aweb-bootstrap aweb-coordination aweb-identity aweb-messaging aweb-team-membership'

make_profile_fixture() {
  # $1 profile, then flags: --no-sentinel, --drop-skill <name>, --extra-skill <name>
  local profile="$1"; shift
  local sentinel="$SENTINEL" drop='' extra='' plugin=coherent markers="$CHANNEL_MARKERS" unsafe_merge='' mcp_name='aweb-channel'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-sentinel) sentinel=''; shift ;;
      --drop-skill) drop="$2"; shift 2 ;;
      --extra-skill) extra="$2"; shift 2 ;;
      --plugin) plugin="$2"; shift 2 ;;
      --mcp-name) mcp_name="$2"; shift 2 ;;
      --drop-trust-boundary)
        markers="$(printf '%s\n' "$markers" | grep -v 'msg.encrypted_envelope != null')"
        shift
        ;;
      --drop-mcp-runtime-name)
        markers="$(printf '%s\n' "$markers" | grep -v 'name: "aweb-channel"')"
        shift
        ;;
      --drop-local-deadline)
        markers="$(printf '%s\n' "$markers" | grep -v 'event stream local deadline reached')"
        shift
        ;;
      --drop-inactivity-watchdog)
        markers="$(printf '%s\n' "$markers" | grep -v 'event stream heartbeat timed out')"
        shift
        ;;
      --drop-backoff-cleanup)
        markers="$(printf '%s\n' "$markers" | grep -v 'removeEventListener("abort", onAbort)')"
        shift
        ;;
      --unsafe-decrypt-merge) unsafe_merge='Object.assign(msg, decrypted)'; shift ;;
    esac
  done
  rm -rf "$tmp/prof"; mkdir -p "$tmp/prof/dist"
  local files='"dist", "README.md"'
  case "$profile" in
    channel)
      printf '%s\n%s\n%s\n' "$markers" "$sentinel" "$unsafe_merge" > "$tmp/prof/dist/index.js"
      printf '{"mcpServers": {"%s": {"command": "node"}}}\n' "$mcp_name" > "$tmp/prof/.mcp.json"
      files='"dist", ".mcp.json", "README.md"'
      case "$plugin" in
        coherent)
          mkdir -p "$tmp/prof/.claude-plugin"
          printf '{"name": "fixture", "version": "1.2.3"}\n' > "$tmp/prof/.claude-plugin/plugin.json"
          files='"dist", ".mcp.json", ".claude-plugin", "README.md"'
          ;;
        mismatched)
          mkdir -p "$tmp/prof/.claude-plugin"
          printf '{"name": "fixture", "version": "9.9.9"}\n' > "$tmp/prof/.claude-plugin/plugin.json"
          files='"dist", ".mcp.json", ".claude-plugin", "README.md"'
          ;;
        missing) ;;
      esac
      ;;
    pi)
      printf '%s\n%s\n' "$markers" "$unsafe_merge" > "$tmp/prof/dist/index.js"
      files='"dist", "skills", "README.md"'
      ;;
    skills)
      mkdir -p "$tmp/prof/.claude-plugin"
      printf '{"name": "fixture", "version": "1.2.3"}\n' > "$tmp/prof/.claude-plugin/plugin.json"
      files='".claude-plugin", "skills", "README.md"'
      ;;
  esac
  if [[ "$profile" == "pi" || "$profile" == "skills" ]]; then
    local s
    for s in $SKILLS $extra; do
      [[ "$s" == "$drop" ]] && continue
      mkdir -p "$tmp/prof/skills/$s"
      echo "skill" > "$tmp/prof/skills/$s/SKILL.md"
    done
  fi
  local main='"main": "./dist/index.js",'
  [[ "$profile" == "skills" ]] && main=''
  cat > "$tmp/prof/package.json" <<EOF
{
  "name": "@awebai/profile-fixture",
  "version": "1.2.3",
  $main
  "files": [$files]
}
EOF
  echo "fixture" > "$tmp/prof/README.md"
}

profile_case() {
  # $1 label, $2 profile, $3 expect (ok|refuse), $4 needle, rest fixture flags
  local label="$1" profile="$2" expect="$3" needle="$4"; shift 4
  make_profile_fixture "$profile" "$@"
  rm -rf "$tmp/prof-out"
  local out
  if out="$(bash "$LANE" pack-inspect --dir "$tmp/prof" --version 1.2.3       --out "$tmp/prof-out" --profile "$profile" --source-root "$ROOT" 2>&1)"; then
    [[ "$expect" == "ok" ]] || fail "$label: accepted what it must refuse"
  else
    [[ "$expect" == "refuse" ]] || fail "$label: refused a coherent fixture: $out"
    grep -qi "$needle" <<<"$out"       || fail "$label: refusal does not name the item ($needle): $out"
  fi
  ok "$label"
}

profile_case "channel profile accepts coherent fixture" channel ok ""
profile_case "channel profile refuses missing sentinel" channel refuse "sentinel\|contract" --no-sentinel
profile_case "channel profile refuses missing plugin manifest" channel refuse "plugin" --plugin missing
profile_case "channel profile refuses mismatched plugin version" channel refuse "plugin" --plugin mismatched
profile_case "channel profile refuses the retired bare MCP server name" channel refuse "aweb-channel" --mcp-name aweb
profile_case "channel profile refuses a bundle without the final MCP runtime name" channel refuse "runtime MCP server" --drop-mcp-runtime-name
profile_case "channel profile refuses missing authenticated trust boundary" channel refuse "encrypted_envelope" --drop-trust-boundary
profile_case "channel profile refuses trust-field overwrite merge" channel refuse "overwrite" --unsafe-decrypt-merge
profile_case "pi profile accepts coherent fixture" pi ok ""
profile_case "pi profile refuses missing skill dir" pi refuse "aweb-identity" --drop-skill aweb-identity
profile_case "pi profile refuses missing authenticated trust boundary" pi refuse "encrypted_envelope" --drop-trust-boundary
profile_case "pi profile refuses trust-field overwrite merge" pi refuse "overwrite" --unsafe-decrypt-merge
profile_case "pi profile refuses missing local stream deadline" pi refuse "local event-stream deadline" --drop-local-deadline
profile_case "pi profile refuses missing inactivity watchdog" pi refuse "byte-inactivity watchdog" --drop-inactivity-watchdog
profile_case "pi profile refuses missing settled backoff cleanup" pi refuse "backoff abort-listener cleanup" --drop-backoff-cleanup
profile_case "skills profile accepts exact five" skills ok ""
profile_case "skills profile refuses a sixth skill dir" skills refuse "skill set" --extra-skill extra-skill

# ── manifest publishability and binding ─────────────────────────────
mkdir -p "$tmp/mstage"
cp "$staged" "$tmp/mstage/"
python3 - "$tmp/mstage" <<'PYM'
import hashlib, json, os, sys
staging = sys.argv[1]
files = {}
for name in sorted(os.listdir(staging)):
    with open(os.path.join(staging, name), "rb") as f:
        files[name] = hashlib.sha256(f.read()).hexdigest()
canonical = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
json.dump({
    "mode": "stage-only", "candidate_version": "1.2.3",
    "source_sha": "a" * 40, "files": files, "canonical_set_digest": canonical,
}, open(os.path.join(staging, "manifest.json"), "w"))
PYM
bash "$LANE" require-publishable --manifest "$tmp/mstage/manifest.json" >/dev/null   || fail "stage-only manifest refused publication"
ok "stage-only manifest is publishable"
python3 - "$tmp/mstage/manifest.json" <<'PYM'
import json, sys
m = json.load(open(sys.argv[1])); m["mode"] = "verify-only"
json.dump(m, open(sys.argv[1], "w"))
PYM
if bash "$LANE" require-publishable --manifest "$tmp/mstage/manifest.json" 2>/dev/null; then
  fail "verify-only manifest accepted for publication"
fi
ok "verify-only manifest refused for publication"
python3 - "$tmp/mstage/manifest.json" <<'PYM'
import json, sys
m = json.load(open(sys.argv[1])); m["mode"] = "stage-only"
json.dump(m, open(sys.argv[1], "w"))
PYM
bash "$LANE" verify-manifest --staging "$tmp/mstage" --manifest "$tmp/mstage/manifest.json"   --sha "$(printf 'a%.0s' {1..40})" --version 1.2.3 >/dev/null   || fail "verify-manifest refused a coherent staging set"
ok "verify-manifest accepts a coherent staging set"
python3 - "$tmp/mstage/manifest.json" <<'PYM'
import json, sys
m = json.load(open(sys.argv[1]))
name = sorted(m["files"])[0]
m["files"][name] = "0" * 64
json.dump(m, open(sys.argv[1], "w"))
PYM
if bash "$LANE" verify-manifest --staging "$tmp/mstage" --manifest "$tmp/mstage/manifest.json"     --sha "$(printf 'a%.0s' {1..40})" --version 1.2.3 2>/dev/null; then
  fail "verify-manifest accepted a tampered digest"
fi
ok "verify-manifest refuses a tampered digest (canonical mismatch)"

# ── input literal validation ────────────────────────────────────────
bash "$LANE" validate-inputs --sha "$(printf 'a%.0s' {1..40})" --version 1.2.3   --digest "sha256:$(printf '0%.0s' {1..64})" --run-id 42 --artifact-id 7 >/dev/null   || fail "well-formed input literals refused"
ok "well-formed input literals accepted"
for bad in "--sha nope" "--version v1.2.3" "--digest $(printf '0%.0s' {1..64})"; do
  # shellcheck disable=SC2086
  if bash "$LANE" validate-inputs $bad 2>/dev/null; then
    fail "malformed input accepted: $bad"
  fi
done
ok "malformed input literals refused (3 forms)"

# ── decide-npm: only 404 proves absence ─────────────────────────────
D="$(printf '7%.0s' {1..64})"; E="$(printf '8%.0s' {1..64})"
[[ "$(bash "$LANE" decide-npm --observed-status 404 --digest "$D")" == "PUBLISH" ]] \
  || fail "404 must permit exactly one publication"
[[ "$(bash "$LANE" decide-npm --observed-status 200 --digest "$D" --observed "$D")" == "ADOPT" ]] \
  || fail "exact present bytes must adopt"
ok "decide-npm publishes on proven absence, adopts exact bytes"
expect_refusal "present mismatch is permanent" "permanent" \
  decide-npm --observed-status 200 --digest "$D" --observed "$E"
expect_refusal "outage is never absence" "never proof of absence" \
  decide-npm --observed-status 503 --digest "$D"
expect_refusal "unavailable digest never acts" "blind" \
  decide-npm --observed-status 200 --digest "$D" --observed unavailable
[[ "$(bash "$LANE" decide-npm --observed-status 404)" == "ABSENT" ]] \
  || fail "guard probe: 404 must prove absence"
ok "guard probe proves absence only from 404"
expect_refusal "guard probe refuses present version" "already exists" \
  decide-npm --observed-status 200
expect_refusal "guard probe refuses outage" "never proof of absence" \
  decide-npm --observed-status 500

# ── verify-published resolving through the REGISTRY ──────────────────
# The path that shipped a false failure. Channel 1.7.4 published, then this
# step read the registry seconds later, got a 404 from propagation lag, and
# reported the release as FAILED. Every earlier test supplied --observed, so
# the resolution path had no coverage at all.

fake_npm_dir="$tmp/fakebin"
mkdir -p "$fake_npm_dir"
attempts_file="$tmp/attempts"

# $1 = how many 404s before the version resolves ("always" never resolves)
# $2 = optional non-404 failure mode
make_fake_npm() {
  local fails_before_success="$1" mode="${2:-notfound}"
  : > "$attempts_file"
  cat > "$fake_npm_dir/npm" <<FAKE
#!/usr/bin/env bash
echo x >> "$attempts_file"
n=\$(wc -l < "$attempts_file" | tr -d ' ')
if [[ "$mode" == "outage" ]]; then
  echo "npm error code E503" >&2
  echo "npm error 503 Service Unavailable" >&2
  exit 1
fi
if [[ "$fails_before_success" == "always" || "\$n" -le "$fails_before_success" ]]; then
  echo "npm error code E404" >&2
  echo "npm error 404 No match found for version 1.2.3" >&2
  exit 1
fi
echo "file://$tmp/observed.tgz"
FAKE
  chmod +x "$fake_npm_dir/npm"
}

attempt_count() { wc -l < "$attempts_file" | tr -d ' '; }

make_fixture
bash "$LANE" pack-inspect --dir "$tmp/pkg" --version 1.2.3 \
  --out "$tmp/staging" >/dev/null
staged="$tmp/staging/awebai-lane-fixture-1.2.3.tgz"
cp "$staged" "$tmp/observed.tgz"

# GREEN: transient 404s are propagation lag, and the step must survive them.
make_fake_npm 2
if PATH="$fake_npm_dir:$PATH" NPM_VERIFY_ATTEMPTS=5 NPM_VERIFY_DELAY=0 \
     bash "$LANE" verify-published --tgz "$staged" \
       --package @awebai/lane-fixture --version 1.2.3 >/dev/null 2>&1; then
  ok "verify-published survives registry propagation lag"
else
  fail "verify-published must retry a 404 rather than report a false failure"
fi
[[ "$(attempt_count)" == "3" ]] \
  || fail "expected 3 attempts (2 lagging + 1 resolving), got $(attempt_count)"
ok "retries stop as soon as the version resolves"

# RED preserved: a version that NEVER appears is a real failure. The retry
# must not decay into a sleep that hides a publish that did not happen.
make_fake_npm always
if PATH="$fake_npm_dir:$PATH" NPM_VERIFY_ATTEMPTS=3 NPM_VERIFY_DELAY=0 \
     bash "$LANE" verify-published --tgz "$staged" \
       --package @awebai/lane-fixture --version 1.2.3 >/dev/null 2>&1; then
  fail "a version that never resolves must still refuse"
fi
ok "a version that never appears still refuses"
[[ "$(attempt_count)" == "3" ]] \
  || fail "expected the full 3 attempts before refusing, got $(attempt_count)"
ok "refusal comes only after the whole propagation window"

# RED preserved: an outage is NEVER proof of absence, and must not be retried
# as though it were lag - it fails immediately, on the first attempt.
make_fake_npm always outage
if PATH="$fake_npm_dir:$PATH" NPM_VERIFY_ATTEMPTS=5 NPM_VERIFY_DELAY=0 \
     bash "$LANE" verify-published --tgz "$staged" \
       --package @awebai/lane-fixture --version 1.2.3 >/dev/null 2>&1; then
  fail "a registry outage must refuse"
fi
ok "a registry outage refuses"
[[ "$(attempt_count)" == "1" ]] \
  || fail "an outage must not be retried as lag; got $(attempt_count) attempts"
ok "an outage is distinguished from lag and never retried"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
