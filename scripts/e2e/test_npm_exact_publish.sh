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
if args != ["publish", expected, "--ignore-scripts", "--access", "public"]:
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
profile_case "pi profile refuses a sixth skill dir" pi refuse "skill set" --extra-skill extra-skill
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

# ── post-action readback: bounded propagation, exact bytes only ─────
cat > "$tmp/fake-bin/curl" <<'EOFCURL'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE_STATUS_SEQUENCE:?}" "${FAKE_CURL_COUNT:?}" "${FAKE_REMOTE_TGZ:?}"
out='' url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w|--connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
if [[ "$url" == "https://registry.example/exact.tgz" ]]; then
  cp "$FAKE_REMOTE_TGZ" "$out"
  exit 0
fi
count=0
[[ ! -f "$FAKE_CURL_COUNT" ]] || count="$(cat "$FAKE_CURL_COUNT")"
count=$((count + 1)); printf '%s' "$count" > "$FAKE_CURL_COUNT"
status="$(sed -n "${count}p" "$FAKE_STATUS_SEQUENCE")"
[[ -n "$status" ]] || status="$(tail -n 1 "$FAKE_STATUS_SEQUENCE")"
if [[ "$status" == 200 ]]; then
  printf '{"dist":{"tarball":"https://registry.example/exact.tgz"}}' > "$out"
else
  : > "$out"
fi
printf '%s' "$status"
EOFCURL
chmod +x "$tmp/fake-bin/curl"

run_bounded_readback() {
  PATH="$tmp/fake-bin:$PATH" \
  FAKE_STATUS_SEQUENCE="$tmp/statuses" \
  FAKE_CURL_COUNT="$tmp/curl-count" \
  FAKE_REMOTE_TGZ="$tmp/remote.tgz" \
    bash "$LANE" verify-published-bounded \
      --tgz "$staged" --package '@awebai/lane-fixture' --version 1.2.3 \
      --post-action publish --deadline-seconds "$1" --backoff-seconds "$2"
}

printf '404\n200\n' > "$tmp/statuses"; : > "$tmp/curl-count"
cp "$staged" "$tmp/remote.tgz"
run_bounded_readback 2 0 >/dev/null \
  || fail "bounded readback did not accept 404 followed by exact bytes"
[[ "$(cat "$tmp/curl-count")" == 2 ]] \
  || fail "404-to-exact readback did not make exactly two observations"
ok "post-publish 404 retries to exact staged-byte success"

printf '404\n' > "$tmp/statuses"; : > "$tmp/curl-count"
if out="$(run_bounded_readback 1 1 2>&1)"; then
  fail "persistent 404 was accepted"
fi
grep -qi "uncertain\|deadline" <<<"$out" \
  || fail "persistent 404 refusal did not name bounded uncertainty: $out"
ok "persistent 404 fails uncertain at the strict deadline"

printf '200\n404\n' > "$tmp/statuses"; : > "$tmp/curl-count"
cp "$staged" "$tmp/remote.tgz"; printf x >> "$tmp/remote.tgz"
if out="$(run_bounded_readback 2 0 2>&1)"; then
  fail "present mismatched bytes were accepted"
fi
grep -qi "permanent" <<<"$out" \
  || fail "present mismatch refusal did not name permanence: $out"
[[ "$(cat "$tmp/curl-count")" == 1 ]] \
  || fail "present mismatch retried instead of refusing permanently"
ok "present mismatch refuses permanently without retry"

# ── committed metadata and ZIP source/output contract ───────────────
node - "$ROOT" <<'NODE'
const fs = require('fs');
const root = process.argv[2];
for (const dir of ['channel', 'packages/claude-skills']) {
  const pkg = JSON.parse(fs.readFileSync(`${root}/${dir}/package.json`));
  const plugin = JSON.parse(fs.readFileSync(`${root}/${dir}/.claude-plugin/plugin.json`));
  if (pkg.version !== plugin.version) {
    throw new Error(`${dir} committed plugin ${plugin.version} != package ${pkg.version}`);
  }
}
NODE
ok "committed channel/skills plugin versions equal package versions"

python3 - "$ROOT" <<'PYSKILLS'
import os
import sys

root = sys.argv[1]
default = {
    "aweb-bootstrap",
    "aweb-coordination",
    "aweb-identity",
    "aweb-messaging",
    "aweb-team-membership",
}
internal = {"aweb-agent-instantiation"}
canonical = {
    name
    for name in os.listdir(os.path.join(root, "skills"))
    if os.path.isfile(os.path.join(root, "skills", name, "SKILL.md"))
}
if default & internal:
    raise SystemExit("default and internal skill sets overlap")
if canonical != default | internal:
    raise SystemExit(
        "canonical skills must be explicitly default or internal: "
        f"canonical={sorted(canonical)} default={sorted(default)} "
        f"internal={sorted(internal)}"
    )
PYSKILLS
ok "every canonical skill is explicitly default-shipped or internal"

ziproot="$tmp/zip-repo"
mkdir -p "$ziproot/packages/claude-ai-skills" "$ziproot/skills"
cp "$ROOT/packages/claude-ai-skills/build-zips.sh" "$ziproot/packages/claude-ai-skills/"
for skill in $SKILLS; do
  mkdir -p "$ziproot/skills/$skill/references"
  printf '%s\n' "$skill" > "$ziproot/skills/$skill/SKILL.md"
  printf '%s\n' "$skill-ref" > "$ziproot/skills/$skill/references/ref.md"
done
(cd "$ziproot/packages/claude-ai-skills" && ./build-zips.sh >/dev/null)
python3 - "$ziproot" <<'PYZIP'
import os, sys, zipfile
root = sys.argv[1]
expected = {"aweb-bootstrap", "aweb-coordination", "aweb-identity", "aweb-messaging", "aweb-team-membership"}
dist = os.path.join(root, "packages", "claude-ai-skills", "dist")
names = {name[:-4] for name in os.listdir(dist) if name.endswith(".zip")}
if names != expected:
    raise SystemExit(f"ZIP names {sorted(names)} != {sorted(expected)}")
for skill in expected:
    with zipfile.ZipFile(os.path.join(dist, skill + ".zip")) as archive:
        actual = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    source = os.path.join(root, "skills", skill)
    wanted = {}
    for base, _, files in os.walk(source):
        for name in files:
            path = os.path.join(base, name)
            wanted[os.path.relpath(path, source)] = open(path, "rb").read()
    if actual != wanted:
        raise SystemExit(f"ZIP {skill} bytes differ from canonical source")
PYZIP
ok "exact five ZIP names and bytes equal the five default skill sources"
rm -rf "$ziproot/skills/aweb-identity"
if (cd "$ziproot/packages/claude-ai-skills" && ./build-zips.sh >/dev/null 2>&1); then
  fail "ZIP build accepted a missing canonical skill source"
fi
ok "ZIP build refuses a missing canonical skill source"
mkdir -p "$ziproot/skills/aweb-identity/references"
printf '%s\n' aweb-identity > "$ziproot/skills/aweb-identity/SKILL.md"
printf '%s\n' aweb-identity-ref > "$ziproot/skills/aweb-identity/references/ref.md"
(cd "$ziproot/packages/claude-ai-skills" && ./build-zips.sh >/dev/null)

# Execute the workflow's exact GitHub Release block with a stateful fake gh.
python3 - "$ROOT/.github/workflows/npm-release.yml" "$tmp/skills-release-block.sh" <<'PYBLOCK'
import sys
lines = open(sys.argv[1]).read().splitlines()
start = next(i for i, line in enumerate(lines) if "SKILLS_RELEASE_BEGIN" in line) + 1
end = next(i for i, line in enumerate(lines) if "SKILLS_RELEASE_END" in line)
block = "\n".join(line[12:] for line in lines[start:end]) + "\n"
open(sys.argv[2], "w").write("set -euo pipefail\nfail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n" + block)
PYBLOCK
cat > "$tmp/fake-bin/gh" <<'PYGH'
#!/usr/bin/env python3
import json, os, shutil, sys
state, mode, staging = os.environ["GH_FIXTURE_STATE"], os.environ["GH_FIXTURE_MODE"], os.environ["staging"]
assets = os.path.join(state, "assets"); os.makedirs(assets, exist_ok=True)
log = os.path.join(state, "actions")
expected = sorted(n for n in os.listdir(staging) if n.endswith(".zip"))
def seed(kind):
    for name in expected:
        if kind == "missing" and name == "aweb-identity.zip": continue
        shutil.copyfile(os.path.join(staging, name), os.path.join(assets, name))
    if kind == "extra": open(os.path.join(assets, "extra.zip"), "wb").write(b"x")
    if kind == "bytes": open(os.path.join(assets, expected[0]), "ab").write(b"wrong")
if sys.argv[1] == "api":
    count_path=os.path.join(state,"reads"); count=int(open(count_path).read())+1 if os.path.exists(count_path) else 1; open(count_path,"w").write(str(count))
    if count == 1:
        if mode in ("absent", "concurrent_create"): print("HTTP 404", file=sys.stderr); sys.exit(1)
        if mode == "outage": print("HTTP 503", file=sys.stderr); sys.exit(1)
        if mode == "auth": print("HTTP 403", file=sys.stderr); sys.exit(1)
        if mode == "malformed": print("not-json"); sys.exit(0)
        if mode == "concurrent_upload": seed("missing")
        if mode == "name_conflict": seed("extra")
        if mode == "byte_conflict": seed("bytes")
    print(json.dumps({"assets":[{"name":n} for n in sorted(os.listdir(assets))]})); sys.exit(0)
if sys.argv[1:3] == ["release", "create"]:
    open(log,"a").write("create\n"); seed("exact")
    sys.exit(1 if mode == "concurrent_create" else 0)
if sys.argv[1:3] == ["release", "upload"]:
    open(log,"a").write("upload\n"); source=sys.argv[-1]; shutil.copyfile(source, os.path.join(assets, os.path.basename(source)))
    sys.exit(1 if mode == "concurrent_upload" else 0)
if sys.argv[1:3] == ["release", "download"]:
    name=sys.argv[sys.argv.index("--pattern")+1]; out=sys.argv[sys.argv.index("--output")+1]; shutil.copyfile(os.path.join(assets,name),out); sys.exit(0)
sys.exit(2)
PYGH
chmod +x "$tmp/fake-bin/gh"
run_gh_fixture() {
  local mode="$1" expect="$2"
  local state="$tmp/gh-$mode" run_tmp="$tmp/gh-run-$mode"
  rm -rf "$state" "$run_tmp"; mkdir -p "$state" "$run_tmp"
  local output
  if output="$(GH_FIXTURE_STATE="$state" GH_FIXTURE_MODE="$mode" \
      staging="$ziproot/packages/claude-ai-skills/dist" RUNNER_TEMP="$run_tmp" \
      GITHUB_REPOSITORY=awebai/aweb tag=skills-v1.2.3 \
      PATH="$tmp/fake-bin:$PATH" bash "$tmp/skills-release-block.sh" 2>&1)"; then
    [[ "$expect" == pass ]] || fail "$mode GitHub fixture unexpectedly passed"
  else
    [[ "$expect" == refuse ]] || fail "$mode GitHub fixture unexpectedly refused: $output"
  fi
  case "$mode" in
    outage|auth|malformed) [[ ! -e "$state/actions" ]] || fail "$mode attempted a GitHub write" ;;
  esac
}
run_gh_fixture absent pass
run_gh_fixture outage refuse
run_gh_fixture auth refuse
run_gh_fixture malformed refuse
run_gh_fixture concurrent_create pass
run_gh_fixture concurrent_upload pass
run_gh_fixture name_conflict refuse
run_gh_fixture byte_conflict refuse
ok "GitHub fixture proves 404/create, outage/auth/malformed refusal, races, and conflicts"

# Execute the workflow's exact conditional Pi aw-floor block.
python3 - "$ROOT/.github/workflows/npm-release.yml" "$tmp/pi-floor-block.sh" <<'PYFLOOR'
import sys
lines=open(sys.argv[1]).read().splitlines()
start=next(i for i,l in enumerate(lines) if "PI_AW_FLOOR_BEGIN" in l)+1
end=next(i for i,l in enumerate(lines) if "PI_AW_FLOOR_END" in l)
block="\n".join(l[10:] for l in lines[start:end])+"\n"
open(sys.argv[2],"w").write("set -euo pipefail\nfail(){ printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n"+block+"printf proceed > \"$FLOOR_PROCEEDED\"\n")
PYFLOOR
cat > "$tmp/fake-bin/curl" <<'PYCURL'
#!/usr/bin/env python3
import json, os, sys
args=sys.argv[1:]; out=args[args.index("-o")+1]; url=args[-1]; mode=os.environ["FLOOR_MODE"]
open(os.environ["FLOOR_QUERIES"],"a").write(url+"\n")
if url.endswith("%40awebai%2Fpi"):
    status={"none":"404","history_outage":"503","history_auth":"403"}.get(mode,"200")
    if status=="200":
        if mode=="history_malformed": open(out,"w").write("not-json")
        else:
            floor="^1.22.1" if mode=="same" else "^1.21.0"
            json.dump({"dist-tags":{"latest":"0.3.5"},"versions":{"0.3.5":{"dependencies":{"@awebai/aw":floor}}}},open(out,"w"))
else:
    status={"aw_outage":"503","aw_auth":"403","aw_absent":"404"}.get(mode,"200")
    if mode=="aw_lag":
        prior=sum(1 for line in open(os.environ["FLOOR_QUERIES"]) if "%40awebai%2Faw" in line)
        status="404" if prior == 1 else "200"
    if status=="200":
        if mode=="aw_malformed": open(out,"w").write("not-json")
        else: json.dump({"version":"9.9.9" if mode=="aw_mismatch" else "1.22.1"},open(out,"w"))
print(status,end="")
PYCURL
chmod +x "$tmp/fake-bin/curl"
run_floor_fixture(){
  local mode="$1" expect="$2"
  local queries="$tmp/floor-$mode-queries" proceeded="$tmp/floor-$mode-proceeded" run_tmp="$tmp/floor-$mode"
  rm -rf "$run_tmp" "$queries" "$proceeded"; mkdir -p "$run_tmp"
  local output
  if output="$(cd "$ROOT" && FLOOR_MODE="$mode" FLOOR_QUERIES="$queries" FLOOR_PROCEEDED="$proceeded" \
      RUNNER_TEMP="$run_tmp" encoded=%40awebai%2Fpi \
      PI_AW_FLOOR_TIMEOUT_SECONDS="$([[ "$mode" == aw_lag ]] && echo 2 || echo 0)" \
      PI_AW_FLOOR_BACKOFF_SECONDS=0 PATH="$tmp/fake-bin:$PATH" \
      bash "$tmp/pi-floor-block.sh" 2>&1)"; then
    [[ "$expect" == pass ]] || fail "$mode floor fixture unexpectedly passed"
    [[ -f "$proceeded" ]] || fail "$mode passed without proceeding"
  else
    [[ "$expect" == refuse ]] || fail "$mode floor fixture unexpectedly refused: $output"
    [[ ! -f "$proceeded" ]] || fail "$mode refusal proceeded"
    case "$mode" in
      history_outage) needle='history unavailable' ;;
      history_auth) needle='history authorization' ;;
      history_malformed) needle='history evidence is malformed' ;;
      aw_outage) needle='floor observation unavailable' ;;
      aw_auth) needle='floor observation authorization' ;;
      aw_absent) needle='propagation deadline exceeded' ;;
      aw_malformed) needle='floor evidence is malformed' ;;
      aw_mismatch) needle='floor evidence mismatch' ;;
    esac
    grep -qi "$needle" <<<"$output" || fail "$mode refusal was unrelated: $output"
  fi
  if [[ "$mode" == same ]]; then
    [[ "$(wc -l < "$queries" | tr -d ' ')" == 1 ]] || fail "unchanged floor queried public aw"
  elif [[ "$mode" == moved || "$mode" == none ]]; then
    [[ "$(wc -l < "$queries" | tr -d ' ')" == 2 ]] || fail "$mode did not query exact public aw"
  elif [[ "$mode" == aw_lag ]]; then
    [[ "$(wc -l < "$queries" | tr -d ' ')" == 3 ]] || fail "lag fixture did not poll 404 to exact success"
  fi
}
run_floor_fixture same pass
run_floor_fixture moved pass
run_floor_fixture none pass
run_floor_fixture aw_lag pass
for mode in history_outage history_auth history_malformed aw_outage aw_auth aw_absent aw_malformed aw_mismatch; do
  run_floor_fixture "$mode" refuse
done
ok "Pi floor fixture proves unchanged independence, moved/404 wait, and named failures"

# ── thin release workflow static contract + causal mutations ───────
python3 - "$ROOT" <<'PYWORKFLOW'
import os, re, sys
from pathlib import Path
root = Path(sys.argv[1])
workflow = (root / ".github/workflows/npm-release.yml").read_text()
makefile = (root / "Makefile").read_text()
for dead in ("release-channel-check", "release-channel-tag", "release-channel-push"):
    assert dead not in makefile, f"deleted Make path survives: {dead}"
suite_map = (root / "release-gate/suite-map.tsv").read_text()
for row in (
    "channel-version-equality\tcontract\t_release-gate-channel-version\n",
    "node-dependencies\tcontract\t_release-node-deps\n",
    "channel-unit\tunit\t_release-unit-channel\n",
    "channel-core-unit\tunit\t_release-unit-channel-core\n",
    "channel-package\tartifact\t_release-artifact-channel\n",
):
    assert row in suite_map, f"missing local-gate mapping: {row}"

def validate(text):
    triggers = text[text.index("\non:\n"):text.index("\njobs:\n")]
    assert "push:" in triggers, "missing push trigger"
    assert re.search(r"branches:\s*\[release\]", triggers), "missing release branches trigger"
    for forbidden in ("workflow_dispatch", "tags:", "main", "pull_request", "schedule"):
        assert forbidden not in triggers, f"forbidden trigger {forbidden}"
    for marker in (
        "SOURCE_SHA: ${{ github.sha }}", "matrix:", "package: [channel, pi, skills]",
        "fail-fast: false", "ref: ${{ github.sha }}", "git ls-remote origin refs/heads/release",
        '[[ "$release_tip" == "$SOURCE_SHA" ]]',
        'git merge-base --is-ancestor "$SOURCE_SHA" origin/main',
        "npm-exact-publish.sh pack-inspect", "npm-exact-publish.sh decide-npm",
        "npm-exact-publish.sh publish-exact", "verify-published-bounded",
        "channel-core source bundle", "canonical skills source bundle",
        "committed plugin version", "packed plugin version", "AW_FLOOR_MOVED",
        "public aw floor", "build-zips.sh", "EXPECTED_ZIPS", "gh release",
        "GitHub release observation unavailable", "HTTP 404", "timeout 30 gh",
        "require_tag_compatible", "publish_tag",
    ):
        assert marker in text, f"missing {marker}"
    for skill in ("aweb-bootstrap", "aweb-coordination", "aweb-identity", "aweb-messaging", "aweb-team-membership"):
        assert skill in text, f"missing canonical skill {skill}"
    assert "aweb-agent-instantiation" not in text, "forbidden sixth source aweb-agent-instantiation"
    for forbidden in ("inputs.", "stage-only", "publish-continuation", "upload-artifact", "download-artifact", "pytest", "npm test", "make test"):
        assert forbidden not in text, f"forbidden thin-workflow marker {forbidden}"

validate(workflow)
mutations = (
    ("wrong branch", workflow.replace("branches: [release]", "branches: [main]", 1), "branches"),
    ("tag trigger", workflow.replace("branches: [release]", "branches: [release]\n    tags: ['v*']", 1), "tags:"),
    ("channel-core drift", workflow.replace("channel-core source bundle", "channel source", 1), "channel-core source bundle"),
    ("missing skill", workflow.replace("aweb-identity", "missing-identity"), "aweb-identity"),
    ("sixth skill", workflow.replace("aweb-team-membership", "aweb-team-membership aweb-agent-instantiation", 1), "aweb-agent-instantiation"),
    ("plugin drift", workflow.replace("committed plugin version", "unchecked plugin"), "committed plugin version"),
    ("Pi races aw", workflow.replace("AW_FLOOR_MOVED", "AW_FLOOR_IGNORED"), "AW_FLOOR_MOVED"),
    ("registry verify removed", workflow.replace("verify-published-bounded", "echo unverified", 1), "verify-published-bounded"),
    ("suite reintroduced", workflow + "\n# npm test\n", "npm test"),
)
for name, mutation, expected in mutations:
    assert mutation != workflow
    try:
        validate(mutation)
    except AssertionError as exc:
        reason = str(exc)
        assert expected in reason, f"{name} failed for unrelated reason: {reason}"
        if os.environ.get("NPM_RELEASE_MUTATION_REPORT") == "1":
            print(f"MUTATION RED: {name}: {reason[:240]}")
    else:
        raise AssertionError(f"{name} mutation stayed green")
PYWORKFLOW
ok "thin npm workflow and nine intended-property mutations"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
