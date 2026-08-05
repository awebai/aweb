#!/usr/bin/env bash
# Self-test for scripts/npm-exact-publish.sh, no network.
#
#   green: pack-inspect stages one tgz from a coherent package and reports
#          its digest; verify-published (against a supplied observed file)
#          adopts byte-identical bytes
#   reds:  declared version mismatch, missing declared main entry inside
#          the tgz, a files[] entry with no content in the tgz, observed
#          published bytes differing from staged

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/npm-exact-publish.sh"
PASS=0

fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

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

# ── package-profile fixtures ────────────────────────────────────────
CHANNEL_MARKERS='const stableID = certificateStableID || identityStableID
case "app_event"
kind: "app"
stableIdentityStateHash
seq>1 requires rotate_key operation
did:aw not derived from genesis key
verifyStableIdentityViaFullLog
pin store is empty or has no document'
SENTINEL='aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1'
SKILLS='aweb-bootstrap aweb-coordination aweb-identity aweb-messaging aweb-team-membership'

make_profile_fixture() {
  # $1 profile, then flags: --no-sentinel, --drop-skill <name>, --extra-skill <name>
  local profile="$1"; shift
  local sentinel="$SENTINEL" drop='' extra=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-sentinel) sentinel=''; shift ;;
      --drop-skill) drop="$2"; shift 2 ;;
      --extra-skill) extra="$2"; shift 2 ;;
    esac
  done
  rm -rf "$tmp/prof"; mkdir -p "$tmp/prof/dist"
  local files='"dist", "README.md"'
  case "$profile" in
    channel)
      printf '%s\n%s\n' "$CHANNEL_MARKERS" "$sentinel" > "$tmp/prof/dist/index.js"
      printf '{"mcpServers": {"aweb": {"command": "node"}}}\n' > "$tmp/prof/.mcp.json"
      files='"dist", ".mcp.json", "README.md"'
      ;;
    pi)
      printf '%s\n' "$CHANNEL_MARKERS" > "$tmp/prof/dist/index.js"
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
profile_case "pi profile accepts coherent fixture" pi ok ""
profile_case "pi profile refuses missing skill dir" pi refuse "aweb-identity" --drop-skill aweb-identity
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

printf 'SELFTEST OK: %d assertions\n' "$PASS"
