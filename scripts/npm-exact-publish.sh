#!/usr/bin/env bash
# Build-once, inspect, publish-exact-bytes for npm lanes.
#
#   pack-inspect     --dir <pkg> --version <X.Y.Z> --out <dir>
#       npm pack once into <dir>, then refuse unless the tgz declares the
#       expected version, contains the declared main entry, and every
#       files[] entry contributed at least one path. Prints the sha256.
#   publish-exact    --tgz <file> [--staged-final]
#       npm publish of the exact staged tgz. Nothing is repacked.
#   verify-published-bounded --tgz <file> --package <name> --version <X.Y.Z>
#                    --post-action <publish|adopt>
#                    [--dist-tag <tag>] [--deadline-seconds <n>] [--backoff-seconds <n>]
#       Only after an exact publish/adopt action, retry transient registry
#       visibility until a strict deadline. Succeeds only on the exact staged
#       bytes and integrity (plus --dist-tag when supplied); the default
#       window is 25 minutes. A present mismatch refuses without retry.
#
# pack-inspect also accepts --profile <channel|pi|skills> --source-root
# <repo root>: package-specific contract checks against the unpacked tgz
# bytes (channel: package-dist markers + sentinel via
# packages/channel/scripts/check-package-dist.mjs, plus the .mcp.json mcpServers
# wrapper with the exact aweb-channel server name; pi:
# packages/pi-extension/scripts/check-package-dist.mjs markers - including the
# authenticated trust boundary and the bundled channel-core deadline,
# byte-inactivity watchdog, and settled-backoff listener cleanup - with no
# bundled skills; skills: plugin version equals the package version, Pi skills
# discovery metadata, and exactly the shipped skill directories).

set -euo pipefail

# Publication must not trigger npm's unrelated background self-update lookup.
export NPM_CONFIG_UPDATE_NOTIFIER=false npm_config_update_notifier=false

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

MODE="${1:-}"; shift || true
DIR='' VERSION='' OUT='' TGZ='' PACKAGE='' PROFILE='' SOURCE_ROOT=''
POST_ACTION='' DEADLINE_SECONDS='' BACKOFF_SECONDS='5' DIST_TAG=''
STAGED_FINAL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tgz) TGZ="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --source-root) SOURCE_ROOT="$2"; shift 2 ;;
    --post-action) POST_ACTION="$2"; shift 2 ;;
    --dist-tag) DIST_TAG="$2"; shift 2 ;;
    --staged-final) STAGED_FINAL=1; shift ;;
    --deadline-seconds) DEADLINE_SECONDS="$2"; shift 2 ;;
    --backoff-seconds) BACKOFF_SECONDS="$2"; shift 2 ;;
    *) echo "npm-exact-publish: unknown argument $1" >&2; exit 2 ;;
  esac
done

# npm treats a relative path containing a slash as a package/git spec in some
# call contexts. Resolve every caller-supplied tgz once, before mode dispatch,
# so all npm operations receive the exact existing file by physical absolute
# path. realpath resolves directory and final-component symlinks without
# reading or rewriting the artifact bytes.
if [[ -n "$TGZ" ]]; then
  supplied_tgz="$TGZ"
  if ! TGZ="$(python3 - "$supplied_tgz" <<'PYTGZ'
import os
import sys

path = os.path.realpath(sys.argv[1])
if not os.path.isfile(path):
    raise SystemExit(1)
print(path)
PYTGZ
  )"; then
    fail "--tgz must name an existing regular file: $supplied_tgz"
  fi
fi

profile_inspect() {
  local tgz="$1"
  [[ -n "$SOURCE_ROOT" ]] || fail "--profile requires --source-root"
  local unpack; unpack="$(mktemp -d)"
  tar -xzf "$tgz" -C "$unpack"
  case "$PROFILE" in
    channel)
      [[ ! -d "$unpack/package/skills" ]] || fail "channel tgz must not bundle skills"
      node "$SOURCE_ROOT/packages/channel/scripts/check-package-dist.mjs" \
        --dist "$unpack/package/dist/index.js" \
        || fail "channel package-dist contract (markers/sentinel/version) failed"
      python3 - "$unpack/package/.mcp.json" <<'PYMCP'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except FileNotFoundError:
    sys.exit("REFUSE: channel tgz lacks .mcp.json")
servers = doc.get("mcpServers")
if not isinstance(servers, dict) or set(servers) != {"aweb-channel"}:
    sys.exit("REFUSE: channel .mcp.json must declare exactly the distinct aweb-channel MCP server")
PYMCP
      # The plugin manifest ships in the tgz; the version coherence must
      # hold in the SHIPPED bytes, not only in the source tree the
      # check-package-dist script reads.
      python3 - "$unpack/package" <<'PYPLUGIN'
import json, os, sys
root = sys.argv[1]
try:
    plugin = json.load(open(os.path.join(root, ".claude-plugin", "plugin.json")))
except FileNotFoundError:
    sys.exit("REFUSE: channel tgz lacks .claude-plugin/plugin.json")
pkg = json.load(open(os.path.join(root, "package.json")))
if plugin.get("version") != pkg["version"]:
    sys.exit(f"REFUSE: channel tgz plugin version {plugin.get('version')} "
             f"does not equal its package version {pkg['version']}")
PYPLUGIN
      ;;
    pi)
      node "$SOURCE_ROOT/packages/pi-extension/scripts/check-package-dist.mjs" \
        --dist "$unpack/package/dist/index.js" \
        || fail "pi package-dist contract (bundled channel-core markers) failed"
      [[ ! -d "$unpack/package/skills" ]] || fail "pi tgz must not bundle skills"
      python3 - "$unpack/package/package.json" <<'PYPI'
import json, sys
pkg = json.load(open(sys.argv[1]))
if pkg.get("pi", {}).get("skills") != []:
    sys.exit("REFUSE: pi runtime must disable automatic skills discovery with pi.skills=[]")
PYPI
      ;;
    skills)
      python3 - "$unpack/package/.claude-plugin/plugin.json" "$VERSION" <<'PYPLUG'
import json, sys
try:
    plugin = json.load(open(sys.argv[1]))
except FileNotFoundError:
    sys.exit("REFUSE: skills tgz lacks .claude-plugin/plugin.json")
if plugin.get("version") != sys.argv[2]:
    sys.exit(f"REFUSE: skills plugin version {plugin.get('version')} "
             f"does not equal the package version {sys.argv[2]}")
PYPLUG
      python3 - "$unpack/package/package.json" <<'PYSKILLS'
import json, sys
pkg = json.load(open(sys.argv[1]))
if pkg.get("pi", {}).get("skills") != ["./skills"]:
    sys.exit("REFUSE: optional skills package must expose pi.skills=[./skills]")
PYSKILLS
      local actual expected
      local expected_skills
      expected_skills="$(node "$SOURCE_ROOT/scripts/skill-packaging.mjs" list)"
      actual="$(ls "$unpack/package/skills" 2>/dev/null | sort | tr '\n' ' ')"
      expected="$(tr ' ' '\n' <<<"$expected_skills" | sort | tr '\n' ' ')"
      [[ "$actual" == "$expected" ]] \
        || fail "skills tgz skill set is [$actual], expected exactly [$expected]"
      ;;
    *) fail "unknown profile $PROFILE" ;;
  esac
  rm -rf "$unpack"
}

case "$MODE" in
  pack-inspect)
    [[ -n "$DIR" && -n "$VERSION" && -n "$OUT" ]] \
      || { echo "pack-inspect requires --dir --version --out" >&2; exit 2; }
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    (cd "$DIR" && npm pack --ignore-scripts --pack-destination "$OUT" >/dev/null)
    count="$(ls "$OUT"/*.tgz 2>/dev/null | wc -l | tr -d ' ')"
    [[ "$count" == "1" ]] || fail "expected exactly one staged tgz in $OUT, found $count"
    tgz="$(ls "$OUT"/*.tgz)"
    python3 - "$tgz" "$VERSION" <<'PY'
import json, sys, tarfile
path, version = sys.argv[1], sys.argv[2]
with tarfile.open(path) as t:
    names = t.getnames()
    pkg = json.load(t.extractfile("package/package.json"))
if pkg["version"] != version:
    sys.exit(f"REFUSE: tgz declares version {pkg['version']}, expected {version}")
main = pkg.get("main")
if main:
    entry = "package/" + main.lstrip("./")
    if entry not in names:
        sys.exit(f"REFUSE: declared main {main.lstrip('./')} is missing from the tgz")
for spec in pkg.get("files", []):
    prefix = "package/" + spec.rstrip("/")
    if not any(n == prefix or n.startswith(prefix + "/") for n in names):
        sys.exit(f"REFUSE: files entry {spec} contributed nothing to the tgz")
PY
    [[ -z "$PROFILE" ]] || profile_inspect "$tgz"
    printf 'STAGED: %s sha256 %s\n' "$(basename "$tgz")" "$(sha256 "$tgz")"
    ;;
  publish-exact)
    [[ -n "$TGZ" && -f "$TGZ" ]] || fail "publish-exact requires an existing --tgz"
    # Select from the staged bytes, not caller environment or a filename.
    dist_tag="$(python3 - "$TGZ" "$STAGED_FINAL" <<'PYTAG'
import json, re, sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    version = json.load(archive.extractfile("package/package.json"))["version"]
base = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
if not isinstance(version, str) or not re.fullmatch(base + r"(?:-rc\.[1-9][0-9]*)?", version):
    sys.exit("REFUSE: npm version must be X.Y.Z or X.Y.Z-rc.N (N >= 1)")
if sys.argv[2] == "1" and not re.fullmatch(base, version):
    sys.exit("REFUSE: staged-final publication requires a final version")
print("next" if sys.argv[2] == "1" or "-rc." in version else "latest")
PYTAG
    )"
    npm publish "$TGZ" --ignore-scripts --access public --tag "$dist_tag"
    printf 'PUBLISHED: %s sha256 %s\n' "$(basename "$TGZ")" "$(sha256 "$TGZ")"
    ;;
  verify-published-bounded)
    [[ -n "$TGZ" && -f "$TGZ" && -n "$PACKAGE" && -n "$VERSION" ]] \
      || fail "verify-published-bounded requires --tgz --package --version"
    [[ "$POST_ACTION" == "publish" || "$POST_ACTION" == "adopt" ]] \
      || fail "verify-published-bounded requires --post-action publish or adopt"
    [[ ( -z "$DEADLINE_SECONDS" || "$DEADLINE_SECONDS" =~ ^[1-9][0-9]*$ ) && "$BACKOFF_SECONDS" =~ ^[0-9]+$ ]] \
      || fail "readback deadline must be positive and backoff non-negative integer seconds"
    readback_args=(--artifact "$PACKAGE=$TGZ" --version "$VERSION"
      --registry "${NPM_CONFIG_REGISTRY:-https://registry.npmjs.org}"
      --backoff-seconds "$BACKOFF_SECONDS")
    [[ -z "$DEADLINE_SECONDS" ]] || readback_args+=(--deadline-seconds "$DEADLINE_SECONDS")
    [[ -z "$DIST_TAG" ]] || readback_args+=(--dist-tag "$DIST_TAG")
    # One verifier ships with the aw distribution and serves every npm lane.
    # Its default is 25 minutes, covering the observed 19-minute registry lag.
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    exec python3 "$root/cli/go/npm/readback.py" "${readback_args[@]}"
    ;;
  *)
    echo "npm-exact-publish: mode must be pack-inspect | publish-exact | verify-published-bounded" >&2
    exit 2
    ;;
esac
