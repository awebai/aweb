#!/usr/bin/env bash
# Build-once, inspect, publish-exact-bytes for npm lanes.
#
#   pack-inspect     --dir <pkg> --version <X.Y.Z> --out <dir>
#       npm pack once into <dir>, then refuse unless the tgz declares the
#       expected version, contains the declared main entry, and every
#       files[] entry contributed at least one path. Prints the sha256.
#   publish-exact    --tgz <file>
#       npm publish of the exact staged tgz. Nothing is repacked.
#   verify-published --tgz <file> --package <name> --version <X.Y.Z>
#                    [--observed <file>]
#       Download the registry tarball (or use --observed) and refuse
#       unless its bytes are identical to the staged tgz.
#   verify-published-bounded --tgz <file> --package <name> --version <X.Y.Z>
#                    --post-action <publish|adopt>
#                    [--deadline-seconds <n>] [--backoff-seconds <n>]
#       Only after an exact publish/adopt action, retry transient registry
#       visibility until a strict deadline. Succeeds only on the exact staged
#       bytes; a present mismatch refuses permanently without retry.
#   require-publishable --manifest <manifest.json>
#       Refuse unless the staged manifest records mode stage-only; a
#       verify-only artifact must never continue to publication.
#   verify-manifest  --staging <dir> --manifest <manifest.json>
#                    --sha <source-sha> --version <X.Y.Z>
#       Refuse unless the manifest binds the declared source and version
#       and the staging dir holds exactly the manifest's files, each
#       matching its digest, with a canonical set digest that recomputes.
#   validate-inputs  [--sha <40-hex>] [--version <X.Y.Z>]
#                    [--digest sha256:<64-hex>] [--run-id <n>] [--artifact-id <n>]
#       Literal-format validation for dispatch inputs.
#   decide-npm       --observed-status <http-code> [--digest <staged sha256>]
#                    [--observed <remote sha256 | unavailable>]
#       Tri-state registry decision. Only HTTP 404 proves absence. With
#       --digest: 404 -> PUBLISH, 200 with identical --observed -> ADOPT,
#       200 with different or unavailable digest refuses, any other
#       status refuses (outage is never proof of absence). Without
#       --digest (stage guard probe): 404 -> ABSENT, anything else refuses.
#
# pack-inspect also accepts --profile <channel|pi|skills> --source-root
# <repo root>: package-specific contract checks against the unpacked tgz
# bytes (channel: package-dist markers + sentinel via
# channel/scripts/check-package-dist.mjs, plus the .mcp.json mcpServers
# wrapper with the exact aweb-channel server name; pi:
# pi-extension/scripts/check-package-dist.mjs markers - including the
# authenticated trust boundary and the bundled channel-core deadline,
# byte-inactivity watchdog, and settled-backoff listener cleanup - plus the five
# skill directories; skills:
# plugin version equals the package version and exactly the five skill
# directories).

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

MODE="${1:-}"; shift || true
DIR='' VERSION='' OUT='' TGZ='' PACKAGE='' OBSERVED='' PROFILE='' SOURCE_ROOT=''
MANIFEST='' STAGING='' SHA='' DIGEST='' RUN_ID='' ARTIFACT_ID='' STATUS=''
POST_ACTION='' DEADLINE_SECONDS='120' BACKOFF_SECONDS='5'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tgz) TGZ="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --observed) OBSERVED="$2"; shift 2 ;;
    --observed-status) STATUS="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --source-root) SOURCE_ROOT="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --staging) STAGING="$2"; shift 2 ;;
    --sha) SHA="$2"; shift 2 ;;
    --digest) DIGEST="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --artifact-id) ARTIFACT_ID="$2"; shift 2 ;;
    --post-action) POST_ACTION="$2"; shift 2 ;;
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

EXPECTED_SKILLS="aweb-bootstrap aweb-coordination aweb-identity aweb-messaging aweb-team-membership"

profile_inspect() {
  local tgz="$1"
  [[ -n "$SOURCE_ROOT" ]] || fail "--profile requires --source-root"
  local unpack; unpack="$(mktemp -d)"
  tar -xzf "$tgz" -C "$unpack"
  case "$PROFILE" in
    channel)
      node "$SOURCE_ROOT/channel/scripts/check-package-dist.mjs" \
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
      node "$SOURCE_ROOT/pi-extension/scripts/check-package-dist.mjs" \
        --dist "$unpack/package/dist/index.js" \
        || fail "pi package-dist contract (bundled channel-core markers) failed"
      local s actual expected
      for s in $EXPECTED_SKILLS; do
        [[ -d "$unpack/package/skills/$s" ]] \
          || fail "pi tgz lacks expected skill directory skills/$s"
      done
      actual="$(ls "$unpack/package/skills" 2>/dev/null | sort | tr '\n' ' ')"
      expected="$(tr ' ' '\n' <<<"$EXPECTED_SKILLS" | sort | tr '\n' ' ')"
      [[ "$actual" == "$expected" ]] \
        || fail "pi tgz skill set is [$actual], expected exactly [$expected]"
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
      local actual expected
      actual="$(ls "$unpack/package/skills" 2>/dev/null | sort | tr '\n' ' ')"
      expected="$(tr ' ' '\n' <<<"$EXPECTED_SKILLS" | sort | tr '\n' ' ')"
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
  inspect-tgz)
    [[ -n "$TGZ" && -f "$TGZ" && -n "$VERSION" ]] \
      || { echo "inspect-tgz requires --tgz --version" >&2; exit 2; }
    python3 - "$TGZ" "$VERSION" <<'PY'
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
    [[ -z "$PROFILE" ]] || profile_inspect "$TGZ"
    printf 'INSPECTED: %s sha256 %s\n' "$(basename "$TGZ")" "$(sha256 "$TGZ")"
    ;;
  publish-exact)
    [[ -n "$TGZ" && -f "$TGZ" ]] || fail "publish-exact requires an existing --tgz"
    npm publish "$TGZ" --ignore-scripts --access public
    printf 'PUBLISHED: %s sha256 %s\n' "$(basename "$TGZ")" "$(sha256 "$TGZ")"
    ;;
  verify-published)
    [[ -n "$TGZ" && -f "$TGZ" ]] || fail "verify-published requires an existing --tgz"
    if [[ -z "$OBSERVED" ]]; then
      [[ -n "$PACKAGE" && -n "$VERSION" ]] \
        || { echo "verify-published requires --package and --version (or --observed)" >&2; exit 2; }
      OBSERVED="$(mktemp)"
      tarball="$(npm view "${PACKAGE}@${VERSION}" dist.tarball)"
      [[ -n "$tarball" ]] || fail "registry has no tarball for ${PACKAGE}@${VERSION}"
      curl -fsSL -o "$OBSERVED" "$tarball"
    fi
    s="$(sha256 "$TGZ")"; o="$(sha256 "$OBSERVED")"
    [[ "$s" == "$o" ]] \
      || fail "published bytes $o do not equal staged bytes $s for $(basename "$TGZ")"
    printf 'VERIFIED: published equals staged (%s)\n' "$s"
    ;;
  verify-published-bounded)
    [[ -n "$TGZ" && -f "$TGZ" && -n "$PACKAGE" && -n "$VERSION" ]] \
      || fail "verify-published-bounded requires --tgz --package --version"
    [[ "$POST_ACTION" == "publish" || "$POST_ACTION" == "adopt" ]] \
      || fail "verify-published-bounded requires --post-action publish or adopt"
    [[ "$DEADLINE_SECONDS" =~ ^[1-9][0-9]*$ && "$BACKOFF_SECONDS" =~ ^[0-9]+$ ]] \
      || fail "readback deadline must be positive and backoff non-negative integer seconds"
    readback_tmp="$(mktemp -d)"
    trap 'rm -rf "$readback_tmp"' EXIT
    packument="$readback_tmp/packument.json"
    observed="$readback_tmp/observed.tgz"
    encoded="$(python3 - "$PACKAGE" <<'PYENC'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PYENC
    )"
    registry_url="https://registry.npmjs.org/${encoded}/${VERSION}"
    deadline=$((SECONDS + DEADLINE_SECONDS))
    attempts=0
    last_observation='not attempted'
    while (( SECONDS < deadline )); do
      attempts=$((attempts + 1))
      remaining=$((deadline - SECONDS))
      if status="$(curl -sS --connect-timeout "$remaining" --max-time "$remaining" \
          -o "$packument" -w '%{http_code}' "$registry_url")"; then
        case "$status" in
          200)
            tarball="$(python3 - "$packument" <<'PYTARBALL' 2>/dev/null || true
import json
import sys
value = json.load(open(sys.argv[1])).get("dist", {}).get("tarball")
if isinstance(value, str) and value:
    print(value)
PYTARBALL
            )"
            remaining=$((deadline - SECONDS))
            if [[ -n "$tarball" && "$remaining" -gt 0 ]] \
               && curl -fsSL --connect-timeout "$remaining" --max-time "$remaining" \
                 -o "$observed" "$tarball"; then
              staged_digest="$(sha256 "$TGZ")"
              observed_digest="$(sha256 "$observed")"
              if [[ "$observed_digest" != "$staged_digest" ]]; then
                fail "registry serves $observed_digest, staged is $staged_digest; permanent mismatch after $POST_ACTION"
              fi
              printf 'VERIFIED: registry equals staged (%s) after %s attempt(s)\n' \
                "$staged_digest" "$attempts"
              exit 0
            fi
            last_observation='HTTP 200 with unavailable tarball bytes'
            ;;
          404) last_observation='HTTP 404 (not yet visible)' ;;
          *) last_observation="HTTP $status (registry unavailable)" ;;
        esac
      else
        last_observation='registry request unavailable'
      fi
      remaining=$((deadline - SECONDS))
      (( remaining > 0 )) || break
      sleep_for="$BACKOFF_SECONDS"
      (( sleep_for <= remaining )) || sleep_for="$remaining"
      sleep "$sleep_for"
    done
    fail "registry readback uncertain at deadline after $attempts attempt(s): $last_observation"
    ;;
  decide-npm)
    # Tri-state registry decision: HTTP 404 alone proves absence (PUBLISH);
    # a present version adopts only on exact digest (ADOPT) and refuses on
    # mismatch; any other status or an unavailable digest refuses - an
    # outage is never permission to stage as absent or publish blind.
    [[ -n "$STATUS" ]] \
      || { echo "decide-npm requires --observed-status (and --digest when deciding a staged tgz)" >&2; exit 2; }
    if [[ -z "$DIGEST" ]]; then
      # Absence probe (stage guard): no staged bytes yet, so only absence
      # can be proven; presence and outage both refuse.
      case "$STATUS" in
        404) echo ABSENT ;;
        200) fail "version already exists on the registry" ;;
        *) fail "registry returned status ${STATUS}; an outage is never proof of absence" ;;
      esac
      exit 0
    fi
    case "$STATUS" in
      404) echo PUBLISH ;;
      200)
        [[ -n "$OBSERVED" && "$OBSERVED" != "unavailable" ]] \
          || fail "present version with unavailable remote digest; refusing to act blind"
        if [[ "$OBSERVED" == "$DIGEST" ]]; then
          echo ADOPT
        else
          fail "registry serves $OBSERVED, staged is $DIGEST; permanent"
        fi
        ;;
      *) fail "registry returned status ${STATUS}; an outage is never proof of absence" ;;
    esac
    ;;
  require-publishable)
    [[ -n "$MANIFEST" ]] || fail "require-publishable requires --manifest"
    mode="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("mode",""))' "$MANIFEST")"
    [[ "$mode" == "stage-only" ]] \
      || fail "manifest mode is ${mode:-absent}; only stage-only artifacts publish"
    echo "PUBLISHABLE: manifest mode is stage-only"
    ;;
  verify-manifest)
    [[ -n "$STAGING" && -n "$MANIFEST" && -n "$SHA" && -n "$VERSION" ]] \
      || fail "verify-manifest requires --staging --manifest --sha --version"
    python3 - "$STAGING" "$MANIFEST" "$SHA" "$VERSION" <<'PYMAN'
import hashlib, json, os, sys
staging, manifest_path, sha, version = sys.argv[1:5]
m = json.load(open(manifest_path))
if m.get("source_sha") != sha:
    sys.exit(f"REFUSE: manifest source_sha {m.get('source_sha')} does not equal declared {sha}")
if m.get("candidate_version") != version:
    sys.exit(f"REFUSE: manifest candidate_version {m.get('candidate_version')} does not equal declared {version}")
files = m.get("files", {})
recomputed = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
if m.get("canonical_set_digest") != recomputed:
    sys.exit("REFUSE: canonical set digest does not recompute from the files map")
on_disk = sorted(n for n in os.listdir(staging) if n != "manifest.json")
if on_disk != sorted(files):
    sys.exit(f"REFUSE: staging files {on_disk} do not equal the manifest set {sorted(files)}")
for name, digest in files.items():
    with open(os.path.join(staging, name), "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != digest:
        sys.exit(f"REFUSE: digest mismatch for {name}")
print(f"MANIFEST OK: {len(files)} files bound to {version}/{sha}")
PYMAN
    ;;
  validate-inputs)
    [[ -z "$SHA" ]] || [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] \
      || fail "sha must be exactly 40 lowercase hex characters, got: $SHA"
    [[ -z "$VERSION" ]] || [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
      || fail "version must be strict X.Y.Z with no prefix, got: $VERSION"
    [[ -z "$DIGEST" ]] || [[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || fail "digest must be sha256:<64 lowercase hex>, got: $DIGEST"
    [[ -z "$RUN_ID" ]] || [[ "$RUN_ID" =~ ^[0-9]+$ ]] \
      || fail "run-id must be numeric, got: $RUN_ID"
    [[ -z "$ARTIFACT_ID" ]] || [[ "$ARTIFACT_ID" =~ ^[0-9]+$ ]] \
      || fail "artifact-id must be numeric, got: $ARTIFACT_ID"
    echo "inputs well-formed"
    ;;
  *)
    echo "npm-exact-publish: mode must be pack-inspect | publish-exact | verify-published | require-publishable | verify-manifest | validate-inputs" >&2
    exit 2
    ;;
esac
