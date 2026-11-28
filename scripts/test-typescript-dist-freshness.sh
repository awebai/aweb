#!/usr/bin/env bash
# Prove the shipped adapter bundles keep their guarded behaviours. Clean source,
# built by each package's own production build, must pass the package checkers
# and the behaviour tests in scripts/typescript-dist. Each guarded behaviour is
# then removed from a copy of the source, the copy is rebuilt by the same
# production build, and the behaviour test that guards it must fail on its own
# named assertion: a build, setup or import failure does not count.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aweb-dist-freshness.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
# Builds and behaviour tests make their temporary files inside this run's own
# directory, so they go with it on pass and on failure.
mkdir "$TMP/tmp"
export TMPDIR="$TMP/tmp"
TESTS="$ROOT/scripts/typescript-dist"

# Run a package's production build, showing its output only when it fails.
build() {
  local out
  if ! out="$(cd "$1" && npm run build 2>&1)"; then
    printf 'build failed in %s:\n%s\n' "$1" "$out" >&2
    return 1
  fi
}

# Run a command under scripts/lib/bounded_group.py: its own process group, one
# deadline of SECONDS, and the group killed and observed empty on every exit
# path. $TMP/verdict says how it ended: "exit N", "timeout" or "interrupted".
bounded() {
  local seconds="$1"
  shift
  rm -f "$TMP/verdict"
  python3 "$ROOT/scripts/lib/bounded_group.py" --seconds "$seconds" --verdict "$TMP/verdict" -- "$@"
}

# Run behaviour tests with the TypeScript loader the Pi package uses, bounded.
behaviour_test() {
  (cd "$ROOT/packages/pi-extension" && bounded 120 node --import tsx --test --test-reporter=tap "$@")
}

# Positive direction: the production package builds pass the package checkers
# and every behaviour test.
build "$ROOT/packages/channel"
build "$ROOT/packages/pi-extension"
node "$ROOT/packages/channel/scripts/check-package-dist.mjs" >/dev/null
node "$ROOT/packages/pi-extension/scripts/check-package-dist.mjs" >/dev/null
AWEB_CHANNEL_DIST="$ROOT/packages/channel/dist/index.js" behaviour_test "$TESTS/channel_bundle.test.mts" >/dev/null
AWEB_PI_DIST="$ROOT/packages/pi-extension/dist/index.js" behaviour_test "$TESTS/pi_bundle.test.mts" >/dev/null

# A session whose shutdown hook never settles keeps its process alive. The
# control must reach the withheld shutdown and then be stopped by the bound.
marker="$TMP/hung-shutdown.marker"
set +e
out="$(cd "$ROOT/packages/pi-extension" && AWEB_PI_DIST="$ROOT/packages/pi-extension/dist/index.js" \
  AWEB_HUNG_SHUTDOWN_MARKER="$marker" \
  bounded 20 node --import tsx --test --test-reporter=tap "$TESTS/pi_hung_shutdown.test.mts" 2>&1)"
status=$?
set -e
if [ "$status" -ne 254 ] || [ "$(cat "$TMP/verdict")" != timeout ] || [ ! -f "$marker" ]; then
  printf 'SELF-TEST FAIL: the hung-shutdown control was not held until its bound (exit %s, verdict %s, marker %s):\n%s\n' \
    "$status" "$(cat "$TMP/verdict")" "$([ -f "$marker" ] && echo written || echo absent)" "$out" >&2
  exit 1
fi

# The mutant tree mirrors the checkout's layout, so each package's production
# build resolves @awebai/channel-core to the mutated sibling exactly as it
# resolves the real one. channel-core's dependencies are copied: the build's
# provenance check requires them inside channel-core/node_modules.
mkdir -p "$TMP/scripts"
cp "$ROOT/scripts/check-node-build-provenance.mjs" "$TMP/scripts/"
for package in channel-core channel pi-extension; do
  mkdir -p "$TMP/packages/$package"
  for entry in package.json package-lock.json tsconfig.json scripts; do
    if [ -e "$ROOT/packages/$package/$entry" ]; then cp -R "$ROOT/packages/$package/$entry" "$TMP/packages/$package/"; fi
  done
done
cp -R "$ROOT/packages/channel-core/node_modules" "$TMP/packages/channel-core/node_modules"
for package in channel pi-extension; do
  mkdir -p "$TMP/packages/$package/node_modules/@awebai"
  for entry in "$ROOT/packages/$package/node_modules"/* "$ROOT/packages/$package/node_modules/.bin"; do
    name="$(basename "$entry")"
    if [ "$name" != "@awebai" ]; then ln -s "$entry" "$TMP/packages/$package/node_modules/$name"; fi
  done
  for entry in "$ROOT/packages/$package/node_modules/@awebai"/*; do
    name="$(basename "$entry")"
    if [ "$name" = "channel-core" ]; then
      ln -s ../../../channel-core "$TMP/packages/$package/node_modules/@awebai/channel-core"
    else
      ln -s "$entry" "$TMP/packages/$package/node_modules/@awebai/$name"
    fi
  done
done

# Copy every package's source afresh, then replace one exact passage of
# channel-core's source with its mutant.
mutate() {
  local file="$1" current="$2" mutant="$3"
  for package in channel-core channel pi-extension; do
    rm -rf "$TMP/packages/$package/src"
    cp -R "$ROOT/packages/$package/src" "$TMP/packages/$package/src"
  done
  python3 - "$TMP/packages/channel-core/src/$file" "$current" "$mutant" <<'PY'
import sys
from pathlib import Path

path, current, mutant = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
text = path.read_text(encoding="utf-8")
if text.count(current) != 1:
    raise SystemExit(f"expected one guarded passage in {path.name}, found {text.count(current)}")
path.write_text(text.replace(current, mutant), encoding="utf-8")
PY
}

# Rebuild a package from the mutated tree and require its named assertion to
# fail. scripts/lib/named_negative.py judges the run: the runner's verdict must
# be an ordinary exit with the same status, and the TAP stream must show that
# one test failing on that assertion.
expect_assertion_failure() {
  local package="$1" variable="$2" test_file="$3" name="$4" assertion="$5"
  local out status reason judged
  build "$TMP/packages/$package"
  set +e
  out="$(export "$variable=$TMP/packages/$package/dist/index.js"
    behaviour_test --test-name-pattern="$name" "$TESTS/$test_file" 2>&1)"
  status=$?
  reason="$(python3 "$ROOT/scripts/lib/named_negative.py" --status "$status" --verdict "$TMP/verdict" \
    --name "$name" --assertion "$assertion" <<<"$out")"
  judged=$?
  set -e
  case "$judged" in
    0) ;;
    1) echo "SELF-TEST FAIL: $package $reason" >&2; return 1 ;;
    *) printf 'SELF-TEST INCONCLUSIVE: %s %s:\n%s\n' "$package" "$reason" "$out" >&2; return 1 ;;
  esac
}

# S4a: the genesis key must derive the did:aw.
mutate identity/registry.ts \
'    if (computeStableID(genesisPub) !== resolution.did_aw) {
      return { outcome: "HARD_ERROR", error: "did:aw not derived from genesis key" };
    }
' ''
expect_assertion_failure channel AWEB_CHANNEL_DIST channel_bundle.test.mts \
  "a genesis whose key does not derive its did:aw is a hard error" "S4a: the genesis key must derive the did:aw"
expect_assertion_failure pi-extension AWEB_PI_DIST pi_bundle.test.mts \
  "Pi refuses a genesis whose key does not derive its did:aw" "S4a: the genesis key must derive the did:aw"

# S4b: the certificate's stable_id wins over identity.yaml's.
mutate config.ts \
'  const stableID = certificateStableID || identityStableID;' \
'  const stableID = identityStableID || certificateStableID;'
expect_assertion_failure pi-extension AWEB_PI_DIST pi_bundle.test.mts \
  "Pi takes the certificate's stable_id over identity.yaml's" "S4b: the certificate's stable_id must win over identity.yaml's"

# S4c: the local deadline closes the stream at its planned close.
mutate api/events.ts \
'    const deadlineTimer = setTimeout(() => {
      deadlineReached = true;
      attemptAbort.abort(new Error("event stream local deadline reached"));
    }, connection.plannedCloseAt - openedAt);
' \
'    const deadlineTimer = setTimeout(() => {}, connection.plannedCloseAt - openedAt);
'
expect_assertion_failure pi-extension AWEB_PI_DIST pi_bundle.test.mts \
  "Pi closes a stream at its requested deadline and reconnects" "S4c: the stream must close at its deadline"

# S4d: the byte-inactivity watchdog ends a silent stream.
mutate api/events.ts \
'    timer = setTimeout(() => {
      const error = new Error("event stream heartbeat timed out");
      cancelReader(error);
      settle(() => reject(error));
    }, EVENT_STREAM_INACTIVITY_MS);
' \
'    timer = setTimeout(() => {}, EVENT_STREAM_INACTIVITY_MS);
'
expect_assertion_failure pi-extension AWEB_PI_DIST pi_bundle.test.mts \
  "Pi gives up on a stream silent for 75 seconds and reconnects after the retry delay" \
  "S4d: a stream silent for 75 seconds must be closed"

# S4e: a settled backoff sleep removes its abort listener.
mutate api/events.ts \
'      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve();
' \
'      clearTimeout(timer);
      resolve();
'
expect_assertion_failure pi-extension AWEB_PI_DIST pi_bundle.test.mts \
  "Pi's settled backoff sleeps leave no listener on the session signal" \
  "S4e: listeners on the session signal grew across backoffs"

echo "self-test passed: clean TypeScript builds pass and each guarded behaviour fails its own assertion when removed"
