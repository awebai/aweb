#!/usr/bin/env bash
# Audit the Node packages' production dependencies (default-aajc.14, Track 1).
#
# WHY THIS AUDITS channel-core AND NOT JUST THE SHIPPED PACKAGES — this is the
# whole point of the gate, and getting it wrong produces a green light about the
# wrong artifact:
#
#   `npm audit` in channel/ reports on THREE production dependencies. The
#   runtime code it actually ships comes from @awebai/channel-core, which is a
#   `file:../channel-core` DEV dependency, so channel-core's production
#   dependencies are outside channel's audit scope entirely — while esbuild
#   inlines that very code into channel/dist/index.js. A vulnerable js-yaml in
#   channel-core was therefore invisible to `npm audit` in channel, which
#   reported "found 0 vulnerabilities" the whole time.
#
# So channel-core's audit is the AUTHORITATIVE one: it is where the dependencies
# that actually ship are declared. channel and pi-extension are audited too, but
# a clean result from them is weak evidence by construction, not strong.
#
# Scope, stated rather than implied: this checks published advisories against
# declared production dependencies. It does not prove a given advisory is
# reachable in our code, and it does not audit the Go or Python toolchains
# (Go: default-aall; Python locks: routed to the owning teams).
#
# Before consulting advisories, verify that both shipped bundles resolve every
# channel-core production dependency at the version in channel-core's lockfile.
# This is authoritative build provenance; bundle string markers are not.
#
# Usage:
#   check-node-audit.sh              verify build inputs, then audit all Node packages
#   check-node-audit.sh --self-test  prove both gates fail for their intended reasons
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Fail on anything at or above this severity.
AUDIT_LEVEL="${AUDIT_LEVEL:-moderate}"

audit_package() {
  local pkg="$1" note="$2" out status
  printf '\n--- %s (%s) ---\n' "$pkg" "$note"
  if [ ! -f "$ROOT/$pkg/package.json" ]; then
    echo "SKIP: no package.json"
    return 0
  fi
  out="$(cd "$ROOT/$pkg" && npm audit --omit=dev --audit-level="$AUDIT_LEVEL" 2>&1)"
  status=$?
  echo "$out" | tail -20
  return $status
}

# Provenance and advisories fail for different reasons and need different
# remedies, so they are tracked apart: reporting a missing workspace install as
# "a dependency has an advisory" sends the reader hunting for a CVE that does
# not exist.
run_audits() {
  provenance_ok=1
  advisory_found=0
  node "$ROOT/scripts/check-node-build-provenance.mjs" || provenance_ok=0
  # Authoritative: these production dependencies are what get bundled/shipped.
  audit_package "channel-core" "AUTHORITATIVE - deps here are inlined into both bundles" || advisory_found=1
  # Weak by construction (see header), but a regression here is still real.
  audit_package "channel" "weak: runtime deps arrive via a file: link, not audited here" || advisory_found=1
  audit_package "pi-extension" "weak: same file: link structure as channel" || advisory_found=1
  [ "$provenance_ok" -eq 1 ] && [ "$advisory_found" -eq 0 ]
}

# A gate is only worth its ability to FAIL. Rather than a synthetic fixture that
# would drift from the real packages, this pins a dependency to a version with a
# known published advisory and asserts the gate rejects it.
self_test() {
  local tmp status out
  if ! node --test "$ROOT/scripts/test-node-build-provenance.mjs"; then
    echo "SELF-TEST FAIL: the build-provenance gate did not reject its bad fixture"
    return 1
  fi
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  cat > "$tmp/package.json" <<'JSON'
{
  "name": "audit-gate-self-test",
  "version": "0.0.0",
  "private": true,
  "dependencies": { "js-yaml": "4.1.1" }
}
JSON
  # js-yaml 4.1.1 carries GHSA-52cp-r559-cp3m (high) and GHSA-h67p-54hq-rp68,
  # both fixed in 4.3.0 — the exact advisories default-aajc.14 patched.
  #
  # A non-zero exit is NOT sufficient evidence that the gate works: an
  # unreachable registry also exits non-zero, and treating that as "the gate
  # rejected the bad dependency" would make this self-test report PASS exactly
  # when it is least able to detect anything. So the install must succeed, and
  # the failure must be FOR THE RIGHT REASON — the advisory output has to name
  # the vulnerable package.
  if ! (cd "$tmp" && npm install --package-lock-only --silent >/dev/null 2>&1); then
    echo "SELF-TEST INCONCLUSIVE: could not resolve the fixture against the npm"
    echo "registry. This is an environment failure, NOT evidence about the gate."
    return 1
  fi
  out="$(cd "$tmp" && npm audit --omit=dev --audit-level="$AUDIT_LEVEL" 2>&1)"
  status=$?
  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: the gate accepted js-yaml 4.1.1, which has published"
    echo "advisories. It cannot detect the class of defect it exists to catch."
    return 1
  fi
  if ! printf '%s' "$out" | grep -qi 'js-yaml'; then
    echo "SELF-TEST FAIL: the audit exited non-zero but did not report js-yaml,"
    echo "so the failure was not the advisory this fixture exists to trigger:"
    printf '%s\n' "$out" | tail -10
    return 1
  fi
  echo "self-test passed: the gate rejects a dependency with a known advisory"
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

if run_audits; then
  printf '\nNode production dependencies have no advisories at or above %s.\n' "$AUDIT_LEVEL"
  exit 0
fi
if [ "$provenance_ok" -eq 0 ]; then
  printf '\nFAIL: the build-provenance check did not pass. This is NOT an advisory\n'
  printf 'finding. It usually means the workspace dependencies are not installed:\n'
  printf '  (cd channel-core && npm ci) && (cd channel && npm ci) && (cd pi-extension && npm ci)\n'
fi
if [ "$advisory_found" -eq 1 ]; then
  printf '\nFAIL: a Node production dependency has an advisory at or above %s.\n' "$AUDIT_LEVEL"
  printf 'Patch it, or record a narrowly scoped exception with call-path evidence.\n'
fi
exit 1
