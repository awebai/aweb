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
# Usage:
#   check-node-audit.sh              audit all Node packages
#   check-node-audit.sh --self-test  prove the gate fails on a known-bad version
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

run_audits() {
  local status=0
  # Authoritative: these production dependencies are what get bundled/shipped.
  audit_package "channel-core" "AUTHORITATIVE - deps here are inlined into both bundles" || status=1
  # Weak by construction (see header), but a regression here is still real.
  audit_package "channel" "weak: runtime deps arrive via a file: link, not audited here" || status=1
  audit_package "pi-extension" "weak: same file: link structure as channel" || status=1
  return $status
}

# A gate is only worth its ability to FAIL. Rather than a synthetic fixture that
# would drift from the real packages, this pins a dependency to a version with a
# known published advisory and asserts the gate rejects it.
self_test() {
  local tmp status
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
  (cd "$tmp" && npm install --package-lock-only --silent >/dev/null 2>&1)
  (cd "$tmp" && npm audit --omit=dev --audit-level="$AUDIT_LEVEL" >/dev/null 2>&1)
  status=$?
  if [ "$status" -eq 0 ]; then
    echo "SELF-TEST FAIL: the gate accepted js-yaml 4.1.1, which has published"
    echo "advisories. It cannot detect the class of defect it exists to catch."
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
printf '\nFAIL: a Node production dependency has an advisory at or above %s.\n' "$AUDIT_LEVEL"
printf 'Patch it, or record a narrowly scoped exception with call-path evidence.\n'
exit 1
