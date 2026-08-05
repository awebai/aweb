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

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

MODE="${1:-}"; shift || true
DIR='' VERSION='' OUT='' TGZ='' PACKAGE='' OBSERVED=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tgz) TGZ="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --observed) OBSERVED="$2"; shift 2 ;;
    *) echo "npm-exact-publish: unknown argument $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  pack-inspect)
    [[ -n "$DIR" && -n "$VERSION" && -n "$OUT" ]] \
      || { echo "pack-inspect requires --dir --version --out" >&2; exit 2; }
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    (cd "$DIR" && npm pack --pack-destination "$OUT" >/dev/null)
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
    printf 'STAGED: %s sha256 %s\n' "$(basename "$tgz")" "$(sha256 "$tgz")"
    ;;
  publish-exact)
    [[ -n "$TGZ" && -f "$TGZ" ]] || fail "publish-exact requires an existing --tgz"
    npm publish "$TGZ" --access public
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
  *)
    echo "npm-exact-publish: mode must be pack-inspect | publish-exact | verify-published" >&2
    exit 2
    ;;
esac
