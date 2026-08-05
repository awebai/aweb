#!/usr/bin/env bash
# Self-test for scripts/pypi-exact-publish.sh, no network.
#   green: a coherent one-sdist/one-wheel dist inspects and verifies
#          against a matching observation
#   reds:  extra file, missing wheel, version mismatch inside the sdist,
#          version mismatch inside the wheel, remote digest mismatch,
#          staged file absent from the remote observation

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/pypi-exact-publish.sh"
PASS=0
fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_dist() {
  # $1 dist dir, $2 version-in-sdist, $3 version-in-wheel
  local dist="$1" sv="$2" wv="$3"
  rm -rf "$dist"; mkdir -p "$dist"
  python3 - "$dist" "$sv" "$wv" <<'PY'
import io, os, sys, tarfile, zipfile
dist, sdist_version, wheel_version = sys.argv[1:4]
version = "1.2.3"
sdist = os.path.join(dist, f"fixture_pkg-{version}.tar.gz")
with tarfile.open(sdist, "w:gz") as t:
    body = f"Metadata-Version: 2.1\nName: fixture-pkg\nVersion: {sdist_version}\n".encode()
    info = tarfile.TarInfo(f"fixture_pkg-{version}/PKG-INFO")
    info.size = len(body)
    t.addfile(info, io.BytesIO(body))
wheel = os.path.join(dist, f"fixture_pkg-{version}-py3-none-any.whl")
with zipfile.ZipFile(wheel, "w") as z:
    z.writestr(f"fixture_pkg-{version}.dist-info/METADATA",
               f"Metadata-Version: 2.1\nName: fixture-pkg\nVersion: {wheel_version}\n")
PY
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

observation() {
  # matching PyPI-shaped observation for the current dist
  python3 - "$tmp/dist" "$tmp/observed.json" <<'PY'
import hashlib, json, os, sys
dist, out = sys.argv[1:3]
urls = []
for name in sorted(os.listdir(dist)):
    with open(os.path.join(dist, name), "rb") as f:
        urls.append({"filename": name,
                     "digests": {"sha256": hashlib.sha256(f.read()).hexdigest()}})
json.dump({"urls": urls}, open(out, "w"))
PY
}

inspect() {
  bash "$LANE" inspect-staged --dist "$tmp/dist" \
    --package fixture-pkg --version 1.2.3 2>&1
}

# green
make_dist "$tmp/dist" 1.2.3 1.2.3
out="$(inspect)" || fail "coherent dist refused: $out"
grep -c "STAGED:" <<<"$out" | grep -qx 2 || fail "expected 2 staged lines: $out"
ok "coherent dist inspects with one sdist and one wheel"

observation
bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-json "$tmp/observed.json" >/dev/null \
  || fail "matching observation refused"
ok "matching observation verifies"

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then fail "$label: accepted what it must refuse"; fi
  grep -qi "$needle" <<<"$out" || fail "$label: refusal does not name ($needle): $out"
  ok "$label refused, naming: $needle"
}

make_dist "$tmp/dist" 1.2.3 1.2.3
echo x > "$tmp/dist/stray.txt"
expect_refusal "extra file" "stray" bash "$LANE" inspect-staged \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3

make_dist "$tmp/dist" 1.2.3 1.2.3
rm "$tmp/dist"/*.whl
expect_refusal "missing wheel" "wheel" bash "$LANE" inspect-staged \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3

make_dist "$tmp/dist" 9.9.9 1.2.3
expect_refusal "sdist version mismatch" "PKG-INFO" bash "$LANE" inspect-staged \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3

make_dist "$tmp/dist" 1.2.3 9.9.9
expect_refusal "wheel version mismatch" "METADATA" bash "$LANE" inspect-staged \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3

make_dist "$tmp/dist" 1.2.3 1.2.3
observation
python3 - "$tmp/observed.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["urls"][0]["digests"]["sha256"] = "0" * 64
json.dump(d, open(sys.argv[1], "w"))
PY
expect_refusal "remote digest mismatch" "permanent" bash "$LANE" verify-published \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3 \
  --observed-json "$tmp/observed.json"

observation
python3 - "$tmp/observed.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["urls"] = d["urls"][1:]
json.dump(d, open(sys.argv[1], "w"))
PY
expect_refusal "staged file absent remotely" "does not serve" bash "$LANE" verify-published \
  --dist "$tmp/dist" --package fixture-pkg --version 1.2.3 \
  --observed-json "$tmp/observed.json"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
