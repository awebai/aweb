#!/usr/bin/env bash
# Self-test for scripts/pypi-exact-publish.sh. No network, except the
# real-builder case at the end: it uses the local uv and its cached build
# backend, and may fetch that backend on a cold cache.
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

# ── plan-publish: outage, adoption, partial, extra, mismatch ────────
make_dist "$tmp/dist" 1.2.3 1.2.3
expect_refusal "outage is never permission to publish" "unavailab" \
  bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 503

plan="$(bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 404)"
[[ "$(wc -l <<<"$plan" | tr -d ' ')" == "2" ]] \
  || fail "absent release must publish both staged files: $plan"
ok "absent release (404) plans both staged files"

observation
plan="$(bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 200 --observed-json "$tmp/observed.json")"
[[ -z "$plan" ]] || fail "complete exact remote state must plan nothing: $plan"
ok "complete exact remote state adopts everything, plans nothing"

python3 - "$tmp/observed.json" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1]))
d["urls"] = [u for u in d["urls"] if not u["filename"].endswith(".whl")]
json.dump(d, open(sys.argv[1], "w"))
PYX
plan="$(bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 200 --observed-json "$tmp/observed.json")"
[[ "$plan" == *.whl && "$(wc -l <<<"$plan" | tr -d ' ')" == "1" ]] \
  || fail "partial state must plan exactly the missing wheel: $plan"
ok "partial remote state plans only the missing staged file"

observation
python3 - "$tmp/observed.json" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1]))
d["urls"].append({"filename": "fixture_pkg-1.2.3-uninvited.whl",
                  "digests": {"sha256": "0" * 64}})
json.dump(d, open(sys.argv[1], "w"))
PYX
expect_refusal "extra remote file" "not in the staged set" \
  bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 200 --observed-json "$tmp/observed.json"
expect_refusal "extra remote file at verification" "not in the staged set" \
  bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-json "$tmp/observed.json"

observation
python3 - "$tmp/observed.json" <<'PYX'
import json, sys
d = json.load(open(sys.argv[1]))
d["urls"][0]["digests"]["sha256"] = "0" * 64
json.dump(d, open(sys.argv[1], "w"))
PYX
expect_refusal "mismatch at planning" "permanent" \
  bash "$LANE" plan-publish --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 --observed-status 200 --observed-json "$tmp/observed.json"

# ── verify-published resolving through PyPI ─────────────────────────
# Same defect the npm lane shipped: an immediate read after upload cannot tell
# propagation lag from a release that never happened, and the old message
# asserted "has no release" for all three causes at once.

fakebin="$tmp/fakebin"; mkdir -p "$fakebin"
curl_attempts="$tmp/curl-attempts"

# $1 = number of 404s before 200 ("always" never resolves); $2 = other status
make_fake_curl() {
  local fails_before_success="$1" other="${2:-}"
  : > "$curl_attempts"
  cat > "$fakebin/curl" <<FAKE
#!/usr/bin/env bash
echo x >> "$curl_attempts"
printf '%s\n' "\$*" >> "$tmp/curl-argv"
n=\$(wc -l < "$curl_attempts" | tr -d ' ')
out=""
prev=""
for a in "\$@"; do
  if [[ "\$prev" == "-o" ]]; then out="\$a"; fi
  prev="\$a"
done
if [[ "$other" == "hang" ]]; then sleep 30; printf '000'; exit 0; fi
if [[ -n "$other" ]]; then printf '%s' "$other"; exit 0; fi
if [[ "$fails_before_success" == "always" || "\$n" -le "$fails_before_success" ]]; then
  printf '404'; exit 0
fi
cp "$tmp/observed.json" "\$out"
printf '200'
FAKE
  chmod +x "$fakebin/curl"
}

curl_count() { wc -l < "$curl_attempts" | tr -d ' '; }

make_dist "$tmp/dist" 1.2.3 1.2.3
observation

# GREEN: transient 404s are lag; the step must survive them.
make_fake_curl 2
if PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=5 PYPI_VERIFY_BACKOFF=0 PYPI_VERIFY_DEADLINE=60 \
     bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
       --version 1.2.3 >/dev/null 2>&1; then
  ok "pypi verify-published survives propagation lag"
else
  fail "pypi verify-published must retry a 404 rather than assert absence"
fi
[[ "$(curl_count)" == "3" ]] \
  || fail "expected 3 attempts (2 lagging + 1 resolving), got $(curl_count)"
ok "pypi retries stop as soon as the release resolves"

# RED preserved: a release that never appears still refuses.
make_fake_curl always
if PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=3 PYPI_VERIFY_BACKOFF=0 PYPI_VERIFY_DEADLINE=60 \
     bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
       --version 1.2.3 >/dev/null 2>&1; then
  fail "a release that never resolves must still refuse"
fi
ok "pypi refuses a release that never appears"
[[ "$(curl_count)" == "3" ]] \
  || fail "expected the full 3 attempts before refusing, got $(curl_count)"
ok "pypi refusal comes only after the whole window"

# RED preserved: an outage is never proof of absence and is not retried.
make_fake_curl always 503
if PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=5 PYPI_VERIFY_BACKOFF=0 PYPI_VERIFY_DEADLINE=60 \
     bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
       --version 1.2.3 >/dev/null 2>&1; then
  fail "a PyPI outage must refuse"
fi
ok "pypi refuses on outage"
[[ "$(curl_count)" == "1" ]] \
  || fail "an outage must not be retried as lag; got $(curl_count) attempts"
ok "pypi distinguishes an outage from lag and never retries it"

# Auth is PERMANENT and must not be reported as an outage or as absence: a
# credential problem will never resolve by waiting, and calling it "unavailable"
# invites a retry that cannot succeed.
make_fake_curl always 403
out="$(PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=5 PYPI_VERIFY_BACKOFF=0 PYPI_VERIFY_DEADLINE=60 \
  bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
    --version 1.2.3 2>&1 || true)"
grep -qi "authoriz\|authentic" <<<"$out" \
  || fail "auth must be named as auth, not as outage or absence: $out"
grep -qvi "never published" <<<"$out" \
  || fail "auth must not be reported as absence: $out"
ok "pypi names an authorization failure permanently, not as absence or outage"
[[ "$(curl_count)" == "1" ]] \
  || fail "auth is permanent and must not be retried; got $(curl_count) attempts"
ok "pypi never retries an authorization failure"

# Exhaustion must not claim absence it cannot know after a completed upload.
make_fake_curl always
out="$(PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=2 PYPI_VERIFY_BACKOFF=0 \
  PYPI_VERIFY_DEADLINE=60 bash "$LANE" verify-published --dist "$tmp/dist" \
  --package fixture-pkg --version 1.2.3 2>&1 || true)"
verdict="$(grep '^REFUSE:' <<<"$out" || true)"
grep -q "visibility is unconfirmed" <<<"$verdict" \
  || fail "exhaustion must refuse as unconfirmed visibility: $verdict"
grep -qi "never published" <<<"$verdict" \
  && fail "exhaustion must not assert absence it cannot know: $verdict"
ok "pypi exhaustion reports unconfirmed visibility, never 'never published'"

# A hung request must not outlast the window. A fake curl cannot honour
# --max-time, so timing a fake proves nothing - an earlier version of this
# control passed with the timeouts REMOVED. What the lane actually owns is
# passing a positive per-request bound, so that is what is asserted.
: > "$tmp/curl-argv"
make_fake_curl always
PATH="$fakebin:$PATH" PYPI_VERIFY_ATTEMPTS=2 PYPI_VERIFY_BACKOFF=0 \
  PYPI_VERIFY_DEADLINE=60 PYPI_VERIFY_REQUEST_TIMEOUT=7 bash "$LANE" \
  verify-published --dist "$tmp/dist" --package fixture-pkg \
  --version 1.2.3 >/dev/null 2>&1 || true
argv="$(head -1 "$tmp/curl-argv")"
grep -q -- "--max-time" <<<"$argv" \
  || fail "curl must be given a per-request bound: $argv"
grep -q -- "--connect-timeout" <<<"$argv" \
  || fail "curl must be given a connect bound: $argv"
bound="$(sed -n 's/.*--max-time \([0-9][0-9]*\).*/\1/p' <<<"$argv")"
[[ -n "$bound" && "$bound" -gt 0 ]] \
  || fail "the per-request bound must be a positive integer: $argv"
[[ "$bound" -le 7 ]] \
  || fail "the per-request bound must not exceed the configured cap: $bound > 7"
ok "pypi passes curl a positive per-request bound within the cap"

# curl treats --max-time 0 and --connect-timeout 0 as NO limit (measured), so
# a zero override silently restores the indefinite hang and must refuse.
make_fake_curl 0
for knob in PYPI_VERIFY_DEADLINE PYPI_VERIFY_REQUEST_TIMEOUT PYPI_VERIFY_ATTEMPTS; do
  for bad in 0 abc -1; do
    out="$(PATH="$fakebin:$PATH" env "$knob=$bad" PYPI_VERIFY_BACKOFF=0 \
      bash "$LANE" verify-published --dist "$tmp/dist" --package fixture-pkg \
      --version 1.2.3 2>&1 || true)"
    grep -q "^REFUSE:.*positive integer" <<<"$out" \
      || fail "$knob=$bad must refuse as a non-positive bound: $out"
  done
done
ok "pypi refuses zero and malformed deadline/request/attempt overrides"

# ── real-builder pipeline: build -> workflow cleanup -> inspect ─────
# The hand-made dists above test the guard; the untested seam that broke a
# release was the pipeline between the real builder and the guard (uv build
# stamps a .gitignore the guard rightly refuses). Build a real package with
# the local uv toolchain, apply the exact cleanup the publish workflow
# applies, and require the result to inspect clean - builder drift reds here
# before a hosted runner sees it. Needs uv and its cached build backend.
awid_version="$(python3 -c "import tomllib; print(tomllib.load(open('$ROOT/awid/pyproject.toml','rb'))['project']['version'])")"
rm -rf "$tmp/real-dist"; mkdir -p "$tmp/real-dist"
uv build --sdist --wheel --out-dir "$tmp/real-dist" "$ROOT/awid" >/dev/null 2>&1 \
  || fail "real uv build of awid failed"
rm -f "$tmp/real-dist/.gitignore"
out="$(bash "$LANE" inspect-staged --dist "$tmp/real-dist" \
  --package awid-service --version "$awid_version" 2>&1)" \
  || fail "real-builder dist refused after workflow cleanup: $out"
grep -c "STAGED:" <<<"$out" | grep -qx 2 \
  || fail "real-builder dist must stage exactly the pair: $out"
ok "real uv build plus workflow cleanup inspects clean (builder-drift detector)"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
