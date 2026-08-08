#!/usr/bin/env bash
# Build-once, inspect, publish-exact-bytes for the PyPI lanes (server, awid).
#
#   inspect-staged    --dist <dir> --package <name> --version <X.Y.Z>
#       Refuses unless the dist holds EXACTLY one sdist and one wheel for
#       the package at the version, the version inside both artifacts
#       (PKG-INFO / METADATA) equals the declared one, and prints one
#       sha256 per file.
#   plan-publish      --dist <dir> --package <name> --version <X.Y.Z>
#                     --observed-status <http-code> [--observed-json <file>]
#       Decides what continuation may publish. 404 means the release is
#       absent: every staged file publishes. 200 means partial or complete
#       state: exact existing files adopt, mismatched or extra remote files
#       refuse permanently, and ONLY the missing staged filenames print
#       (one per line) for publication. Any other status is an outage and
#       refuses - unavailability is never permission to publish.
#   verify-published  --dist <dir> --package <name> --version <X.Y.Z>
#                     [--observed-json <file>]
#       Compares PyPI's per-file sha256 (JSON API, or the supplied
#       observation) against the staged files: the complete remote set must
#       EXACTLY equal the staged set - a missing, mismatched, or extra
#       remote file refuses. PyPI can never re-upload, so any mismatch is
#       permanent.

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

MODE="${1:-}"; shift || true
DIST='' PACKAGE='' VERSION='' OBSERVED='' STATUS=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) DIST="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --observed-json) OBSERVED="$2"; shift 2 ;;
    --observed-status) STATUS="$2"; shift 2 ;;
    *) echo "pypi-exact-publish: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DIST" && -n "$PACKAGE" && -n "$VERSION" ]] \
  || { echo "pypi-exact-publish: --dist --package --version are required" >&2; exit 2; }

# PEP 625: distribution filenames normalize dashes to underscores.
NORMALIZED="${PACKAGE//-/_}"

case "$MODE" in
  inspect-staged)
    python3 - "$DIST" "$NORMALIZED" "$VERSION" <<'PY'
import hashlib, os, re, sys, tarfile, zipfile
dist, normalized, version = sys.argv[1:4]
files = sorted(os.listdir(dist))
sdists = [f for f in files if f == f"{normalized}-{version}.tar.gz"]
wheels = [f for f in files if re.fullmatch(
    re.escape(normalized) + "-" + re.escape(version) + r"-[^-]+-[^-]+-[^-]+\.whl", f)]
extras = [f for f in files if f not in sdists + wheels]
if len(sdists) != 1 or len(wheels) != 1 or extras:
    sys.exit(f"REFUSE: dist must hold exactly one sdist and one wheel for "
             f"{normalized} {version}; found sdists={sdists} wheels={wheels} "
             f"extras={extras}")

def meta_version(text):
    for line in text.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None

with tarfile.open(os.path.join(dist, sdists[0])) as t:
    member = f"{normalized}-{version}/PKG-INFO"
    try:
        inside = meta_version(t.extractfile(member).read().decode())
    except KeyError:
        sys.exit(f"REFUSE: sdist lacks {member}")
if inside != version:
    sys.exit(f"REFUSE: sdist PKG-INFO declares version {inside}, expected {version}")

with zipfile.ZipFile(os.path.join(dist, wheels[0])) as z:
    meta = [n for n in z.namelist()
            if n == f"{normalized}-{version}.dist-info/METADATA"]
    if not meta:
        sys.exit(f"REFUSE: wheel lacks {normalized}-{version}.dist-info/METADATA")
    inside = meta_version(z.read(meta[0]).decode())
if inside != version:
    sys.exit(f"REFUSE: wheel METADATA declares version {inside}, expected {version}")

for name in sdists + wheels:
    with open(os.path.join(dist, name), "rb") as f:
        print(f"STAGED: {name} sha256 {hashlib.sha256(f.read()).hexdigest()}")
PY
    ;;
  plan-publish)
    [[ -n "$STATUS" ]] || { echo "plan-publish requires --observed-status" >&2; exit 2; }
    if [[ "$STATUS" == "404" ]]; then
      ls "$DIST" | grep -E "^${NORMALIZED}-.*(\\.tar\\.gz|\\.whl)$"
      exit 0
    fi
    [[ "$STATUS" == "200" ]] \
      || fail "PyPI observation returned status ${STATUS}; unavailability is never permission to publish"
    [[ -n "$OBSERVED" ]] || { echo "plan-publish with status 200 requires --observed-json" >&2; exit 2; }
    python3 - "$DIST" "$OBSERVED" "$NORMALIZED" "$VERSION" <<'PY'
import hashlib, json, os, sys
dist, observed_path, normalized, version = sys.argv[1:5]
observed = {
    u["filename"]: u["digests"]["sha256"]
    for u in json.load(open(observed_path)).get("urls", [])
}
staged = {}
for name in sorted(os.listdir(dist)):
    if name.startswith(f"{normalized}-") and (
        name.endswith(".tar.gz") or name.endswith(".whl")
    ):
        with open(os.path.join(dist, name), "rb") as f:
            staged[name] = hashlib.sha256(f.read()).hexdigest()
extra = sorted(set(observed) - set(staged))
if extra:
    sys.exit(f"REFUSE: PyPI serves files not in the staged set: {extra}; "
             "permanent")
for name, digest in staged.items():
    remote = observed.get(name)
    if remote is not None and remote != digest:
        sys.exit(f"REFUSE: {name}: PyPI serves sha256 {remote}, staged is "
                 f"{digest}; PyPI can never re-upload, this is permanent")
for name in staged:
    if name not in observed:
        print(name)
PY
    ;;
  verify-published)
    if [[ -z "$OBSERVED" ]]; then
      OBSERVED="$(mktemp)"
      # PyPI propagates too, so an immediate read after upload can 404 for a
      # release that succeeded. The npm lane reported exactly that as a failed
      # release once, with correct bytes already published; the old message
      # here ("has no release") made the same mistake worse by asserting
      # absence when it could not tell absence from lag or from an outage.
      #
      # 404 is retried within a bounded window; any other HTTP status is not,
      # because an outage is never evidence of absence. Exhausting the window
      # still refuses.
      # TWO bounds, whichever comes first, plus a per-REQUEST bound. Without
      # connect/max timeouts a single hung request outlasts the whole window
      # and "bounded" is a bound in name only.
      deadline_seconds="${PYPI_VERIFY_DEADLINE:-120}"
      backoff="${PYPI_VERIFY_BACKOFF:-6}"
      req_cap="${PYPI_VERIFY_REQUEST_TIMEOUT:-30}"
      max_attempts="${PYPI_VERIFY_ATTEMPTS:-20}"
      deadline=$((SECONDS + deadline_seconds))
      attempts=0
      last=""
      while :; do
        attempts=$((attempts + 1))
        remaining=$((deadline - SECONDS))
        (( remaining < 1 )) && remaining=1
        req="$req_cap"; (( remaining < req )) && req="$remaining"
        status="$(curl -sSL -o "$OBSERVED" -w '%{http_code}' \
          --connect-timeout "$req" --max-time "$req" \
          "https://pypi.org/pypi/${PACKAGE}/${VERSION}/json" 2>/dev/null || true)"
        [[ "$status" == "200" ]] && break
        # Four outcomes, four diagnostics. Collapsing them is the reporting
        # defect itself: waiting cannot fix credentials, and calling an outage
        # or a timeout "absent" asserts something the observation cannot support.
        case "$status" in
          401|403)
            fail "PyPI refused authorization for ${PACKAGE} ${VERSION} (HTTP ${status}); this is permanent and waiting cannot resolve it" ;;
          404) last="not yet visible" ;;
          000|"") last="request exceeded ${req}s or did not connect" ;;
          *)
            fail "PyPI is unavailable for ${PACKAGE} ${VERSION} (HTTP ${status}); unavailable is never evidence of absence" ;;
        esac
        if (( SECONDS + backoff >= deadline )) || (( attempts >= max_attempts )); then
          # After a completed upload, "never published" is not knowable. All
          # this observation supports is that it did not become visible in time.
          fail "PyPI did not serve ${PACKAGE} ${VERSION} within ${deadline_seconds}s after ${attempts} attempt(s) (${last}); visibility is unconfirmed, which is not the same as absent"
        fi
        printf 'waiting for %s %s to propagate (%s, %ds left)\n' \
          "$PACKAGE" "$VERSION" "$last" "$((deadline - SECONDS))" >&2
        sleep "$backoff"
      done
    fi
    python3 - "$DIST" "$OBSERVED" "$NORMALIZED" "$VERSION" <<'PY'
import hashlib, json, os, re, sys
dist, observed_path, normalized, version = sys.argv[1:5]
observed = {
    u["filename"]: u["digests"]["sha256"]
    for u in json.load(open(observed_path)).get("urls", [])
}
staged = [
    f for f in sorted(os.listdir(dist))
    if f.startswith(f"{normalized}-{version}") and
    (f.endswith(".tar.gz") or f.endswith(".whl"))
]
if not staged:
    sys.exit(f"REFUSE: no staged files for {normalized} {version}")
extra = sorted(set(observed) - set(staged))
if extra:
    sys.exit(f"REFUSE: PyPI serves files not in the staged set: {extra}; "
             "the complete remote set must exactly equal staged")
for name in staged:
    with open(os.path.join(dist, name), "rb") as f:
        local = hashlib.sha256(f.read()).hexdigest()
    remote = observed.get(name)
    if remote is None:
        sys.exit(f"REFUSE: {name} is staged but PyPI does not serve it")
    if remote != local:
        sys.exit(f"REFUSE: {name}: PyPI serves sha256 {remote}, staged is "
                 f"{local}; PyPI can never re-upload, this is permanent")
    print(f"VERIFIED: {name} published equals staged ({local})")
PY
    ;;
  *)
    echo "pypi-exact-publish: mode must be inspect-staged | plan-publish | verify-published" >&2
    exit 2
    ;;
esac
