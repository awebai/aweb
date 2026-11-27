#!/usr/bin/env bash
# Build-once, inspect, publish-exact-bytes for the awid image (Option A):
# the multi-platform image is built to an OCI archive WITHOUT any registry
# push; this script binds its complete identity, and continuation transfers
# those exact bytes with skopeo.
#
#   inspect-staged    --archive <oci.tar> --version <X.Y.Z>
#                     --source-sha <sha> --out <identities.json>
#       Refuses unless the archive is a coherent OCI layout whose effective
#       image index carries EXACTLY linux/amd64 and linux/arm64, every
#       referenced manifest, config, and layer blob is present and hashes to
#       its declared digest, and BOTH config blobs label
#       org.opencontainers.image.version == the declared version and
#       org.opencontainers.image.revision == the declared source SHA.
#       Machine JSON goes ONLY to --out; stdout carries diagnostics.
#   verify-published  --archive <oci.tar> --version <X.Y.Z>
#                     --source-sha <sha> --repository <ghcr.io/owner/name>
#                     [--version-only] [--observed-digest <tag>=sha256:<hex> ...]
#       Refuses unless the version tag AND latest resolve to exactly the
#       staged index digest (observations via skopeo inspect, or supplied).
#       --version-only verifies just the immutable RC tag, never latest.

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

# A bound of zero is not a bound: timeout(1) treats 0 as NO limit (measured:
# "timeout 0 sleep 3" returns 0 after three seconds), so a well-meaning
# override of 0 silently restores the indefinite hang.
require_positive_int() {
  [[ "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]] \
    || fail "$1 must be a positive integer, got '${2}'; a zero or malformed bound is not a bound"
}
require_nonnegative_int() {
  [[ "$2" =~ ^[0-9]+$ ]] || fail "$1 must be a non-negative integer, got '${2}'"
}

MODE="${1:-}"; shift || true
ARCHIVE='' VERSION='' REPOSITORY='' SOURCE_SHA='' OUT=''
OBSERVED=()
VERSION_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version-only) VERSION_ONLY=true; shift ;;
    --archive) ARCHIVE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --source-sha) SOURCE_SHA="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --observed-digest) OBSERVED+=("$2"); shift 2 ;;
    *) echo "oci-exact-publish: unknown argument $1" >&2; exit 2 ;;
  esac
done

index_digest() {
  python3 - "$ARCHIVE" "$VERSION" "$SOURCE_SHA" <<'PY'
import hashlib, json, sys, tarfile

archive, version, source_sha = sys.argv[1:4]
t = tarfile.open(archive)

def read(name):
    member = t.extractfile(name)
    if member is None:
        sys.exit(f"REFUSE: OCI layout member {name} is missing")
    return member.read()

def blob(digest):
    algo, _, hex_ = digest.partition(":")
    if algo != "sha256" or not hex_:
        sys.exit(f"REFUSE: unsupported blob digest {digest}")
    try:
        data = read(f"blobs/sha256/{hex_}")
    except KeyError:
        sys.exit(f"REFUSE: blob {digest} referenced but missing from the archive")
    actual = hashlib.sha256(data).hexdigest()
    if actual != hex_:
        sys.exit(f"REFUSE: blob {digest} hashes to {actual}")
    return data

names = t.getnames()
if "oci-layout" not in names or "index.json" not in names:
    sys.exit("REFUSE: archive is not an OCI layout (oci-layout/index.json missing)")
top = json.loads(read("index.json"))
manifests = top.get("manifests", [])
INDEX = "application/vnd.oci.image.index.v1+json"
if len(manifests) == 1 and manifests[0].get("mediaType") == INDEX:
    index_digest = manifests[0]["digest"]
    index_bytes = blob(index_digest)
    index = json.loads(index_bytes)
else:
    sys.exit("REFUSE: top-level index must reference exactly one image index")

platforms = {}
for entry in index.get("manifests", []):
    p = entry.get("platform", {})
    key = f"{p.get('os')}/{p.get('architecture')}"
    if key in platforms:
        sys.exit(f"REFUSE: platform {key} appears more than once in the index")
    platforms[key] = entry
if set(platforms) != {"linux/amd64", "linux/arm64"}:
    sys.exit(f"REFUSE: index platforms are {sorted(platforms)}, expected "
             "exactly linux/amd64 and linux/arm64")

identities = {"index": index_digest, "platforms": {}}
for key, entry in platforms.items():
    manifest = json.loads(blob(entry["digest"]))
    config_digest = manifest["config"]["digest"]
    config = json.loads(blob(config_digest))
    labels = (config.get("config") or {}).get("Labels") or {}
    if labels.get("org.opencontainers.image.version") != version:
        sys.exit(f"REFUSE: platform {key} config labels version "
                 f"{labels.get('org.opencontainers.image.version')!r}, "
                 f"expected {version!r}")
    if labels.get("org.opencontainers.image.revision") != source_sha:
        sys.exit(f"REFUSE: platform {key} config labels revision "
                 f"{labels.get('org.opencontainers.image.revision')!r}, "
                 f"expected {source_sha!r}")
    layers = []
    for layer in manifest.get("layers", []):
        blob(layer["digest"])
        layers.append(layer["digest"])
    if not layers:
        sys.exit(f"REFUSE: platform {key} manifest carries no layers")
    identities["platforms"][key] = {
        "manifest": entry["digest"],
        "config": config_digest,
        "layers": layers,
    }
print(json.dumps(identities, indent=2, sort_keys=True))
PY
}

case "$MODE" in
  inspect-staged)
    [[ -n "$ARCHIVE" && -n "$VERSION" && -n "$SOURCE_SHA" && -n "$OUT" ]] \
      || { echo "inspect-staged requires --archive --version --source-sha --out" >&2; exit 2; }
    identities="$(index_digest)"
    # Machine JSON only to the file; stdout carries diagnostics only.
    printf '%s\n' "$identities" > "$OUT"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT" \
      || fail "identities output is not valid JSON"
    printf 'STAGED INDEX: %s\n' \
      "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["index"])' "$OUT")"
    ;;
  verify-published)
    [[ -n "$REPOSITORY" && -n "$ARCHIVE" && -n "$VERSION" && -n "$SOURCE_SHA" ]] \
      || { echo "verify-published requires --archive --version --source-sha --repository" >&2; exit 2; }
    identities="$(index_digest)"
    staged="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["index"])' <<<"$identities")"
    declare -A observed_map=()
    for pair in "${OBSERVED[@]+"${OBSERVED[@]}"}"; do
      observed_map["${pair%%=*}"]="${pair#*=}"
    done
    tags=("$VERSION")
    if [[ "$VERSION_ONLY" == false ]]; then tags+=(latest); fi
    for tag in "${tags[@]}"; do
      if [[ -n "${observed_map[$tag]:-}" ]]; then
        remote="${observed_map[$tag]}"
      else
        # GHCR propagates like every other registry, so a push is not
        # instantly visible to an inspect. A missing manifest is retried until
        # a WALL-CLOCK deadline; each request is itself bounded, because a
        # single hung request would otherwise outlast the whole window and the
        # "bound" would be a bound in name only.
        #
        # The response is written to a FILE and the file is hashed. Capturing
        # it in a variable strips a trailing newline and a here-string appends
        # one, so either hashes bytes skopeo never returned - the hazard
        # service-image-release.yml documents, and one this code got wrong once.
        # TWO bounds, whichever comes first. The deadline is the one that
        # matters in production - it is what makes "bounded" true in wall-clock
        # terms even if every request hangs. The attempt cap keeps the loop and
        # its controls deterministic.
        deadline_seconds="${OCI_VERIFY_DEADLINE:-120}"
        backoff="${OCI_VERIFY_BACKOFF:-6}"
        req_cap="${OCI_VERIFY_REQUEST_TIMEOUT:-30}"
        max_attempts="${OCI_VERIFY_ATTEMPTS:-20}"
        require_positive_int OCI_VERIFY_DEADLINE "$deadline_seconds"
        require_positive_int OCI_VERIFY_REQUEST_TIMEOUT "$req_cap"
        require_positive_int OCI_VERIFY_ATTEMPTS "$max_attempts"
        require_nonnegative_int OCI_VERIFY_BACKOFF "$backoff"
        # Every observation must be capped. Running skopeo bare when no timeout
        # capability exists was a convenience that defeated the guarantee: it
        # is exactly the unbounded call this task removes. Refuse instead, so
        # the absence of a bound is visible rather than silent.
        timeout_bin="${OCI_TIMEOUT_BIN:-timeout}"
        command -v "$timeout_bin" >/dev/null 2>&1 \
          || fail "no bounded-execution capability: '${timeout_bin}' is not available, and an unbounded registry observation is not permitted (install coreutils timeout or set OCI_TIMEOUT_BIN)"
        deadline=$((SECONDS + deadline_seconds))
        attempts=0
        remote=""
        last=""
        while :; do
          attempts=$((attempts + 1))
          skopeo_err="$(mktemp)"; raw_file="$(mktemp)"
          remaining=$((deadline - SECONDS))
          (( remaining < 1 )) && remaining=1
          req="$req_cap"; (( remaining < req )) && req="$remaining"
          # Capture the status in a CONDITION: under set -e a bare
          # "cmd; rc=$?" aborts the script before rc is ever assigned.
          # Capture the status in a CONDITION: under set -e a bare
          # "cmd; rc=$?" aborts the script before rc is ever assigned.
          rc=0
          "$timeout_bin" "$req" skopeo inspect --raw "docker://${REPOSITORY}:${tag}" \
            >"$raw_file" 2>"$skopeo_err" || rc=$?
          if [[ "$rc" -eq 0 && -s "$raw_file" ]]; then
            # The same byte-exact reader the production workflow pipes into -
            # stdin.buffer, no shell rewriting.
            remote="$(python3 -c 'import hashlib, sys; print("sha256:" + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())' <"$raw_file")"
            rm -f "$skopeo_err" "$raw_file"
            break
          fi
          # Auth is checked FIRST and is permanent: waiting cannot fix a
          # credential, and an unauthorized reply can itself contain "not
          # found", so testing absence first would misfile it as propagation.
          if grep -qiE 'unauthoriz|authentication required|denied|forbidden' "$skopeo_err"; then
            printf '%s\n' "$(cat "$skopeo_err")" >&2
            rm -f "$skopeo_err" "$raw_file"
            fail "${REPOSITORY}:${tag} refused authorization; this is permanent and waiting cannot resolve it"
          fi
          if [[ "$rc" -eq 124 ]]; then
            last="request exceeded ${req}s"
          elif grep -qiE 'manifest unknown|not found|was not found|NAME_UNKNOWN|MANIFEST_UNKNOWN' "$skopeo_err"; then
            last="not yet visible"
          else
            printf '%s\n' "$(cat "$skopeo_err")" >&2
            rm -f "$skopeo_err" "$raw_file"
            fail "${REPOSITORY}:${tag} is unavailable; unavailable is never evidence of absence"
          fi
          rm -f "$skopeo_err" "$raw_file"
          if (( SECONDS + backoff >= deadline )) || (( attempts >= max_attempts )); then
            # After a completed push, "never pushed" is not knowable. All this
            # observation supports is that it did not become visible in time.
            fail "${REPOSITORY}:${tag} did not become visible within ${deadline_seconds}s after ${attempts} attempt(s) (${last}); visibility is unconfirmed, which is not the same as absent"
          fi
          printf 'waiting for %s:%s to propagate (%s, %ds left)\n' \
            "$REPOSITORY" "$tag" "$last" "$((deadline - SECONDS))" >&2
          sleep "$backoff"
        done
      fi
      [[ "$remote" == "$staged" ]] \
        || fail "${REPOSITORY}:${tag} resolves to ${remote}, staged index is ${staged}"
      printf 'VERIFIED: %s:%s resolves to the staged index %s\n' \
        "$REPOSITORY" "$tag" "$staged"
    done
    ;;
  *)
    echo "oci-exact-publish: mode must be inspect-staged | verify-published" >&2
    exit 2
    ;;
esac
