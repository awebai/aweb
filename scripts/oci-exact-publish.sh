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
#   decide-tag        --tag-kind version|latest --staged sha256:<hex>
#                     --listing-status ok|failed --present yes|no
#                     --remote-digest sha256:<hex>|unavailable
#       Prints ADOPT or COPY, or refuses. An unavailable listing or digest
#       always refuses - observation failure is never permission to write.
#       A version tag with a different digest refuses permanently; latest is
#       the one planned mutable pointer and may transition to the staged
#       digest.
#   classify-listing  --tag <name>
#       Reads a tag-listing JSON document on stdin and prints yes or no for
#       the tag's presence. Refuses unless the document is a JSON object
#       whose .Tags is an array of strings: a successful listing command
#       with malformed, truncated, or unexpected evidence is not an
#       observation, and callers must map that refusal to an unavailable
#       listing - never to absence.
#   require-absent    --listing-status ok|failed --present yes|no
#       Stage-only absence proof: a failed listing blocks (outage is never
#       proof of absence), a listed version refuses, and only a proven
#       absence continues.
#   observe-digest
#       Reads raw manifest bytes on stdin and prints sha256:<hex> of the
#       EXACT byte stream - no shell variable capture, which strips
#       trailing newlines, and no here-string, which appends one.
#   verify-published  --archive <oci.tar> --version <X.Y.Z>
#                     --source-sha <sha> --repository <ghcr.io/owner/name>
#                     [--observed-digest <tag>=sha256:<hex> ...]
#       Refuses unless the version tag AND latest resolve to exactly the
#       staged index digest (observations via skopeo inspect, or supplied).

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

MODE="${1:-}"; shift || true
ARCHIVE='' VERSION='' REPOSITORY='' SOURCE_SHA='' OUT=''
TAG_KIND='' STAGED='' LISTING_STATUS='' PRESENT='' REMOTE_DIGEST='' TAG_NAME=''
OBSERVED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --source-sha) SOURCE_SHA="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tag-kind) TAG_KIND="$2"; shift 2 ;;
    --tag) TAG_NAME="$2"; shift 2 ;;
    --staged) STAGED="$2"; shift 2 ;;
    --listing-status) LISTING_STATUS="$2"; shift 2 ;;
    --present) PRESENT="$2"; shift 2 ;;
    --remote-digest) REMOTE_DIGEST="$2"; shift 2 ;;
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
  decide-tag)
    [[ -n "$TAG_KIND" && -n "$STAGED" && -n "$LISTING_STATUS" && -n "$PRESENT" ]] \
      || { echo "decide-tag requires --tag-kind --staged --listing-status --present" >&2; exit 2; }
    [[ "$LISTING_STATUS" == "ok" ]] \
      || fail "tag listing unavailable; observation failure is never permission to write"
    if [[ "$PRESENT" == "no" ]]; then
      echo COPY
      exit 0
    fi
    [[ -n "$REMOTE_DIGEST" && "$REMOTE_DIGEST" != "unavailable" ]] \
      || fail "remote digest unavailable for a present tag; refusing to write blind"
    if [[ "$REMOTE_DIGEST" == "$STAGED" ]]; then
      echo ADOPT
    elif [[ "$TAG_KIND" == "latest" ]]; then
      # latest is the one planned mutable pointer; it may transition.
      echo COPY
    else
      fail "version tag resolves to $REMOTE_DIGEST, staged index is $STAGED; an immutable version tag is never rewritten"
    fi
    ;;
  classify-listing)
    [[ -n "$TAG_NAME" ]] \
      || { echo "classify-listing requires --tag" >&2; exit 2; }
    # -c keeps the script's stdin (the piped listing) as python's stdin; a
    # heredoc would displace it.
    python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception as exc:
    sys.exit(f"REFUSE: tag listing is not valid JSON ({exc}); malformed "
             "evidence is never an observation")
tags = doc.get("Tags") if isinstance(doc, dict) else None
if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
    sys.exit("REFUSE: tag listing .Tags is not an array of strings; "
             "malformed evidence is never an observation")
print("yes" if sys.argv[1] in tags else "no")
' "$TAG_NAME"
    ;;
  require-absent)
    [[ -n "$LISTING_STATUS" && -n "$PRESENT" ]] \
      || { echo "require-absent requires --listing-status --present" >&2; exit 2; }
    [[ "$LISTING_STATUS" == "ok" ]] \
      || fail "tag listing unavailable; an outage is never proof of absence"
    [[ "$PRESENT" == "no" ]] \
      || fail "the candidate version tag already exists in the registry"
    echo "ABSENT: proven by an authoritative listing"
    ;;
  observe-digest)
    python3 -c 'import hashlib, sys; print("sha256:" + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
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
    for tag in "$VERSION" latest; do
      if [[ -n "${observed_map[$tag]:-}" ]]; then
        remote="${observed_map[$tag]}"
      else
        # GHCR propagates like every other registry, so a push is not
        # instantly visible to an inspect. The npm lane reported a successful
        # release as FAILED for exactly this reason. A missing manifest is
        # retried within a bounded window; any other skopeo failure is not,
        # because an outage is never evidence of absence. Exhausting the
        # window still refuses.
        attempts="${OCI_VERIFY_ATTEMPTS:-10}"
        delay="${OCI_VERIFY_DELAY:-6}"
        attempt=1
        remote=""
        while :; do
          skopeo_err="$(mktemp)"
          if raw="$(skopeo inspect --raw "docker://${REPOSITORY}:${tag}" \
               2>"$skopeo_err")" && [[ -n "$raw" ]]; then
            rm -f "$skopeo_err"
            remote="sha256:$(printf '%s' "$raw" \
              | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } \
              | awk '{print $1}')"
            break
          fi
          # Four outcomes, four diagnostics. Auth is checked FIRST and is
          # permanent: waiting cannot fix a credential, and an "unauthorized"
          # reply can also carry the word "not found", so testing absence
          # first would misfile it as propagation and retry it pointlessly.
          if grep -qiE 'unauthoriz|authentication required|denied|forbidden|UNAUTHORIZED|DENIED' \
               "$skopeo_err"; then
            printf '%s\n' "$(cat "$skopeo_err")" >&2
            rm -f "$skopeo_err"
            fail "${REPOSITORY}:${tag} refused authorization; this is permanent and waiting cannot resolve it"
          fi
          if ! grep -qiE 'manifest unknown|not found|was not found|NAME_UNKNOWN|MANIFEST_UNKNOWN' \
               "$skopeo_err"; then
            printf '%s\n' "$(cat "$skopeo_err")" >&2
            rm -f "$skopeo_err"
            fail "${REPOSITORY}:${tag} is unavailable; unavailable is never evidence of absence"
          fi
          rm -f "$skopeo_err"
          if [[ "$attempt" -ge "$attempts" ]]; then
            fail "${REPOSITORY}:${tag} is still absent after ${attempts} attempts; it was never pushed"
          fi
          printf 'waiting for %s:%s to propagate (attempt %d/%d)\n' \
            "$REPOSITORY" "$tag" "$attempt" "$attempts" >&2
          sleep "$delay"
          attempt=$((attempt + 1))
        done
      fi
      [[ "$remote" == "$staged" ]] \
        || fail "${REPOSITORY}:${tag} resolves to ${remote}, staged index is ${staged}"
      printf 'VERIFIED: %s:%s resolves to the staged index %s\n' \
        "$REPOSITORY" "$tag" "$staged"
    done
    ;;
  *)
    echo "oci-exact-publish: mode must be inspect-staged | classify-listing | decide-tag | require-absent | observe-digest | verify-published" >&2
    exit 2
    ;;
esac
