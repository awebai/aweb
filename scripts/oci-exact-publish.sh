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
#   verify-published  --archive <oci.tar> --version <X.Y.Z>
#                     --source-sha <sha> --repository <ghcr.io/owner/name>
#                     [--observed-digest <tag>=sha256:<hex> ...]
#       Refuses unless the version tag AND latest resolve to exactly the
#       staged index digest (observations via skopeo inspect, or supplied).

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

MODE="${1:-}"; shift || true
ARCHIVE='' VERSION='' REPOSITORY='' SOURCE_SHA='' OUT=''
TAG_KIND='' STAGED='' LISTING_STATUS='' PRESENT='' REMOTE_DIGEST=''
OBSERVED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --source-sha) SOURCE_SHA="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tag-kind) TAG_KIND="$2"; shift 2 ;;
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
        remote="$(skopeo inspect --raw "docker://${REPOSITORY}:${tag}" \
          | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } \
          | awk '{print "sha256:"$1}')" \
          || fail "cannot observe ${REPOSITORY}:${tag}"
      fi
      [[ "$remote" == "$staged" ]] \
        || fail "${REPOSITORY}:${tag} resolves to ${remote}, staged index is ${staged}"
      printf 'VERIFIED: %s:%s resolves to the staged index %s\n' \
        "$REPOSITORY" "$tag" "$staged"
    done
    ;;
  *)
    echo "oci-exact-publish: mode must be inspect-staged | decide-tag | verify-published" >&2
    exit 2
    ;;
esac
