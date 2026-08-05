#!/usr/bin/env bash
# Build-once, inspect, publish-exact-bytes for the awid image (Option A):
# the multi-platform image is built to an OCI archive WITHOUT any registry
# push; this script binds its complete identity, and continuation transfers
# those exact bytes with skopeo.
#
#   inspect-staged    --archive <oci.tar> --version <X.Y.Z>
#       Refuses unless the archive is a coherent OCI layout whose effective
#       image index carries EXACTLY linux/amd64 and linux/arm64, with every
#       referenced manifest, config, and layer blob present and hashing to
#       its declared digest. Prints the index digest (the immutable identity
#       both registry tags must resolve to) and every bound identity.
#   verify-published  --archive <oci.tar> --version <X.Y.Z>
#                     --repository <ghcr.io/owner/name>
#                     [--observed-digest <tag>=sha256:<hex> ...]
#       Refuses unless the version tag AND latest resolve to exactly the
#       staged index digest (observations via skopeo inspect, or supplied).

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

MODE="${1:-}"; shift || true
ARCHIVE='' VERSION='' REPOSITORY=''
OBSERVED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --observed-digest) OBSERVED+=("$2"); shift 2 ;;
    *) echo "oci-exact-publish: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$ARCHIVE" && -n "$VERSION" ]] \
  || { echo "oci-exact-publish: --archive and --version are required" >&2; exit 2; }

index_digest() {
  python3 - "$ARCHIVE" <<'PY'
import hashlib, json, sys, tarfile

archive = sys.argv[1]
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
    blob(config_digest)
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
    identities="$(index_digest)"
    printf '%s\n' "$identities"
    printf 'STAGED INDEX: %s\n' \
      "$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["index"])' <<<"$identities")"
    ;;
  verify-published)
    [[ -n "$REPOSITORY" ]] \
      || { echo "verify-published requires --repository" >&2; exit 2; }
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
    echo "oci-exact-publish: mode must be inspect-staged | verify-published" >&2
    exit 2
    ;;
esac
