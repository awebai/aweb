#!/usr/bin/env bash
# Self-test for scripts/oci-exact-publish.sh, no network.
#   green: a coherent two-platform OCI archive inspects, binds identities,
#          and verifies when both tags resolve to the staged index
#   reds:  missing layer blob, tampered index blob, single platform,
#          version tag resolving elsewhere, latest resolving elsewhere

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="$ROOT/scripts/oci-exact-publish.sh"
PASS=0
fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_archive() {
  # $1 out.tar; flags: --drop-layer --tamper-index --single-platform
  python3 - "$@" <<'PY'
import hashlib, io, json, sys, tarfile

out = sys.argv[1]
flags = set(sys.argv[2:])

blobs = {}
def add(data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    blobs[digest] = data
    return digest

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"

entries = []
platforms = [("amd64",), ("arm64",)]
if "--single-platform" in flags:
    platforms = [("amd64",)]
for (arch,) in platforms:
    config = add(json.dumps({"architecture": arch, "os": "linux"}).encode())
    layer = add(f"layer-bytes-{arch}".encode())
    manifest = add(json.dumps({
        "schemaVersion": 2, "mediaType": MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": config, "size": len(blobs[config])},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer, "size": len(blobs[layer])}],
    }).encode())
    entries.append({"mediaType": MANIFEST, "digest": manifest,
                    "size": len(blobs[manifest]),
                    "platform": {"os": "linux", "architecture": arch}})

index_bytes = json.dumps({
    "schemaVersion": 2, "mediaType": INDEX, "manifests": entries,
}).encode()
index = add(index_bytes)

if "--drop-layer" in flags:
    layer_digests = [e for e in blobs if blobs[e].startswith(b"layer-bytes")]
    del blobs[layer_digests[0]]
if "--tamper-index" in flags:
    blobs[index] = index_bytes + b" "

top = json.dumps({
    "schemaVersion": 2,
    "manifests": [{"mediaType": INDEX, "digest": index,
                   "size": len(index_bytes)}],
}).encode()

with tarfile.open(out, "w") as t:
    def put(name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    put("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
    put("index.json", top)
    for digest, data in blobs.items():
        put("blobs/sha256/" + digest.split(":")[1], data)
print(index)
PY
}

INDEX_DIGEST="$(make_archive "$tmp/good.tar")"
out="$(bash "$LANE" inspect-staged --archive "$tmp/good.tar" --version 0.5.14)" \
  || fail "coherent archive refused: $out"
grep -q "STAGED INDEX: $INDEX_DIGEST" <<<"$out" \
  || fail "identity not bound: $out"
grep -q "linux/arm64" <<<"$out" || fail "platform identities not printed"
ok "coherent two-platform archive binds its complete identity"

bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=$INDEX_DIGEST" \
  --observed-digest "latest=$INDEX_DIGEST" >/dev/null \
  || fail "matching tag observations refused"
ok "version and latest resolving to the staged index verify"

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then fail "$label: accepted what it must refuse"; fi
  grep -qi "$needle" <<<"$out" || fail "$label: refusal does not name ($needle): $out"
  ok "$label refused, naming: $needle"
}

make_archive "$tmp/nolayer.tar" --drop-layer >/dev/null
expect_refusal "missing layer blob" "missing" \
  bash "$LANE" inspect-staged --archive "$tmp/nolayer.tar" --version 0.5.14

make_archive "$tmp/tampered.tar" --tamper-index >/dev/null
expect_refusal "tampered index blob" "hashes to" \
  bash "$LANE" inspect-staged --archive "$tmp/tampered.tar" --version 0.5.14

make_archive "$tmp/single.tar" --single-platform >/dev/null
expect_refusal "single platform" "linux/arm64" \
  bash "$LANE" inspect-staged --archive "$tmp/single.tar" --version 0.5.14

expect_refusal "version tag resolving elsewhere" "resolves to" \
  bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=sha256:$(printf '0%.0s' {1..64})" \
  --observed-digest "latest=$INDEX_DIGEST"

expect_refusal "latest resolving elsewhere" "latest" \
  bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=$INDEX_DIGEST" \
  --observed-digest "latest=sha256:$(printf '0%.0s' {1..64})"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
