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

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then fail "$label: accepted what it must refuse"; fi
  grep -qi "$needle" <<<"$out" || fail "$label: refusal does not name ($needle): $out"
  ok "$label refused, naming: $needle"
}


SRC_SHA="$(printf 'a%.0s' {1..40})"

make_archive() {
  # $1 out.tar; flags: --drop-layer --tamper-index --single-platform
  #                    --wrong-version-label --wrong-revision-label
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

version = "9.9.9" if "--wrong-version-label" in flags else "0.5.14"
revision = ("b" * 40) if "--wrong-revision-label" in flags else ("a" * 40)
labels = {
    "org.opencontainers.image.title": "awid",
    "org.opencontainers.image.version": version,
    "org.opencontainers.image.revision": revision,
}

entries = []
platforms = [("amd64",), ("arm64",)]
if "--single-platform" in flags:
    platforms = [("amd64",)]
for (arch,) in platforms:
    config = add(json.dumps({"architecture": arch, "os": "linux",
                             "config": {"Labels": labels}}).encode())
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
out="$(bash "$LANE" inspect-staged --archive "$tmp/good.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/identities.json")" \
  || fail "coherent archive refused: $out"
grep -q "STAGED INDEX: $INDEX_DIGEST" <<<"$out" \
  || fail "identity not bound: $out"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "linux/arm64" in d["platforms"]' \
  "$tmp/identities.json" || fail "identities file is not valid JSON with platforms"
grep -q "{" <<<"$out" && fail "machine JSON leaked onto stdout"
ok "coherent archive binds identities to the file, diagnostics to stdout"

bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" \
  --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=$INDEX_DIGEST" \
  --observed-digest "latest=$INDEX_DIGEST" >/dev/null \
  || fail "matching tag observations refused"
ok "version and latest resolving to the staged index verify"

make_archive "$tmp/wrongver.tar" --wrong-version-label >/dev/null
expect_refusal "wrong version label" "labels version" \
  bash "$LANE" inspect-staged --archive "$tmp/wrongver.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/x.json"

make_archive "$tmp/wrongrev.tar" --wrong-revision-label >/dev/null
expect_refusal "wrong revision label" "labels revision" \
  bash "$LANE" inspect-staged --archive "$tmp/wrongrev.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/x.json"

# decide-tag: observation failure is never permission to write
S="sha256:$(printf '1%.0s' {1..64})"; D="sha256:$(printf '2%.0s' {1..64})"
[[ "$(bash "$LANE" decide-tag --tag-kind version --staged "$S" \
  --listing-status ok --present no)" == "COPY" ]] || fail "missing version tag must COPY"
[[ "$(bash "$LANE" decide-tag --tag-kind version --staged "$S" \
  --listing-status ok --present yes --remote-digest "$S")" == "ADOPT" ]] \
  || fail "exact version tag must ADOPT"
[[ "$(bash "$LANE" decide-tag --tag-kind latest --staged "$S" \
  --listing-status ok --present yes --remote-digest "$D")" == "COPY" ]] \
  || fail "different latest must transition (COPY)"
ok "decide-tag adopts exact, copies missing, transitions latest"
expect_refusal "version tag mismatch never rewrites" "never rewritten" \
  bash "$LANE" decide-tag --tag-kind version --staged "$S" \
  --listing-status ok --present yes --remote-digest "$D"
expect_refusal "unavailable listing never writes" "never permission" \
  bash "$LANE" decide-tag --tag-kind version --staged "$S" \
  --listing-status failed --present no
expect_refusal "unavailable remote digest never writes" "refusing to write blind" \
  bash "$LANE" decide-tag --tag-kind latest --staged "$S" \
  --listing-status ok --present yes --remote-digest unavailable

make_archive "$tmp/nolayer.tar" --drop-layer >/dev/null
expect_refusal "missing layer blob" "missing" \
  bash "$LANE" inspect-staged --archive "$tmp/nolayer.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/x.json"

make_archive "$tmp/tampered.tar" --tamper-index >/dev/null
expect_refusal "tampered index blob" "hashes to" \
  bash "$LANE" inspect-staged --archive "$tmp/tampered.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/x.json"

make_archive "$tmp/single.tar" --single-platform >/dev/null
expect_refusal "single platform" "linux/arm64" \
  bash "$LANE" inspect-staged --archive "$tmp/single.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --out "$tmp/x.json"

expect_refusal "version tag resolving elsewhere" "resolves to" \
  bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=sha256:$(printf '0%.0s' {1..64})" \
  --observed-digest "latest=$INDEX_DIGEST"

expect_refusal "latest resolving elsewhere" "latest" \
  bash "$LANE" verify-published --archive "$tmp/good.tar" --version 0.5.14 \
  --source-sha "$SRC_SHA" --repository ghcr.io/awebai/awid \
  --observed-digest "0.5.14=$INDEX_DIGEST" \
  --observed-digest "latest=sha256:$(printf '0%.0s' {1..64})"

# ── stage-only absence proof ────────────────────────────────────────
[[ "$(bash "$LANE" require-absent --listing-status ok --present no)" == ABSENT* ]] \
  || fail "proven absence must continue"
ok "proven absence continues staging"
expect_refusal "outage is never proof of absence" "never proof" \
  bash "$LANE" require-absent --listing-status failed --present no
expect_refusal "listed candidate version refuses staging" "already exists" \
  bash "$LANE" require-absent --listing-status ok --present yes

# ── observation hashes the exact byte stream ────────────────────────
# A raw manifest WITHOUT a trailing newline: variable capture strips and a
# here-string re-appends, so only a direct pipe hashes the true bytes.
expected="sha256:$(printf '{"raw":"manifest"}' | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
observed="$(printf '{"raw":"manifest"}' | bash "$LANE" observe-digest)"
[[ "$observed" == "$expected" ]] \
  || fail "observe-digest altered the byte stream: $observed != $expected"
corrupted="$(raw="$(printf '{"raw":"manifest"}')"; sha256sum <<<"$raw" | awk '{print "sha256:"$1}')"
[[ "$corrupted" != "$expected" ]] \
  || fail "the regression control failed: here-string hashing did not corrupt"
ok "observe-digest hashes exact bytes; the here-string form provably corrupts"

# ── listing evidence must be schema-valid before it counts ──────────
[[ "$(printf '{"Tags":["0.5.14","latest"]}' | bash "$LANE" classify-listing --tag 0.5.14)" == "yes" ]] \
  || fail "listed tag must classify yes"
[[ "$(printf '{"Tags":["latest"]}' | bash "$LANE" classify-listing --tag 0.5.14)" == "no" ]] \
  || fail "unlisted tag must classify no"
ok "schema-valid listings classify presence correctly"
for doc in '{}' '{"Tags":null}' '{"Tags":"not-an-array"}' 'not json at all'; do
  if out="$(printf '%s' "$doc" | bash "$LANE" classify-listing --tag 0.5.14 2>&1)"; then
    fail "malformed listing accepted as observation: $doc -> $out"
  fi
  grep -q "never an observation" <<<"$out" \
    || fail "malformed-listing refusal does not say so: $out"
done
ok "malformed, null, and non-array listings refuse (4 shapes) - never absence"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
