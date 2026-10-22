#!/usr/bin/env bash
# Real AWID + aweb + Folio + aw + channel-core acceptance. No mocks.
# Requires Docker/buildx/Compose, Go, Node/npm and Python 3. Fixed disposable
# project abrm-folio and ports 38000/38010/38765/57432 must be unused.
# Folio binds TLS on this host's non-loopback address for the guarded origin fetch.
# AW_BIN may name the exact candidate binary; otherwise build from this tree.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EVIDENCE="${FOLIO_WAKE_EVIDENCE:-$(mktemp -d /tmp/folio-wakes-evidence.XXXXXX)}"
mkdir -p "$EVIDENCE"
COMPOSE=(docker compose -p abrm-folio --project-directory "$ROOT" -f "$ROOT/scripts/e2e/folio-wakes.compose.yml")
BUILDER="folio-wakes-$$"
WORK="$(mktemp -d /tmp/folio-wakes-bin.XXXXXX)"
export GOMAXPROCS=2
export GOFLAGS="${GOFLAGS:-} -p=2"
export FOLIO_WAKES_ADDRESS="${FOLIO_WAKES_ADDRESS:-$(python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("192.0.2.1",9)); print(s.getsockname()[0]); s.close()')}"
export FOLIO_WAKES_ORIGIN="https://$FOLIO_WAKES_ADDRESS:38765"
export NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,localhost,$FOLIO_WAKES_ADDRESS"
export FOLIO_WAKES_TLS="$WORK/tls"
export FOLIO_WAKES_APP_KEY_FILES='{}'
mkdir -p "$FOLIO_WAKES_TLS"
chmod 755 "$WORK" "$FOLIO_WAKES_TLS"
# The Folio deployment's manifest, mounted by the compose file (written below).
export FOLIO_WAKES_MANIFEST="$WORK/aweb-app.json"
: >"$FOLIO_WAKES_MANIFEST"
cleanup() {
  status=$?
  "${COMPOSE[@]}" unpause aweb >/dev/null 2>&1 || true
  "${COMPOSE[@]}" logs --no-color >"$EVIDENCE/services.log" 2>&1 || true
  "${COMPOSE[@]}" down -v --rmi local --remove-orphans || status=1
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  echo "Evidence: $EVIDENCE"
  exit "$status"
}
# Refuse someone else's active gate instead of resetting its state.
if [[ -n "$(docker ps -aq --filter label=com.docker.compose.project=abrm-folio)" ]]; then
  echo 'abrm-folio project already exists; finish its owner-run gate first' >&2
  exit 1
fi
trap cleanup EXIT
# Limit the build as well as every service in the compose file.
docker buildx create --name "$BUILDER" --driver docker-container \
  --driver-opt memory=2g,cpu-period=100000,cpu-quota=200000 >/dev/null
"${COMPOSE[@]}" build --builder "$BUILDER" >"$EVIDENCE/build.log" 2>&1
# The same maintained throwaway CA as the real HTTP/TLS installation tests.
docker run --rm --user 0 --entrypoint /app/.venv/bin/python \
  -v "$FOLIO_WAKES_TLS:/tls" -v "$ROOT/naapp-lib/testing/src:/test-support:ro" \
  -e PYTHONPATH=/test-support -e FOLIO_WAKES_ADDRESS \
  abrm-folio-aweb -c 'import os; from pathlib import Path; from aweb_naapp_testing.network import make_certificates; make_certificates(Path("/tls"), [], [os.environ["FOLIO_WAKES_ADDRESS"]])'
export SSL_CERT_FILE="$FOLIO_WAKES_TLS/ca.pem"
# Go's compatibility default on macOS otherwise ignores SSL_CERT_FILE.
export GODEBUG="${GODEBUG:+$GODEBUG,}x509sslcertoverrideplatform=1"
# Public deterministic test material, in the runtime's normal key-file format.
python3 - "$FOLIO_WAKES_TLS" <<'PY'
import sys
from pathlib import Path
for name, byte in (("emit-other", "02"), ("grant-read", "03")):
    path = Path(sys.argv[1]) / (name + ".key")
    path.write_text(byte * 32 + "\n")
    path.chmod(0o644)
PY
# Folio checks its emit key against its manifest at startup, so the deployment's
# manifest exists before Folio starts.
docker run --rm --entrypoint /app/.venv/bin/python -v "$ROOT/scripts/e2e:/e2e:ro" \
  -e FOLIO_WAKES_ORIGIN \
  abrm-folio-folio /e2e/folio_wakes_manifest.py 0.1.0 true 1 >"$FOLIO_WAKES_MANIFEST"
export FOLIO_WAKES_APP_KEY_FILES="$(python3 - "$FOLIO_WAKES_MANIFEST" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1]))
kids = {key["kid"] for key in manifest.get("app_keys", [])}
print(json.dumps({"folio:grant-read-1": "/tls/grant-read.key"} if "folio:grant-read-1" in kids else {}))
PY
)"
"${COMPOSE[@]}" up --no-build -d --wait
if [[ -z "${AW_BIN:-}" ]]; then
  (cd "$ROOT/cli/go" && go build -o "$WORK/aw" ./cmd/aw)
  export AW_BIN="$WORK/aw"
fi
(cd "$ROOT/channel-core" && npm ci --ignore-scripts && npm run build) >"$EVIDENCE/channel-build.log" 2>&1
git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/source-sha.txt"
python3 "$ROOT/scripts/e2e/folio_wakes.py" 2>&1 | tee "$EVIDENCE/acceptance.log"
