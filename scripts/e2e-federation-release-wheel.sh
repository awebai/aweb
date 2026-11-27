#!/usr/bin/env bash
# The federation journey with a release's built server wheel installed in both
# servers, in place of servers built from source. The journey records the
# sha256 of the wheel each container holds in AWEB_FED_E2E_WHEEL_EVIDENCE.
#   AWEB_CANDIDATE_RELEASE_FILES  the release command's built files
#   CANDIDATE_LOG_DIR             where the wheel evidence is written

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files="${AWEB_CANDIDATE_RELEASE_FILES:?AWEB_CANDIDATE_RELEASE_FILES is required}"
log_dir="${CANDIDATE_LOG_DIR:?CANDIDATE_LOG_DIR is required}"

wheel_inputs="$(python3 "$ROOT/scripts/release_files.py" server-wheel "$files")"
{ read -r wheel; read -r wheel_sha256; read -r version; } <<<"$wheel_inputs"
mcp_version="$(python3 - "$ROOT/server/uv.lock" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    [package] = [p for p in tomllib.load(handle)["package"] if p["name"] == "mcp"]
print(package["version"])
PY
)"

export AWEB_FED_E2E_SERVER_MODE=wheel
export AWEB_FED_E2E_MCP_VERSION="$mcp_version"
export AWEB_FED_E2E_WHEEL_EVIDENCE="$log_dir/release-wheels.json"
for side in ALPHA BETA; do
  export "AWEB_${side}_WHEEL=$wheel" "AWEB_${side}_WHEEL_SHA256=$wheel_sha256" "AWEB_${side}_VERSION=$version"
done
exec "$ROOT/scripts/e2e-oss-federation.sh"
