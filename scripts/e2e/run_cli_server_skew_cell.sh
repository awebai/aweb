#!/usr/bin/env bash
# Run one release-driver CLI/server SkewCell through the existing real stack.
# AW_BIN and AWEB_E2E_SERVER_WHEEL are exact resolved artifacts; this wrapper
# assembles a runtime image around the wheel but never rebuilds either artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
E2E_SCRIPT="$REPO_ROOT/cli/scripts/e2e.sh"

allocate_ports() {
  python3 - <<'PY'
import socket
sockets = []
try:
    for _ in range(4):
        value = socket.socket()
        value.bind(("127.0.0.1", 0))
        sockets.append(value)
    print(" ".join(str(value.getsockname()[1]) for value in sockets))
finally:
    for value in sockets:
        value.close()
PY
}

validate_inputs() {
  : "${AW_BIN:?AW_BIN must name the exact resolved aw binary}"
  : "${AWEB_E2E_SERVER_WHEEL:?AWEB_E2E_SERVER_WHEEL must name the exact resolved server wheel}"
  : "${AW_SKEW_DIRECTION:?AW_SKEW_DIRECTION must name the requested SkewCell direction}"
  : "${AW_SKEW_CELL_IDENTITY_JSON:?full SkewCell identity JSON is required}"
  : "${AW_SKEW_CELL_IDENTITY_SHA256:?SkewCell identity SHA-256 is required}"
  : "${AWEB_SKEW_RUNTIME_PROOF_PATH:?runtime proof path is required}"
  : "${AWEB_SKEW_EXPECTED_SERVER_VERSION:?expected server version is required}"
  : "${AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256:?expected server wheel SHA-256 is required}"
  : "${AWEB_SKEW_EXPECTED_MCP_VERSION:?exact locked MCP version is required}"
  [[ -x "$AW_BIN" ]] || {
    echo "FATAL: AW_BIN is not executable: $AW_BIN" >&2
    return 1
  }
  [[ -f "$AWEB_E2E_SERVER_WHEEL" ]] || {
    echo "FATAL: server wheel is absent: $AWEB_E2E_SERVER_WHEEL" >&2
    return 1
  }
  [[ "$AWEB_E2E_SERVER_WHEEL" == *.whl ]] || {
    echo "FATAL: server artifact is not a wheel" >&2
    return 1
  }
  local identity_sha
  identity_sha="$(python3 - <<'PY'
import hashlib
import json
import os
value = json.loads(os.environ["AW_SKEW_CELL_IDENTITY_JSON"])
assert value.get("direction") == os.environ["AW_SKEW_DIRECTION"], value
assert value.get("journey") == "make cli-e2e", value
body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(body).hexdigest())
PY
)"
  [[ "$identity_sha" == "$AW_SKEW_CELL_IDENTITY_SHA256" ]] || {
    echo "FATAL: SkewCell identity JSON does not match its SHA-256" >&2
    return 1
  }
  [[ "$AW_SKEW_CELL_IDENTITY_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "FATAL: SkewCell identity SHA-256 is malformed" >&2
    return 1
  }
  case "$AW_SKEW_DIRECTION" in
    a-to-b|b-to-a) ;;
    *)
      echo "FATAL: unsupported CLI/server direction: $AW_SKEW_DIRECTION" >&2
      return 1
      ;;
  esac
}

prepare_context() {
  local ports token
  context="$(mktemp -d "${TMPDIR:-/tmp}/aweb-skew-server.XXXXXX")"
  cp "$REPO_ROOT/scripts/e2e/cli-server-wheel.Dockerfile" "$context/Dockerfile"
  cp "$AWEB_E2E_SERVER_WHEEL" "$context/$(basename "$AWEB_E2E_SERVER_WHEEL")"

  cat >"$context/compose.yml" <<'YAML'
services:
  aweb:
    build:
      context: ${AWEB_E2E_SERVER_WHEEL_CONTEXT:?}
      dockerfile: Dockerfile
      args:
        MCP_VERSION: ${AWEB_SKEW_EXPECTED_MCP_VERSION:?}
YAML

  # A skew cell owns every stack selector. Ambient ordinary-journey values may
  # neither preserve nor redirect this exact-artifact invocation.
  unset KEEP_UP LIBRARY_E2E_PROJECT LIBRARY_E2E_AWID_PORT \
    LIBRARY_E2E_AWEB_PORT LIBRARY_E2E_LIBRARY_PORT \
    LIBRARY_E2E_POSTGRES_PORT LIBRARY_E2E_AWEB_PUBLIC_ORIGIN \
    LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN \
    LIBRARY_E2E_COMPOSE_OVERLAY
  ports="$(allocate_ports)"
  read -r LIBRARY_E2E_AWID_PORT LIBRARY_E2E_AWEB_PORT \
    LIBRARY_E2E_LIBRARY_PORT LIBRARY_E2E_POSTGRES_PORT <<<"$ports"
  token="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"

  export AWEB_E2E_SERVER_WHEEL_CONTEXT="$context"
  export LIBRARY_E2E_COMPOSE_OVERLAY="$context/compose.yml"
  export LIBRARY_E2E_PROJECT="aweb-skew-${AW_SKEW_CELL_IDENTITY_SHA256:0:20}-$token"
  export LIBRARY_E2E_AWID_PORT LIBRARY_E2E_AWEB_PORT \
    LIBRARY_E2E_LIBRARY_PORT LIBRARY_E2E_POSTGRES_PORT
  # Discovery responses advertise only this invocation's allocated loopback ports.
  export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="http://127.0.0.1:$LIBRARY_E2E_AWEB_PORT"
  export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="http://127.0.0.1:$LIBRARY_E2E_AWID_PORT"
  export LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN="http://127.0.0.1:$LIBRARY_E2E_LIBRARY_PORT"
  export AW_E2E_TEST_RUN='^TestRealStackWorkspacePresenceAndLocksUseDistinctIdentifiers$'
}

cleanup_context() {
  local original_status="$1" cleanup_status=0
  if [[ -n "${context:-}" ]]; then
    rm -rf -- "$context" || cleanup_status=$?
    if [[ -e "$context" ]]; then
      echo "FATAL: skew temporary context remains after cleanup: $context" >&2
      cleanup_status=1
    fi
  fi
  if (( original_status != 0 )); then
    return "$original_status"
  fi
  return "$cleanup_status"
}

main() {
  validate_inputs
  context=""
  trap 'status=$?; trap - EXIT; cleanup_context "$status"; exit $?' EXIT
  prepare_context
  "$E2E_SCRIPT"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
