#!/usr/bin/env bash
# Run one release-driver CLI/server SkewCell through the existing real stack.
# AW_BIN and AWEB_E2E_SERVER_WHEEL are exact resolved artifacts; this wrapper
# assembles a runtime image around the wheel but never rebuilds either artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
E2E_SCRIPT="${CLI_SERVER_SKEW_E2E_SCRIPT:-$REPO_ROOT/cli/scripts/e2e.sh}"

: "${AW_BIN:?AW_BIN must name the exact resolved aw binary}"
: "${AWEB_E2E_SERVER_WHEEL:?AWEB_E2E_SERVER_WHEEL must name the exact resolved server wheel}"
: "${AW_SKEW_DIRECTION:?AW_SKEW_DIRECTION must name the requested SkewCell direction}"
[[ -x "$AW_BIN" ]] || { echo "FATAL: AW_BIN is not executable: $AW_BIN" >&2; exit 1; }
[[ -f "$AWEB_E2E_SERVER_WHEEL" ]] || { echo "FATAL: server wheel is absent: $AWEB_E2E_SERVER_WHEEL" >&2; exit 1; }
[[ "$AWEB_E2E_SERVER_WHEEL" == *.whl ]] || { echo "FATAL: server artifact is not a wheel" >&2; exit 1; }
case "$AW_SKEW_DIRECTION" in
  a-to-b|b-to-a) ;;
  *) echo "FATAL: unsupported CLI/server direction: $AW_SKEW_DIRECTION" >&2; exit 1 ;;
esac

context="$(mktemp -d "${TMPDIR:-/tmp}/aweb-skew-server.XXXXXX")"
trap 'rm -rf "$context"' EXIT
cp "$REPO_ROOT/scripts/e2e/cli-server-wheel.Dockerfile" "$context/Dockerfile"
cp "$AWEB_E2E_SERVER_WHEEL" "$context/$(basename "$AWEB_E2E_SERVER_WHEEL")"

cat >"$context/compose.yml" <<'YAML'
services:
  aweb:
    build:
      context: ${AWEB_E2E_SERVER_WHEEL_CONTEXT:?}
      dockerfile: Dockerfile
YAML

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

export AWEB_E2E_SERVER_WHEEL_CONTEXT="$context"
export LIBRARY_E2E_COMPOSE_OVERLAY="$context/compose.yml"
export LIBRARY_E2E_PROJECT="${LIBRARY_E2E_PROJECT:-aweb-skew-cli-server-$$}"
export LIBRARY_E2E_AWID_PORT="${LIBRARY_E2E_AWID_PORT:-$(free_port)}"
export LIBRARY_E2E_AWEB_PORT="${LIBRARY_E2E_AWEB_PORT:-$(free_port)}"
export LIBRARY_E2E_LIBRARY_PORT="${LIBRARY_E2E_LIBRARY_PORT:-$(free_port)}"
export LIBRARY_E2E_POSTGRES_PORT="${LIBRARY_E2E_POSTGRES_PORT:-$(free_port)}"
# Discovery responses must advertise the same isolated host ports this cell
# reaches; the base compose defaults name the ordinary fixed-port journey.
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="${LIBRARY_E2E_AWEB_PUBLIC_ORIGIN:-http://127.0.0.1:$LIBRARY_E2E_AWEB_PORT}"
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="${LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL:-http://127.0.0.1:$LIBRARY_E2E_AWID_PORT}"
export AW_E2E_TEST_RUN='^TestRealStackWorkspacePresenceAndLocksUseDistinctIdentifiers$'

"$E2E_SCRIPT"
