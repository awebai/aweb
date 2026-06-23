#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM_NAME="${AW_LAUNCH_TEAM:-launch-demo}"
TEAM_ALIAS="${AW_LAUNCH_ALIAS:-owner}"
PACK_REF="${AW_LAUNCH_PACK:-aweb.engineering-pack}"
RUNTIME="${AW_LAUNCH_RUNTIME:-local-shell}"
LIBRARY_MANIFEST_URL="${AW_LAUNCH_LIBRARY_MANIFEST_URL:-https://library.aweb.ai/.well-known/aweb-app.json}"

usage() {
  cat <<'EOF'
Usage: AWEB_API_KEY=... scripts/launch-demo-path.sh
       AW_LAUNCH_SELF_HOSTED=1 AWEB_URL=http://127.0.0.1:18000 AWID_REGISTRY_URL=http://127.0.0.1:18010 scripts/launch-demo-path.sh

Runs the launch demo path from a clean temporary HOME/workspace:
  1. install/update the Library plugin
  2. aw team create
  3. aw team add coordinator/developer/reviewer from the live engineering pack
  4. aw agent start/status/logs for each agent

Environment:
  AW_BIN                         Existing aw binary to use (default: build a temp binary from cli/go)
  AWEB_API_KEY                   Team API key for clean-env hosted bootstrap
  AWEB_URL                       Aweb service URL (default: aw's built-in default)
  AWID_REGISTRY_URL              Optional AWID registry override for an e2e stack
  AW_LAUNCH_SELF_HOSTED          Set to 1 to use the disposable self-hosted e2e stack without AWEB_API_KEY
  AW_LAUNCH_WORK_ROOT            Optional parent for a script-owned work root (default: mktemp)
  AW_LAUNCH_KEEP                 Set to 1 to keep the temp HOME/workspace and leave agents running
  AW_LAUNCH_TEAM                 Team name label passed to aw team create (default: launch-demo)
  AW_LAUNCH_ALIAS                Initial workspace alias (default: owner)
  AW_LAUNCH_PACK                 Library pack ref (default: aweb.engineering-pack)
  AW_LAUNCH_RUNTIME              Runtime used for materialize/start (default: local-shell)
  AW_LAUNCH_LIBRARY_MANIFEST_URL Library manifest URL (default: live Library manifest)
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ -z "${AWEB_API_KEY:-}" && "${AW_LAUNCH_SELF_HOSTED:-}" != "1" ]]; then
  echo "error: AWEB_API_KEY is required for the clean-env hosted demo path" >&2
  echo "Use a disposable/e2e team API key, or set AW_LAUNCH_SELF_HOSTED=1 for the disposable self-hosted e2e stack." >&2
  exit 2
fi
if [[ "${AW_LAUNCH_SELF_HOSTED:-}" == "1" && ( -z "${AWEB_URL:-}" || -z "${AWID_REGISTRY_URL:-}" ) ]]; then
  echo "error: AW_LAUNCH_SELF_HOSTED=1 requires AWEB_URL and AWID_REGISTRY_URL" >&2
  exit 2
fi
if [[ "${AW_LAUNCH_SELF_HOSTED:-}" == "1" ]]; then
  # The self-hosted e2e path must be isolated from any hosted/shared key the
  # operator happens to have exported in their shell.
  unset AWEB_API_KEY
fi

WORK_PARENT="${AW_LAUNCH_WORK_ROOT:-}"
if [[ -z "$WORK_PARENT" ]]; then
  WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aw-launch-demo.XXXXXX")"
else
  mkdir -p "$WORK_PARENT"
  WORK_ROOT="$(mktemp -d "$WORK_PARENT/aw-launch-demo.XXXXXX")"
fi
WORK_ROOT_MARKER="$WORK_ROOT/.aw-launch-demo-owned"
printf 'script-owned launch demo work root\n' >"$WORK_ROOT_MARKER"
DEMO_HOME="$WORK_ROOT/home"
WORKSPACE="$WORK_ROOT/workspace"
mkdir -p "$DEMO_HOME" "$WORKSPACE"

TMP_BIN=""
AW="${AW_BIN:-}"
if [[ -z "$AW" ]]; then
  TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/aw-launch-demo-bin.XXXXXX")"
  (cd "$ROOT/cli/go" && go build -o "$TMP_BIN" ./cmd/aw)
  AW="$TMP_BIN"
fi

export HOME="$DEMO_HOME"
if [[ -n "${AWEB_API_KEY:-}" ]]; then
  export AWEB_API_KEY
fi
if [[ -n "${AWEB_URL:-}" ]]; then
  export AWEB_URL
fi
if [[ -n "${AWID_REGISTRY_URL:-}" ]]; then
  export AWID_REGISTRY_URL
fi

cleanup() {
  set +e
  if [[ "${AW_LAUNCH_KEEP:-}" != "1" ]]; then
    for agent in coordinator developer reviewer; do
      (cd "$WORKSPACE" && "$AW" agent stop "$agent" >/dev/null 2>&1) || true
    done
    if [[ -n "$WORK_ROOT" && -f "$WORK_ROOT_MARKER" && "$(basename "$WORK_ROOT")" == aw-launch-demo.* ]]; then
      rm -rf "$WORK_ROOT"
    else
      echo "refusing to delete unverified launch demo work root: $WORK_ROOT" >&2
    fi
    [[ -n "$TMP_BIN" ]] && rm -f "$TMP_BIN"
  else
    echo "kept launch demo workspace: $WORKSPACE" >&2
    echo "kept launch demo HOME: $DEMO_HOME" >&2
    [[ -n "$TMP_BIN" ]] && echo "kept temp aw binary: $TMP_BIN" >&2
  fi
}
trap cleanup EXIT

run_aw() {
  echo "+ aw $*" >&2
  (cd "$WORKSPACE" && "$AW" "$@")
}

assert_status_running() {
  local agent="$1"
  local status_json="$2"
  python3 - "$agent" "$status_json" <<'PY'
import json
import sys
agent = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
if data.get("status") != "running":
    raise SystemExit(f"{agent} status={data.get('status')!r}, want 'running': {data}")
if not data.get("pid"):
    raise SystemExit(f"{agent} missing pid: {data}")
PY
}

echo "launch demo work root: $WORK_ROOT" >&2
echo "workspace: $WORKSPACE" >&2
echo "HOME: $DEMO_HOME" >&2

run_aw plugin install "$LIBRARY_MANIFEST_URL"
run_aw team create "$TEAM_NAME" --alias "$TEAM_ALIAS" --json

for agent in coordinator developer reviewer; do
  run_aw team add "${agent}@${PACK_REF}/${agent}" --runtime "$RUNTIME" --json
  test -f "$WORKSPACE/agents/instances/$agent/AGENTS.md"
  test -f "$WORKSPACE/agents/instances/$agent/.aw/profile/ref.json"
done

for agent in coordinator developer reviewer; do
  run_aw agent start "$agent" --runtime "$RUNTIME" --json
  status_file="$WORK_ROOT/${agent}-status.json"
  run_aw agent status "$agent" --json >"$status_file"
  assert_status_running "$agent" "$status_file"
  run_aw agent logs "$agent" >/dev/null
done

cat <<EOF
launch demo path passed
work_root=$WORK_ROOT
workspace=$WORKSPACE
home=$DEMO_HOME
team=$TEAM_NAME
pack=$PACK_REF
runtime=$RUNTIME
agents=coordinator,developer,reviewer
EOF
