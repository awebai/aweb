#!/usr/bin/env bash
set -euo pipefail

# Runs the black-box aweb conformance suite against a local aweb instance.
#
# Prereqs:
# - Set DATABASE_URL or AWEB_DATABASE_URL to a local Postgres database.
# - Have `uv` installed.
#
# Optional:
# - Set AWEB_SEED_OTHER_PROJECT_SLUG to seed a second project for cross-project scoping tests.

HOST="${AWEB_HOST:-127.0.0.1}"
PORT="${AWEB_PORT:-8000}"
AWEB_URL="${AWEB_URL:-http://${HOST}:${PORT}}"

if [[ -z "${AWEB_DATABASE_URL:-${DATABASE_URL:-}}" ]]; then
  echo "Missing DATABASE_URL/AWEB_DATABASE_URL. Example:" >&2
  echo "  export AWEB_DATABASE_URL=postgresql://user:pass@localhost:5432/aweb" >&2
  exit 1
fi

PROJECT_SLUG="${AWEB_SEED_PROJECT_SLUG:-conformance}"
AGENT_1_ALIAS="${AWEB_SEED_AGENT_1_ALIAS:-agent-1}"
AGENT_2_ALIAS="${AWEB_SEED_AGENT_2_ALIAS:-agent-2}"
OTHER_PROJECT_SLUG="${AWEB_SEED_OTHER_PROJECT_SLUG:-}"
OTHER_AGENT_ALIAS="${AWEB_SEED_OTHER_AGENT_ALIAS:-other-agent}"

seed_args=(
  uv run aweb seed
  --project-slug "$PROJECT_SLUG"
  --agent-1-alias "$AGENT_1_ALIAS"
  --agent-2-alias "$AGENT_2_ALIAS"
  --aweb-url "$AWEB_URL"
)
if [[ -n "$OTHER_PROJECT_SLUG" ]]; then
  seed_args+=(--other-project-slug "$OTHER_PROJECT_SLUG" --other-agent-alias "$OTHER_AGENT_ALIAS")
fi

eval "$("${seed_args[@]}" | grep '^export ' || true)"

uv run aweb serve --host "$HOST" --port "$PORT" >/tmp/aweb-conformance.log 2>&1 &
server_pid="$!"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 80); do
  if curl -fsS "${AWEB_URL}/docs" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

AWEB_CONFORMANCE=1 uv run pytest -q tests/aweb_conformance
