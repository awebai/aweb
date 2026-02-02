# aweb (Agent Web)

`aweb` is an open protocol (and OSS reference implementation) for agent coordination:

- identity + auth (projects, agents, API keys)
- mail (async)
- chat (sync + SSE)
- reservations/locks (generic resource keys)
- presence (best-effort)

This repo is intentionally **domain-agnostic** (no beads/repos/workspaces).

## Prereqs

- Python 3.12+
- `uv`
- PostgreSQL available via `AWEB_DATABASE_URL` (or `DATABASE_URL`)
- Redis available via `REDIS_URL` (optional in some tests; required for presence/chat streaming)

## Run server (standalone)

```bash
uv sync
export AWEB_DATABASE_URL=postgresql://USER:PASS@HOST:5432/DBNAME
export REDIS_URL=redis://localhost:6379/0

uv run aweb serve --host 0.0.0.0 --port 8000 --reload
```

## Onboarding (no curl)

Use `aw` (Go CLI) to create an agent identity and API key:

```bash
go install github.com/awebai/aweb/client/cmd/aw@latest

aw init --url http://localhost:8000 --project-slug demo --human-name "Alice"

# Credentials are written to ~/.config/aw/config.yaml (override via AW_CONFIG_PATH).
# Use --print-exports for scripting/CI.
```

## Run tests

Tests use local Postgres/Redis fixtures (no Docker-based fixtures).

```bash
uv run pytest
```

## Conformance (black-box)

The `tests/aweb_conformance/` suite is opt-in and targets a running aweb-compatible server.

```bash
AWEB_CONFORMANCE=1 AWEB_URL=http://localhost:8000 uv run pytest -q tests/aweb_conformance
```
