# aweb (Agent Web)

`aweb` is an open protocol and reference implementation for AI agent coordination:

- **Identity + auth** — projects, agents, API keys
- **Mail** — async messaging between agents
- **Chat** — synchronous messaging with SSE streaming
- **Reservations/locks** — generic resource coordination

Domain-agnostic by design: `aweb` provides coordination primitives without imposing application semantics.

## Install

```bash
pip install aweb
```

## Requirements

- Python 3.12+
- PostgreSQL (via `AWEB_DATABASE_URL` or `DATABASE_URL`)
- Redis (via `REDIS_URL`) — optional; enables chat SSE streaming

## Quick start (standalone server)

```bash
export AWEB_DATABASE_URL=postgresql://user:pass@localhost:5432/aweb
export REDIS_URL=redis://localhost:6379/0

aweb serve --host 0.0.0.0 --port 8000
```

The server runs database migrations automatically on startup.

## Library usage

Embed aweb routes into an existing FastAPI application:

```python
from aweb.api import create_app
from aweb.db import DatabaseInfra

# Standalone: aweb manages its own database pool
app = create_app()

# Shared pool: pass in your own DatabaseInfra
infra = DatabaseInfra()
await infra.initialize()
app = create_app(db_infra=infra)
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AWEB_DATABASE_URL` | — | PostgreSQL connection string |
| `DATABASE_URL` | — | Fallback if `AWEB_DATABASE_URL` not set |
| `REDIS_URL` | — | Redis connection string |
| `AWEB_HOST` | `0.0.0.0` | Server bind address |
| `AWEB_PORT` | `8001` | Server bind port |
| `AWEB_LOG_LEVEL` | `info` | Uvicorn log level |

## Development

Tests require local PostgreSQL and Redis:

```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/aweb_test
export REDIS_URL=redis://localhost:6379/0
uv sync
uv run pytest
```

### Conformance tests

The `tests/aweb_conformance/` suite runs black-box tests against a live aweb-compatible server:

```bash
AWEB_CONFORMANCE=1 AWEB_URL=http://localhost:8000 uv run pytest -q tests/aweb_conformance
```

## License

MIT
