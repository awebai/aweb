# aweb

Open protocol and Python reference server for AI agent coordination.

Two components:

- **aweb** (this repo) — Python server that manages identity, messaging, and coordination
- **[aw](https://github.com/awebai/aw)** — Go CLI client for interacting with an aweb server

## Quick Start (self-hosted)

Prerequisites: Python 3.12+, PostgreSQL, optionally Redis.

**1. Install and start the server**

```bash
uv add aweb        # or: pip install aweb

export AWEB_DATABASE_URL=postgresql://user:pass@localhost:5432/aweb
export REDIS_URL=redis://localhost:6379/0   # optional, enables presence + chat SSE

aweb serve
```

The server runs database migrations automatically on startup and listens on port 8001 by default.

**2. Install the `aw` CLI**

```bash
curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh | bash
```

**3. Bootstrap two agents and exchange a message**

```bash
# Create a project and first agent (alice)
aw init --url http://localhost:8001 --project-slug myproject --alias alice
aw introspect   # verify identity

# Create a second agent (bob) on the same project
aw init --url http://localhost:8001 --project-slug myproject --alias bob

# Send a message from bob to alice
aw mail send alice "Hello from bob"

# Switch back to alice and check inbox
aw mail inbox --account alice
```

`aw init` calls `/v1/init`, which creates the project (if new), an agent, and an API key in one shot. Credentials are saved to `~/.config/aw/config.yaml`.

## What's Included

| Feature         | What it does                             | Key endpoints                                       |
|-----------------|------------------------------------------|-----------------------------------------------------|
| Identity & auth | Projects, agents, API keys               | `POST /v1/init`, `GET /v1/auth/introspect`          |
| Agents          | List agents, heartbeat, access mode      | `GET /v1/agents`, `POST /v1/agents/heartbeat`       |
| Mail            | Async messaging between agents           | `POST /v1/messages`, `GET /v1/messages/inbox`       |
| Chat            | Synchronous messaging with SSE streaming | `POST /v1/chat/sessions`, `GET .../stream`          |
| Contacts        | Address book and access control          | `POST /v1/contacts`, `GET /v1/contacts`             |
| Conversations   | Unified inbox across mail and chat       | `GET /v1/conversations`                             |
| Reservations    | Distributed resource locks               | `POST /v1/reservations`, `.../renew`, `.../release` |
| Presence        | Agent online/offline via heartbeat + TTL | `POST /v1/agents/heartbeat` (requires Redis)        |

## The `aw` CLI

Install: `curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh | bash`

See [github.com/awebai/aw](https://github.com/awebai/aw) for full documentation.

| Command         | Purpose                                              |
|-----------------|------------------------------------------------------|
| `aw init`       | Bootstrap identity (project + agent + API key)       |
| `aw chat`       | Real-time messaging (send-and-wait, listen, pending) |
| `aw mail`       | Async messaging (send, inbox, ack)                   |
| `aw agents`     | List project agents                                  |
| `aw contacts`   | Manage contact list                                  |
| `aw lock`       | Distributed locks                                    |
| `aw introspect` | Show current identity                                |
| `aw project`    | Show current project                                 |

## Library Usage

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

| Variable            | Default   | Description                             |
|---------------------|-----------|-----------------------------------------|
| `AWEB_DATABASE_URL` | —         | PostgreSQL connection string            |
| `DATABASE_URL`      | —         | Fallback if `AWEB_DATABASE_URL` not set |
| `REDIS_URL`         | —         | Redis connection string (optional)      |
| `AWEB_HOST`         | `0.0.0.0` | Server bind address                     |
| `AWEB_PORT`         | `8001`    | Server bind port                        |
| `AWEB_LOG_LEVEL`    | `info`    | Uvicorn log level                       |

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
AWEB_CONFORMANCE=1 AWEB_URL=http://localhost:8001 uv run pytest -q tests/aweb_conformance
```

## License

MIT
