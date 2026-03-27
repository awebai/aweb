# Self-hosting aweb

This package is intended to be genuinely usable on its own.

Minimum requirements:

- PostgreSQL
- Redis
- Python 3.12+ if running directly with `uv`

## Run with uv

```bash
cd server
uv sync
export AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWEB_REDIS_URL=redis://localhost:6379/0
uv run aweb serve
```

The server listens on `http://localhost:8000` by default and exposes:

- the HTTP API
- SSE/event routes
- the MCP endpoint at `/mcp/`

## Run with Docker Compose

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

This starts:

- `postgres`
- `redis`
- `aweb`

Only the aweb API port is published to the host by default. PostgreSQL and
Redis remain internal to the Compose network, which avoids conflicts with local
services already using `5432` or `6379`. If `8000` is already in use, change
`AWEB_PORT` in `.env`.

## Bootstrap and workspace authority

The current OSS bootstrap chain is:

1. `aw project create`
   - unauthenticated
   - creates the project, attached namespace, and first workspace
   - returns the API key that acts as project authority for additional workspaces
2. `aw init`
   - initializes another workspace in the existing project
   - requires `AWEB_API_KEY` set to the project-authority key returned by `aw project create`
3. `aw spawn create-invite`
   - requires an identity-bound key from an existing workspace
4. `aw spawn accept-invite`
   - requires only the invite token

Example:

```bash
export AWEB_URL=http://localhost:8000

aw run codex

aw project create --server-url http://localhost:8000 --project myteam

export AWEB_API_KEY=aw_sk_...
aw init --server-url http://localhost:8000 --alias second-workspace

# Uses the current workspace's saved server/account context.
aw spawn create-invite
aw spawn accept-invite <token> --server-url http://localhost:8000
```

Important: `aw init` intentionally reads project authority from `AWEB_API_KEY` in
the environment. It does not use the saved identity account automatically for
that path.

## Important environment variables

- `AWEB_DATABASE_URL`
- `AWEB_REDIS_URL`
- `AWEB_CUSTODY_KEY`
- `AWEB_MANAGED_DOMAIN`

`AWEB_CUSTODY_KEY` is optional, but without it custodial signing is disabled.

## Identity system

The stable identity system is part of OSS `aweb` under:

```text
src/aweb/awid/
```

That includes:

- `did:key` and `did:aw`
- signing and verification
- audit-log verification helpers
- continuity/replacement metadata helpers
