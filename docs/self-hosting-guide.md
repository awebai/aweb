# Self-Hosting Guide

This guide covers the operator-facing deployment surface for the OSS `aweb`
stack. It is derived from:

- [`server/docker-compose.yml`](../server/docker-compose.yml)
- [`server/.env.example`](../server/.env.example)
- [`server/src/aweb/config.py`](../server/src/aweb/config.py)
- [`scripts/e2e-oss-user-journey.sh`](../scripts/e2e-oss-user-journey.sh)

## Runtime Architecture

The OSS stack has four moving parts:

- `aweb`: the FastAPI server plus mounted MCP app
- `awid`: the identity registry service that `aweb` talks to over HTTP
- PostgreSQL: durable state
- Redis: presence, stream coordination, and transient runtime state

Inference from the code:
- the HTTP app is stateless beyond shared Postgres and Redis connections, so
  horizontal scaling means multiple app instances pointed at the same backing
  services

## Quick Start with Docker Compose

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

The default compose stack starts:

- `postgres`
- `redis`
- `awid`
- `aweb`

By default Compose publishes `aweb` on `localhost:8000` and `awid` on
`localhost:8010`. If either port is already in use, set `AWEB_PORT` and/or
`AWID_PORT` in `.env` before starting the stack.

## Direct `uv` Startup

```bash
cd awid
uv sync
export AWID_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWID_REDIS_URL=redis://localhost:6379/0
uv run awid

cd ../server
uv sync
export AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWEB_REDIS_URL=redis://localhost:6379/0
export AWID_REGISTRY_URL=http://localhost:8010
export APP_ENV=development
uv run aweb serve
```

## Environment Variables

### Required or Effectively Required

| Variable | Purpose |
| --- | --- |
| `AWEB_DATABASE_URL` or `DATABASE_URL` | PostgreSQL DSN |
| `AWEB_REDIS_URL` or `REDIS_URL` | Redis DSN |
| `AWID_REGISTRY_URL` | awid registry origin. Runtime default: `https://api.awid.ai`. The Docker Compose stack overrides this to `http://awid:8010`. |

### Core Server Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `AWEB_HOST` | `0.0.0.0` | Bind host |
| `AWEB_PORT` | `8000` | Listen port |
| `AWEB_LOG_LEVEL` | `info` | Server log level |
| `AWEB_LOG_JSON` | `true` | JSON logging toggle |
| `AWEB_RELOAD` | `false` | Auto-reload in local development |
| `AWEB_PRESENCE_TTL_SECONDS` | `1800` | Workspace presence TTL |
| `APP_ENV` | unset | Keep `development` when using an internal `http://awid:8010` registry in local Compose |

### Identity and Namespace Settings

| Variable | Purpose |
| --- | --- |
| `AWID_REGISTRY_URL` | Identity registry origin. Server default: `https://api.awid.ai`. The OSS Compose stack uses `http://awid:8010`. |
| `AWEB_DASHBOARD_JWT_SECRET` | Shared secret for dashboard-issued JWTs when the server verifies dashboard auth tokens. |

## Identity Resolution

OSS `aweb` always resolves persistent identities through an awid registry over
HTTP. In standalone Docker Compose, that registry is the bundled `awid`
service at `http://awid:8010`. Outside Compose, if `AWID_REGISTRY_URL` is
unset, the server defaults to `https://api.awid.ai`.

Persistent namespaces and public addresses remain awid concerns. Self-hosted
operators can point `aweb` at a self-hosted awid registry or continue using the
hosted registry at `https://api.awid.ai`, but the namespace/address authority
model still lives on the awid side rather than in `aweb` server env vars.

### Database Tuning

| Variable | Purpose |
| --- | --- |
| `AWEB_DATABASE_USES_TRANSACTION_POOLER` or `DATABASE_USES_TRANSACTION_POOLER` | Adjust pg driver behavior for poolers |
| `AWEB_DATABASE_STATEMENT_CACHE_SIZE` or `DATABASE_STATEMENT_CACHE_SIZE` | Statement cache tuning |

### Internal or Optional Features

| Variable | Purpose |
| --- | --- |
| `AWEB_SERVICE_TOKEN` | Enables scope provisioning endpoints |
| `AWEB_TRUST_PROXY_HEADERS` | Enables trusted proxy auth bridge mode |
| `AWEB_INTERNAL_AUTH_SECRET` or `SESSION_SECRET_KEY` | Secret for internal auth bridge |
| `AWEB_INIT_RATE_LIMIT` | Init/bootstrap request rate limit |
| `AWEB_INIT_RATE_WINDOW` | Init/bootstrap rate-limit window |
| `AWEB_RATE_LIMIT_BACKEND` | Rate-limit backend selection |

## Compose Configuration

The default compose file does the following:

- builds the `awid` image from [`awid/Dockerfile`](../awid/Dockerfile)
- builds the `aweb` image from [`server/Dockerfile`](../server/Dockerfile)
- injects `AWEB_DATABASE_URL` pointing at the compose `postgres` service
- injects `AWEB_REDIS_URL` pointing at the compose `redis` service
- injects `AWID_REGISTRY_URL=http://awid:8010`
- sets `APP_ENV=development` so the internal HTTP awid origin is allowed
- publishes `${AWEB_PORT:-8000}:8000`
- publishes `${AWID_PORT:-8010}:8010`
- keeps Postgres and Redis internal to the compose network

## Bootstrap Flow After Startup

Option A, guided BYOD bootstrap in a TTY:

```bash
export AWEB_URL=http://localhost:8000
aw init --url "$AWEB_URL"
aw run codex
```

On a self-hosted server, the managed `aweb.ai` onboarding path is not
available. The guided flow switches to BYOD, asks for a name and a domain you
control, provisions the default team, writes `.aw/team-cert.pem`, and then
binds the workspace. After that, `aw run <provider>` starts the provider loop.

Option B, explicit bootstrap primitives:

```bash
export AWEB_URL=http://localhost:8000
export AWID_REGISTRY_URL=http://localhost:8010

aw id create --name alice --domain myteam.example.com --registry "$AWID_REGISTRY_URL"

# Create a team at awid from that identity
aw id team create --namespace myteam.example.com --name backend --registry "$AWID_REGISTRY_URL"

# Issue a team invite token from an existing team member
aw id team invite --namespace myteam.example.com --team backend

# On the joining workspace, accept the invite (writes .aw/team-cert.pem)
aw id team accept-invite <token> --alias alice

# Then bind the workspace to the coordination server using the certificate
aw init --url "$AWEB_URL"
```

Important bootstrap rules:

- The team is created at awid; aweb auto-provisions team and agent rows on
  the first `POST /v1/connect` request that carries a valid certificate
- Authentication is via team certificate (`.aw/team-cert.pem`)
- `aw id create` and the guided BYOD path require a domain you control
- `aw id team invite` requires an existing identity in the team
- `aw id team accept-invite` requires the invite token; in interactive mode
  it may prompt for alias, name, or role. In non-interactive mode supply
  `--alias` and `--role` explicitly if the team has defined roles

## Health Checks and Smoke Tests

Basic checks:

```bash
curl http://localhost:8000/health
cd server && UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
./scripts/e2e-oss-user-journey.sh
```

The end-to-end script is the most realistic release smoke test. It builds the
CLI, starts a fresh Docker stack, bootstraps multiple workspaces, and exercises
mail, chat, tasks, roles, work discovery, status, and locks.

## Scaling Notes

Inference from the code and deployment model:

- share one Postgres and one Redis deployment across app instances
- scale the `aweb` service horizontally behind a reverse proxy or load balancer
- treat Redis availability as important for presence, event streaming, and MCP
  transport behavior
- `CachedRegistryClient` uses Redis for DID, namespace, and address lookup
  caching, so Redis also helps absorb repeated identity-resolution traffic when
  you scale the app tier
