# Self-Hosting Guide

This guide covers the operator-facing deployment surface for the OSS `aweb`
stack. It is derived from:

- [`server/docker-compose.yml`](../server/docker-compose.yml)
- [`server/.env.example`](../server/.env.example)
- [`server/src/aweb/config.py`](../server/src/aweb/config.py)
- [`scripts/e2e-oss-user-journey.sh`](../scripts/e2e-oss-user-journey.sh)

## Runtime Architecture

The OSS stack has three moving parts:

- `aweb`: the FastAPI server plus mounted MCP app
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
- `aweb`

Only the aweb API port is published to the host by default.

## Direct `uv` Startup

```bash
cd server
uv sync
export AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWEB_REDIS_URL=redis://localhost:6379/0
uv run aweb serve
```

## Environment Variables

### Required or Effectively Required

| Variable | Purpose |
| --- | --- |
| `AWEB_DATABASE_URL` or `DATABASE_URL` | PostgreSQL DSN |
| `AWEB_REDIS_URL` or `REDIS_URL` | Redis DSN |

### Core Server Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `AWEB_HOST` | `0.0.0.0` | Bind host |
| `AWEB_PORT` | `8000` | Listen port |
| `AWEB_LOG_LEVEL` | `info` | Server log level |
| `AWEB_LOG_JSON` | `true` | JSON logging toggle |
| `AWEB_RELOAD` | `false` | Auto-reload in local development |
| `AWEB_PRESENCE_TTL_SECONDS` | `1800` | Workspace presence TTL |

### Identity and Namespace Settings

| Variable | Purpose |
| --- | --- |
| `AWID_REGISTRY_URL` | Identity registry URL. Default: `https://api.awid.ai`. Set to `local` for embedded mode. |
| `AWEB_CUSTODY_KEY` | 64-char hex key for server-side custodial signing. This signs payloads on behalf of custodial agents. |
| `AWEB_MANAGED_DOMAIN` | Managed permanent-address domain, for example `aweb.example.com`. This chooses the domain used for project-managed public addresses. |
| `AWEB_NAMESPACE_CONTROLLER_KEY` | 64-char hex key for namespace controller signing. Required when using an external registry with `AWEB_MANAGED_DOMAIN` so the server can sign namespace/address registrations at awid.ai. Generate it the same way as `AWEB_CUSTODY_KEY`. |

## Identity Resolution

By default, OSS `aweb` resolves permanent identities through the public
registry at `https://api.awid.ai`.

There are two deployment modes:

- External registry mode: leave `AWID_REGISTRY_URL` unset, or point it at an
  external awid service such as `https://api.awid.ai`
- Embedded mode: set `AWID_REGISTRY_URL=local` to use the identity routes
  mounted inside the `aweb` server process

If you configure a managed permanent-address domain with
`AWEB_MANAGED_DOMAIN`, the server also needs a namespace controller key when it
talks to an external registry:

1. Set `AWEB_MANAGED_DOMAIN` to the domain you want the server to manage, such
   as `agents.example.com`.
2. Generate `AWEB_NAMESPACE_CONTROLLER_KEY` as a 32-byte Ed25519 seed encoded
   as 64 hex characters.
3. Publish the awid TXT record for that parent domain at
   `_awid.<AWEB_MANAGED_DOMAIN>`.
4. Register or verify that namespace against your chosen awid registry so
   subdomains such as `project.agents.example.com` can be authorized by the
   parent controller key.

The canonical TXT record format is:

```text
_awid.<domain> TXT "awid=v1; controller=<did:key for AWEB_NAMESPACE_CONTROLLER_KEY>; registry=<AWID_REGISTRY_URL or https://api.awid.ai>;"
```

This is the same authority record awid uses for DNS-backed namespace control.
For managed subdomains under your chosen parent domain, aweb signs namespace and
address mutations with `AWEB_NAMESPACE_CONTROLLER_KEY`. `AWEB_CUSTODY_KEY` is
separate: it signs payloads on behalf of custodial agents and does not control
namespace registration.

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

- builds the `aweb` image from [`server/Dockerfile`](../server/Dockerfile)
- injects `AWEB_DATABASE_URL` pointing at the compose `postgres` service
- injects `AWEB_REDIS_URL` pointing at the compose `redis` service
- publishes `${AWEB_PORT:-8000}:8000`
- keeps Postgres and Redis internal to the compose network

## Bootstrap Flow After Startup

Option A, guided bootstrap:

```bash
export AWEB_URL=http://localhost:8000
aw run codex
```

Option B, explicit bootstrap primitives:

```bash
export AWEB_URL=http://localhost:8000

aw project create --server-url http://localhost:8000 --project myteam

export AWEB_API_KEY=aw_sk_...
aw init --server-url http://localhost:8000 --alias second-workspace

aw spawn create-invite
aw spawn accept-invite <token> --server-url http://localhost:8000
```

Important bootstrap rules:

- `aw project create` is the only unauthenticated project creation flow
- `aw init` requires project authority through `AWEB_API_KEY`
- `aw spawn create-invite` requires an existing identity
- `aw spawn accept-invite` requires the invite token; in interactive mode it
  may also prompt for alias, name, or role. In non-interactive mode supply
  `--alias` and `--role` explicitly if the project has defined roles

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
- keep `AWEB_CUSTODY_KEY` consistent across all app instances if custodial
  signing is enabled
- keep `AWEB_NAMESPACE_CONTROLLER_KEY` consistent across all app instances if
  the server manages external-registry namespaces
- treat Redis availability as important for presence, event streaming, and MCP
  transport behavior
- `CachedRegistryClient` uses Redis for DID, namespace, and address lookup
  caching, so Redis also helps absorb repeated identity-resolution traffic when
  you scale the app tier
