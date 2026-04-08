# aweb server

This directory contains the standalone OSS `aweb` Python package.

It is the self-hostable coordination server and protocol runtime. The package
includes:

- the FastAPI server (`aweb.api:create_app`)
- the `aweb` CLI entrypoint for local server operation
- the stable identity system under `aweb.awid`
- database migrations
- default coordination project roles bundles
- MCP integration

## Run locally

Recommended OSS path: start the bundled stack with Docker Compose. That stack
includes `aweb`, `awid`, Postgres, and Redis.

```bash
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

Only the aweb API port is published to the host by default. PostgreSQL, Redis,
and awid stay on the internal Compose network, so existing local database
services do not block the basic setup. If `8000` is already taken, change
`AWEB_PORT` in `.env`.

Direct `uv` mode remains available when you already have Postgres, Redis, and
an awid service:

```bash
cd ../awid
uv sync
uv run awid serve

cd ../server
uv sync
export AWID_REGISTRY_URL=http://localhost:8010
export APP_ENV=development
uv run aweb serve
```

By default, `aweb` reads:

- `AWEB_DATABASE_URL` or `DATABASE_URL`
- `AWEB_REDIS_URL` or `REDIS_URL`
- `AWID_REGISTRY_URL`
- `AWEB_HOST`
- `AWEB_PORT`
- `AWEB_CUSTODY_KEY` for custodial signing
- `AWEB_MANAGED_DOMAIN` for persistent managed-address bootstrap
- `AWEB_NAMESPACE_CONTROLLER_KEY` for managed namespace/address registration

## Bootstrap flow

The current `aw` client talks to this server without protocol changes.

Typical flow:

```bash
# Point aw at the self-hosted server first.
export AWEB_URL=http://localhost:8000

# Primary human path: guided onboarding plus provider startup.
aw run codex

# Create the project and first workspace.
aw project create --server-url http://localhost:8000 --project myteam

# Create a second workspace in the same project.
export AWEB_API_KEY=aw_sk_...
aw init --server-url http://localhost:8000 --alias second-workspace

# Delegate another workspace through an invite.
# Uses the current workspace's saved server/account context.
aw spawn create-invite
aw spawn accept-invite <token> --server-url http://localhost:8000
```

Important:

- `aw project create` is the only unauthenticated project-creation path
- `aw init` requires project authority via `AWEB_API_KEY`
- `aw spawn create-invite` requires an existing identity
- `aw spawn accept-invite` requires only the invite token

See [`../docs/self-hosting-guide.md`](../docs/self-hosting-guide.md) for the operator view.

## Release to PyPI

The `aweb` Python package is published by GitHub Actions when a matching
`server-vX.Y.Z` tag is pushed.

Local release commands:

```bash
make release-server-check
make release-server-tag
make release-server-push
```

The package version lives in `pyproject.toml`. The tag must match that version
or `.github/workflows/server-release.yml` will fail the release.

## Identity boundary

Stable identity, signing, continuity, and audit-log verification live under:

```text
src/aweb/awid/
```

That boundary is explicit on purpose. The OSS deployment includes both
services, but `aweb` and `awid` now run as separate processes.
