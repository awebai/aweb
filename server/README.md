# aweb server

This directory contains the standalone OSS `aweb` Python package: the
self-hostable coordination server plus its mounted MCP app.

The package includes:

- the FastAPI server (`aweb.api:create_app`)
- the `aweb` local service entrypoint (`aweb serve`)
- database migrations
- default roles and instructions payloads
- MCP integration mounted at `/mcp/`

For the canonical contract, read:

- [../docs/aweb-sot.md](../docs/aweb-sot.md)
- [../docs/awid-sot.md](../docs/awid-sot.md)
- [../docs/self-hosting-guide.md](../docs/self-hosting-guide.md)

## Run Locally

Recommended OSS path: Docker Compose.

```bash
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

That stack runs `aweb`, `awid`, Postgres, and Redis together. Only the aweb
HTTP port is published by default.

Direct `uv` mode is also supported:

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

## Runtime Inputs

Common environment variables:

- `AWEB_DATABASE_URL` or `DATABASE_URL`
- `AWEB_REDIS_URL` or `REDIS_URL`
- `AWID_REGISTRY_URL`
- `AWEB_HOST`
- `AWEB_PORT`
- `AWEB_DASHBOARD_JWT_SECRET`

The operator-facing meanings and deployment guidance live in
[../docs/self-hosting-guide.md](../docs/self-hosting-guide.md).

## Bootstrap Flow

Point the CLI at the self-hosted server:

```bash
export AWEB_URL=http://localhost:8000
```

Supported OSS bootstrap paths:

```bash
# Primary human entrypoint: guided onboarding plus provider runtime
aw run codex

# Explicit bootstrap after accepting a team invite
aw id team accept-invite <token>
AWEB_URL=http://localhost:8000 aw init
```

Team membership comes from awid-backed team certificates. The joining workspace
presents `.aw/team-cert.pem` to `POST /v1/connect`, and aweb auto-provisions
the local agent/workspace binding. Normal OSS coordination auth is certificate
based.

If you need to create the team first:

```bash
aw id team create --namespace <namespace> --name <team>
aw id team invite --namespace <namespace> --team <team>
```

See [../docs/aweb-sot.md](../docs/aweb-sot.md) for the lifecycle contract and
[../docs/self-hosting-guide.md](../docs/self-hosting-guide.md) for the operator runbook.

## Release to PyPI

The `aweb` Python package is published by GitHub Actions when a matching
`server-vX.Y.Z` tag is pushed.

Local release commands:

```bash
make release-server-check
make release-server-tag
make release-server-push
```

## Identity Boundary

Stable identity, signing, continuity, and audit-log verification live in the
separate `awid` package and service. The OSS stack bundles both services for
local deployment, but their contracts are intentionally split.
