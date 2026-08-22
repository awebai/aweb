# awid.ai service

This directory contains the standalone `awid.ai` registry service.

It is intentionally thin:

- imports the DID, namespace, and address routes from the `aweb` package
- uses the same signing, verification, and HTTP contracts as `aweb`
- owns only service-local concerns: startup, pgdbm wiring, Redis-backed rate
  limiting, health endpoints, Docker packaging, and migration tooling

## Run locally

```bash
uv sync
uv run awid
```

Required environment:

- `AWID_DATABASE_URL` or `DATABASE_URL`
- `AWID_REDIS_URL` or `REDIS_URL`

Optional environment:

- `AWID_HOST` default `0.0.0.0`
- `AWID_PORT` default `8010`
- `AWID_DB_SCHEMA` default `awid`
- `AWID_RATE_LIMIT_BACKEND` default `redis`
- `AWID_SERVICE_TOKEN` optional for standalone AWID, but required when AWID
  serves an aweb deployment. Configure the same >=32-byte value on both so
  aweb can read private-team keys and revocations.

## Docker

```bash
cp .env.example .env
docker compose up --build -d
curl http://localhost:8010/health
```

## Release

`awid` is released as a GHCR container image through the repository's `release`
skill and driver. The driver owns planning, exact-byte staging, publication,
tagging, registry verification, and the receipt; do not start a release by
pushing an `awid-vX.Y.Z` tag. The version remains in `pyproject.toml`.
