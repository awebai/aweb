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
  aweb can read private-team keys and revocations and bypass the public-IP
  rate limits on all registry reads. Write limits and identity-private/blob
  authentication still apply. `awid_service_exempt` logs cumulative per-bucket,
  process-local exemption counts at 1, 2, 4, 8 and later powers of two; the token
  is never logged. See [the trust model](../docs/trust-model.md#trusted-awid-service-reads).
- `AWID_DATABASE_USES_TRANSACTION_POOLER` default `false`. Set `true` when the
  database URL points at a transaction pooler (PgBouncer, Neon `-pooler`
  endpoints): asyncpg's statement cache is turned off and the pool is bounded.
- `AWID_DATABASE_POOLER_MAX_CONNECTIONS` default `10`, the pool bound used with
  the transaction pooler.
- `AWID_DATABASE_STATEMENT_CACHE_SIZE` overrides the statement cache size.
- `AWID_DATABASE_SESSION_CHECK_TIMEOUT_SECONDS` default `30`, the bound on the
  startup session-settings check.
- `AWID_DATABASE_REQUIRE_SESSION_SETTINGS` default `false`. Set `true` to refuse
  to start unless connections carry the `search_path` pin and the pgdbm
  timeouts (`statement_timeout`, `lock_timeout`,
  `idle_in_transaction_session_timeout`, `jit`).

### Session settings in the connection URL

Neon drops pgdbm's startup parameters on its direct endpoint as well as on its
pooler. On a direct (non-pooler) endpoint, put the settings in the URL's
`options` parameter instead, which Neon applies to each connection
(`source = client` in `pg_settings`); its pooler refuses `options`:

```
postgresql://<user>:<password>@<direct-host>/<db>?sslmode=require&options=-c%20search_path%3Dpg_catalog%20-c%20statement_timeout%3D60000%20-c%20lock_timeout%3D5000%20-c%20idle_in_transaction_session_timeout%3D60000%20-c%20jit%3Doff
```

This changes nothing on the database role, so removing the parameter undoes
it. Leave `AWID_DATABASE_USES_TRANSACTION_POOLER` at `false` (a direct
connection keeps the statement cache) and set
`AWID_DATABASE_REQUIRE_SESSION_SETTINGS=true`: the `search_path` in `options`
must be `pg_catalog`, the value awid pins, or startup refuses. Each instance
holds up to 20 connections, so size against the server's `max_connections`
with two instances overlapping during a deploy. `SHOW` formats durations
(`1min`, `5s`), so compare with `pg_settings.setting` instead.

### Migrations under the pinned search_path

With `search_path` set to `pg_catalog`, an unqualified name resolves only in
`pg_catalog`, so every object a migration creates or alters must be written as
`{{tables.name}}`, which pgdbm qualifies with the `awid` schema. An unqualified
`CREATE TABLE`, `CREATE TYPE`, `CREATE FUNCTION` or reference fails at startup
and the deploy does not go live. An index name may stay bare, since an index is
created in its table's schema. The test suite applies every migration under the
same pin (`tests/conftest.py`, `shared_test_pool`), so such a migration fails
in CI first.

### Behind a transaction pooler

pgdbm requests its `search_path` pin and timeouts as startup parameters, and a
transaction pooler can drop them without an error; Neon's pooler does. Set them
as defaults of the database role, which the server applies to every new
connection:

```sql
ALTER ROLE <role> SET search_path TO pg_catalog;
ALTER ROLE <role> SET statement_timeout = '60s';
ALTER ROLE <role> SET lock_timeout = '5s';
ALTER ROLE <role> SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE <role> SET jit = off;
```

Role defaults reach only new server connections, so refresh the pooler's
connections afterwards, and confirm with
`SELECT name, setting, source FROM pg_settings` that each shows `source = user`.
Then set `AWID_DATABASE_USES_TRANSACTION_POOLER=true` and
`AWID_DATABASE_REQUIRE_SESSION_SETTINGS=true`. At startup awid samples at least
20 concurrently held server connections and refuses to start if any lacks a
setting, so a partially refreshed pooler is caught. `make test-awid-pooler`
runs awid's checks through a real PgBouncer.

The defaults apply to everything that connects as that role. Operators and
scripts using it must schema-qualify (`awid.teams`), or set the path inside a
transaction: through a transaction pooler a plain `SET` does not persist, so use
`BEGIN; SET LOCAL search_path TO awid; ...; COMMIT;`. A migration or backfill
that may run longer than 60 seconds must raise its own limit inside its
transaction with `SET LOCAL statement_timeout = '...'`.

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
