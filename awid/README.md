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
- `AWID_PUBLIC_ORIGINS` comma-separated canonical external registry origins,
  for example `https://registry.example.com`. Set it before protecting any
  team or using covering controller requests. An embedding may instead set
  `app.state.awid_public_origins` explicitly. Protected mutations fail closed
  when their audience is not configured; Host, forwarded headers and a supplied
  proof never configure an origin. Legacy-only startup remains supported.
- `AWEB_CF_EDGE_CIDRS` and `AWEB_TRUSTED_PROXY_CIDRS` default empty. Both must
  contain valid JSON-array, comma- or pipe-separated CIDR lists to use forwarded
  client IPs for rate limits. Configured proxy peers are trusted first-party
  callers, including private services on Render; they may choose their rate
  attribution. Keep Uvicorn's `FORWARDED_ALLOW_IPS` at its loopback default.
  See [client IP rate attribution](../docs/awid-sot.md#client-ip-rate-attribution)
  for the full trust boundary and fallback behavior.
- `AWID_SERVICE_TOKEN` optional for standalone AWID, but required when AWID
  serves an aweb deployment. Configure the same >=32-byte value on both so
  aweb can read private-team keys and revocations and bypass the public-IP
  rate limits on all registry reads, DID registration, namespace registration,
  encryption-key publication, team creation, certificate registration, address
  registration, team visibility changes, team deletion and certificate revocation.
  All other write limits and all write authorization and
  identity-private/blob authentication still apply. `awid_service_exempt` logs cumulative per-bucket,
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

### Private teams and public certificate status

Private team metadata remains permission-gated. Anyone who knows a certificate
ID can read its existing public status. Negotiating `?protection=1` also returns
the team's protection binding and certificate hash, including for a private
team. These are intentionally public governance facts; no member fields or
certificate blob are returned. Without the query the response stays exactly
the existing four fields. See [the protection contract](../docs/protected-team-boundary.md#binding-and-cutover).

### Registry-first upgrades and rollback limits

Team and negotiated certificate-status reads share the canonical namespace
and team locks. A namespace-level controller effect holds the namespace lock
exclusively and blocks team reads throughout that domain. Keep those effects
short and perform no network work under effect locks. A read that reaches the
database lock timeout answers `503 protected_state_unavailable` with
`Retry-After: 1`; retry rather than treating it as an older registry or legacy
team. Invalid protection projections also log the affected team ID.

The health aliases `/health`, `/ready` and `/ops/health` add
`capabilities.team_protection: true` while preserving their existing fields.
This advertises implementation of explicit team protection and negotiated
certificate status, not a team's state or readiness to cut over. An older
registry may omit the flag; see [startup capability diagnostics](../docs/awid-sot.md#health-probes)
for the distinction between older and unknown responses.

Upgrade the registry before deploying consumers that require its explicit
protection projection. Migrations 012–015 add tables; the native compatibility
check starts the published 0.5.39 registry on that schema and exercises legacy
reads and mutations. Startup compatibility alone is not rollback approval.

After any team has been provisioned, **no registry binary or schema rollback is
supported**, including after forward deprotection. Version 0.5.39 starts but
does not enforce protected teams: a key-only mutation it accepts is refused by
0.5.40. After deprotection it can also rotate the controller without advancing
retained protection generation. Never restore a pre-cutover registry backup to
undo protection. Reconcile and repair forward while preserving its history.
Whether an untouched, never-provisioned legacy installation can downgrade is a
separate compatibility decision.

To repeat the isolated startup/enforcement matrix, provide a disposable
PostgreSQL administrator URL and a dedicated Redis database. The check creates
and removes its own database and runs the actual published 0.5.39 CLI:

```bash
AWID_COMPAT_POSTGRES_URL='<disposable-postgres-url>' \
AWID_REDIS_URL='<dedicated-redis-url>' \
uv run --project awid python scripts/check_awid_039_schema_compatibility.py
```

This is a compatibility test, not an operator provisioning command or a full
client/deployment compatibility matrix.

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

`/health` and `/ready` answer 503 when the Redis or database check fails;
`/live` answers 200 whenever the process serves requests. Use `/live` for
liveness probes and container healthchecks, `/ready` for readiness and routing.
See [health probes](../docs/awid-sot.md#health-probes).

## Release

`awid` is released as a GHCR container image through the repository's `release`
skill and driver. The driver owns planning, exact-byte staging, publication,
tagging, registry verification, and the receipt; do not start a release by
pushing an `awid-vX.Y.Z` tag. The version remains in `pyproject.toml`.
