---
name: production-awid-db
description: Connect to the awid.ai production database for migrations, audits, and data operations. Credentials at .env.awid-production.
---

# awid.ai production database operations

## Credentials

Production credentials are at the repo root:
```
/Users/juanre/prj/awebai/aweb/.env.awid-production
```

The key variable is `AWID_DATABASE_URL` — a Neon Postgres connection
string. The schema name is `awid` (not `aweb`).

## Connecting

```bash
# Read the URL
grep AWID_DATABASE_URL .env.awid-production

# Connect with psql (strip the channel_binding parameter if psql complains)
psql 'postgresql://...'
```

## Common operations

### Audit table counts
```sql
SELECT 'did_aw_mappings' as tbl, count(*) FROM awid.did_aw_mappings
UNION ALL SELECT 'did_aw_log', count(*) FROM awid.did_aw_log
UNION ALL SELECT 'dns_namespaces', count(*) FROM awid.dns_namespaces
UNION ALL SELECT 'public_addresses', count(*) FROM awid.public_addresses
UNION ALL SELECT 'teams', count(*) FROM awid.teams
UNION ALL SELECT 'team_certificates', count(*) FROM awid.team_certificates
ORDER BY tbl;
```

### Check for orphan addresses (FK violation candidates)
```sql
SELECT pa.name, ns.domain, pa.did_aw
FROM awid.public_addresses pa
JOIN awid.dns_namespaces ns ON ns.namespace_id = pa.namespace_id
LEFT JOIN awid.did_aw_mappings m ON m.did_aw = pa.did_aw
WHERE m.did_aw IS NULL;
```

### Run migrations
```bash
AWID_DATABASE_URL='...' AWID_DB_SCHEMA=awid uv run --project awid python - <<'PY'
import asyncio, os
from awid_service.db import AwidDatabaseInfra

async def main():
    infra = AwidDatabaseInfra(schema=os.environ.get('AWID_DB_SCHEMA', 'awid'))
    await infra.initialize(run_migrations=True)
    await infra.close()

asyncio.run(main())
PY
```

### Dump data
```bash
pg_dump 'postgresql://...' --schema=awid --data-only --column-inserts -f /tmp/awid-dump.sql
```

## Schema reset (consolidation)

When consolidating migrations into a single 001_registry.sql:

1. Dump current data with `--column-inserts`
2. Transform the dump to match the new schema (strip dropped columns)
3. Drop the schema: `DROP SCHEMA awid CASCADE;`
4. Run the migration (see above)
5. Load the transformed data
6. Verify counts and orphans

This was done for awid 0.3.1. See commit cd01fac for the consolidation.

## Notes

- The cloud database at aweb-cloud/.env.production is SEPARATE.
  It has an embedded awid copy with minimal data. The external
  awid.ai registry database is what matters for production.
- Always verify orphan addresses before deploying migrations that
  add FK constraints.
- Do NOT use `source .env.awid-production` directly — the URL
  contains `&` which breaks shell parsing. Use grep or inline the URL.
