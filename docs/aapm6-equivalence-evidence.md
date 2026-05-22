# aapm.6: canonical aweb consolidation — final-schema equivalence evidence

Athena `c3692734` non-negotiable: prove `001_initial.sql` (the consolidated baseline) produces an identical final schema to the prior `001..011` chain on a fresh DB.

## Method

Apply each set to a freshly-created Postgres database, dump schema-only with `pg_dump`, diff.

```python
# Both databases get aweb schema with module_name="aweb-aweb".
old_path = /Users/juanre/prj/awebai/aweb/server/src/aweb/migrations/aweb   # main @ f31ffcb (001..011)
new_path = /Users/juanre/prj/awebai/aweb-aapm6/server/src/aweb/migrations/aweb   # this branch (single 001)

await apply_migrations("aapm6_old_chain", old_path)       # 11 migrations applied
await apply_migrations("aapm6_new_baseline", new_path)    #  1 migration applied

pg_dump --schema-only --no-owner --no-privileges --no-comments \
        --schema=aweb -h localhost -p 5432 -U postgres aapm6_old_chain  > /tmp/aapm6_old.sql
pg_dump --schema-only --no-owner --no-privileges --no-comments \
        --schema=aweb -h localhost -p 5432 -U postgres aapm6_new_baseline > /tmp/aapm6_new.sql

# Strip pg_dump's random per-session \restrict/\unrestrict tokens:
diff <(grep -vE '^\\(restrict|unrestrict) ' /tmp/aapm6_old.sql) \
     <(grep -vE '^\\(restrict|unrestrict) ' /tmp/aapm6_new.sql)
```

## Result

```
exit=0   # zero output — schemas are identical
```

Both pg_dump outputs are 31237 bytes; after stripping the random session-restrict tokens the byte-for-byte diff is empty.

## Tables verified

The consolidated baseline produces every table the prior chain produced, with identical columns, types, defaults, CHECK constraints, indexes, FKs, and the `trg_conversations_updated_at` trigger + `aweb.set_conversation_updated_at()` function. Column ordinal positions in `aweb.agents` and `aweb.contacts` are preserved (the baseline places `inbound_mode`/`identity_scope` after the original 001 columns and the 004 contacts columns after `created_at`, matching where the historical ALTER TABLE statements landed them).

## What's intentionally different

- `schema_migrations` content. Old chain has 11 rows; new baseline has 1. This is the design intent: the rebuild path resets `schema_migrations` so the rebuilt target does not replay the historical chain. AC's consumer (cutover/restore) treats `schema_migrations` as out-of-scope for restore and lets the migration manager rebuild it fresh.

## Reproducer

Both databases must be **freshly created** (DROP + CREATE on each run) because `pgdbm`'s migration manager refuses to re-run a migration whose checksum has changed; the equivalence check needs a clean slate to compare baselines.
