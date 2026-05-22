# aapm.6: canonical aweb consolidation — final-schema equivalence evidence

Athena `c3692734` non-negotiable: prove `001_initial.sql` (the consolidated baseline) produces an identical final schema to the prior `001..011` chain on a fresh DB.

## Reset-only baseline — not an in-place upgrade

This consolidation **changes the checksum of `001_initial.sql` and removes the later filenames** that were previously applied to existing databases. That's the design intent for Juan's prod rebuild/restore cutover (the aapm.2 mapping script rebuilds the DB and `schema_migrations` from scratch), but it is **not** a normal pgdbm upgrade path:

- The consolidated `001_initial.sql` MUST NOT be applied as an in-place migration against an already-migrated DB whose `schema_migrations` already contains rows for `001..011`. pgdbm's migration manager will refuse (checksum mismatch on the previously-applied `001_initial.sql`).
- The only supported consumption is a **fresh rebuild** where `schema_migrations` is rebuilt by pgdbm's first apply of the consolidated baseline.
- Existing-DB upgrade paths (if any environment is still running the historical 001..011 chain and cannot be rebuilt) must NOT path-swap `schema_migrations` to claim the consolidated checksum; that would silently break checksum provenance. Either rebuild from a dump (aapm.2 mapping script), or keep the historical chain pinned in a parallel `aweb` package version until the environment is decommissioned.

## Old → new mapping

| Removed | Folded into `001_initial.sql` as |
|---|---|
| `002_conversations.sql` | inline `CREATE TABLE conversations` + `conversation_participants` |
| `003_conversations_constraints.sql` | inline CHECK constraints (`conversations_created_by_did_not_blank`, `conversation_participants_alias_not_blank`, `conversation_participants_reachable`) + `aweb.set_conversation_updated_at()` function + `trg_conversations_updated_at` trigger |
| `004_contacts_handle_state.sql` | inline `reference_type` / `status` / `handle_namespace` / `target_agent_name` columns on contacts + `contacts_reference_type_valid` / `contacts_status_valid` / `contacts_reference_shape_valid` CHECKs + `idx_contacts_owner_handle_target` index |
| `005_federated_message_deliveries.sql` | inline `CREATE TABLE federated_message_deliveries` |
| `006_participant_delivery_origin.sql` | inline `delivery_origin TEXT` on chat_participants + conversation_participants + per-table partial indexes |
| `007_participant_current_did_key.sql` | inline `current_did_key TEXT` on both participant tables |
| `008_agent_inbound_mode.sql` | inline `agents.inbound_mode TEXT` column with the final 3-value CHECK (no two-value intermediate; no messaging_policy backfill UPDATEs) |
| `009_drop_messaging_policy.sql` | `messaging_policy` absent from the baseline (not declared, not dropped) |
| `010_agent_identity_scope.sql` | inline `agents.identity_scope TEXT NOT NULL DEFAULT 'local'` + `agents_identity_scope_valid` CHECK; `lifetime` absent from the baseline |
| `011_contacts_or_teammates_inbound_mode.sql` | the 3-value CHECK is the only `agents_inbound_mode_valid` CHECK in 001 (no DROP+ADD CONSTRAINT churn) |

Column ordinal positions in `agents` and `contacts` match the historical chain so `pg_dump --schema-only` diffs clean (see "Result" below): `inbound_mode` and `identity_scope` declared at the end of the agents column list; 004 contacts columns declared after `created_at`.

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
