# AASN migration evidence runbook

Status: **evidence gathering only**. Juan approved read-only production observations, a data-only production dump, and writes/migrations only on a disposable restored clone. This does **not** authorize a production migration, schema write, Render change, release tag, image change, or live heartbeat repair. Tess must approve this runbook before a credentialed operator connects to production.

## Ownership and boundaries

- **Sol:** pins source and normalized manifests, authors this plan, and reviews sanitized evidence. Sol has no production environment file or Render/Neon credentials and cannot run credentialed steps.
- **Credentialed human operator:** reads Neon capacity, runs production read-only SQL and dump, provisions/destroys the clone, and restores/rehearses there.
- **Tess:** reviews this plan before execution and independently reviews the resulting evidence.
- **Juan:** approved evidence gathering only. Production publication, migration, deploy, and live repair remain separately gated.

Pinned canonical aweb release boundary: `55c01511382e6918620427d110422c4c1e9ef098`. `main` has moved; never substitute `main`, `HEAD`, or a branch ref.

Production baseline: AC `v0.7.8`, AC SHA `1f291a72`, embedded aweb SHA `1fb4ea88`, `server-v1.26.24`.

The exact candidate AC image digest does not yet exist. The runbook is therefore deliberately split:

- **Digest-independent:** Phases 0–2 and 2A collect the production inventory/capacity, prove dump/restore, and produce a clone-only temporary-table estimate of new heap/index size. These can proceed after Tess approves the runbook.
- **Digest-dependent:** Phase 3 establishes exact forward-migration timing, locking lower bound, final persistent size, and idempotence. It must wait for a reviewed candidate image—or another separately reviewed exact-source harness—containing the `55c0151` migration bytes.

An unpinned image tag cannot complete Phase 3.

The production-accessing database tools are separately pinned to AC `v0.7.8` commit `1f291a727c0df68633c97aee542903b2cae8efe0`. Raw file SHA-256 values at that commit are:

- `scripts/prod_db_reset.py`: `34016a8e81fba0e8c5eedb22886e1071208efeea4e9f7f8abc8b9f3fd5c17a19`
- `scripts/verify_db_reset_roundtrip.py`: `9ce6e35c93f16f05af35be3e6ca3067771c40704a73633b3d9d922295fdfa5c5`

These tool files are byte-identical on the AC main revision independently reviewed by Tess, but the operator must still use the exact pinned commit above.

## Expected normalized manifest

These values use pgdbm's `sha256(content.replace("\r\n", "\n").strip())`. They are **not** raw `sha256sum` file hashes.

| Migration | pgdbm-normalized checksum |
|---|---|
| `001_initial.sql` | `f54884d83c672403a148ff8968d0cdc0dd9fb16f1afec7dcea8d32c2161e212f` |
| `002_agent_encryption_keys.sql` | `5d1d64d119ff4e62231bdb2245244d0da94a37e0f20673389904c7d8648e49b8` |
| `003_messages_encrypted_v2.sql` | `ab026edadb28658106335d9e8bf6140c4e12be313af104cbd4a767f9a8f89a65` |
| `004_chat_messages_encrypted_v2.sql` | `741cdaa0336cf219e72555246bcc59b1923fa26b59da3051223a309420da75c7` |
| `005_messages_encrypted_v2_shape_legacy_fields.sql` | `97566ffb81713732171e69ae4c490dcb9c6571151153b8b911cd232349c22eda` |
| `006_chat_participants_left_at.sql` | `673104df94388ae9a74d8832470c06ca1dfa7ea4899f55ed0f12e89377a66f52` |
| `007_agent_encryption_key_custody.sql` | `c1ff7c6a97bd2f94471afa8b27edd2b2505e1b32f8fd3f19e7d39b0ab8f90d11` |
| `008_app_registry_grants.sql` | `4867389ff723fed56ed70af33f82bdef815a5ffb8cfc4fd123097f597a8469e9` |
| `009_app_events.sql` | `c59448f589161864c2366e6e48dd7189281bd7dbc731153d8f5ffa9a1cb7ec35` |
| `010_session_admission_leases.sql` | `ef89706921b5f2e73bd9e9798dfcad75ddab5b1ffc3842b9a2d7b3c9d2fb2ef8` |
| `010a_chat_message_reads_orphan_guard.sql` | `7ededc1a3d6f63c4ee145244d7d8874011e78a0c5cf6d8ee6a7ba7e5a80489c7` |
| `011_chat_message_reads.sql` | `8f29a8f12e23242257e99ce158c18de58a54e6b2962eafa4d5f92f873161b1d8` |
| `012_chat_message_reads_orphan_backfill.sql` | `31168413916024a29d8c9c880299b20d77e775c532da1cba074f08543422e376` |

Expected production state is `001`–`009` `MATCH` and all four later files `PENDING`. Anything else is a stop.

## Phase 0: operator preparation

No database access yet.

1. Create a private detached AC worktree at exactly `1f291a727c0df68633c97aee542903b2cae8efe0`, never a dirty shared checkout. Before access, require `git rev-parse HEAD` to equal that full SHA and `git status --porcelain` to be empty. Compute raw SHA-256 for both tool files and require the two values pinned above. Any difference is a stop.
2. Record `psql`, `pg_dump`, Docker, and `/usr/bin/time` versions. PostgreSQL client major version must be compatible with the server.
3. Create a mode-`0700` evidence directory on encrypted private storage and set `umask 077`.
4. Configure separate mode-`0600` PostgreSQL service/password files for production and clone. Logs and commands identify service names only, never URLs/passwords. Visually label separate environment files `READ-ONLY PROD` and `DISPOSABLE CLONE`.
5. The dedicated env file passed to `prod_db_reset.py` must contain exactly one effective database setting of the form `DATABASE_URL=service=<safe-name>`. Set `DB_ENV` to that file and run both fail-closed checks immediately before each dump or restore:

   ```sh
   test "$(grep -Ec '^DATABASE_URL=service=[A-Za-z0-9_.-]+$' "$DB_ENV")" -eq 1
   test "$(grep -Ec '^[[:space:]]*(export[[:space:]]+)?DATABASE_URL[[:space:]]*=' "$DB_ENV")" -eq 1
   ! grep -Eiq '(postgres(ql)?://|password[[:space:]]*=|host[[:space:]]*=)' "$DB_ENV"
   ```

   Any failure stops access. This is mandatory because the tool prints its database argument; an accidental URL could disclose credentials.
6. Obtain direct/unpooled endpoints for dump and migration operations. Keep their details only in the protected service/password files. Record only provider project/branch identifiers.
7. Record the production image by immutable digest from Render and verify `/health`. Later record the candidate image by immutable digest and source attestation. Mutable tags fail the gate.
8. Before creating a dump, name both a primary data custodian and a second cleanup custodian, record the dump path and clone identifier, and set an alarm for a hard expiry no later than four hours after dump start. On every success, stop, timeout, failure, disconnection, or reschedule path, the primary operator must destroy the dump and clone before ending the session; if the primary operator disconnects, the second custodian owns immediate cleanup. Evidence is invalid until deletion is independently confirmed. If Phase 3 cannot start in the same bounded session, clean up after Phase 2A and later repeat Phase 2 with a fresh dump/clone.

## Phase 1: production read-only inventory

Run once, off peak, using `psql -X -v ON_ERROR_STOP=1 -P pager=off service=<production-service>`. Save stdout privately. The transaction must remain read-only. The 120-second timeout bounds load from cardinality counting; if it expires, record `UNKNOWN` and stop for review rather than increasing it.

```sql
BEGIN TRANSACTION READ ONLY;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '120s';
SELECT current_timestamp AS observed_at, current_database(), current_user,
       current_setting('transaction_read_only') AS read_only;

SELECT module_name, filename, checksum, applied_at
FROM aweb.schema_migrations
WHERE module_name = 'aweb-aweb' OR module_name IS NULL
ORDER BY module_name NULLS FIRST, filename;

WITH expected(ord, filename, checksum) AS (VALUES
 (1,'001_initial.sql','f54884d83c672403a148ff8968d0cdc0dd9fb16f1afec7dcea8d32c2161e212f'),
 (2,'002_agent_encryption_keys.sql','5d1d64d119ff4e62231bdb2245244d0da94a37e0f20673389904c7d8648e49b8'),
 (3,'003_messages_encrypted_v2.sql','ab026edadb28658106335d9e8bf6140c4e12be313af104cbd4a767f9a8f89a65'),
 (4,'004_chat_messages_encrypted_v2.sql','741cdaa0336cf219e72555246bcc59b1923fa26b59da3051223a309420da75c7'),
 (5,'005_messages_encrypted_v2_shape_legacy_fields.sql','97566ffb81713732171e69ae4c490dcb9c6571151153b8b911cd232349c22eda'),
 (6,'006_chat_participants_left_at.sql','673104df94388ae9a74d8832470c06ca1dfa7ea4899f55ed0f12e89377a66f52'),
 (7,'007_agent_encryption_key_custody.sql','c1ff7c6a97bd2f94471afa8b27edd2b2505e1b32f8fd3f19e7d39b0ab8f90d11'),
 (8,'008_app_registry_grants.sql','4867389ff723fed56ed70af33f82bdef815a5ffb8cfc4fd123097f597a8469e9'),
 (9,'009_app_events.sql','c59448f589161864c2366e6e48dd7189281bd7dbc731153d8f5ffa9a1cb7ec35'),
 (10,'010_session_admission_leases.sql','ef89706921b5f2e73bd9e9798dfcad75ddab5b1ffc3842b9a2d7b3c9d2fb2ef8'),
 (11,'010a_chat_message_reads_orphan_guard.sql','7ededc1a3d6f63c4ee145244d7d8874011e78a0c5cf6d8ee6a7ba7e5a80489c7'),
 (12,'011_chat_message_reads.sql','8f29a8f12e23242257e99ce158c18de58a54e6b2962eafa4d5f92f873161b1d8'),
 (13,'012_chat_message_reads_orphan_backfill.sql','31168413916024a29d8c9c880299b20d77e775c532da1cba074f08543422e376')
), actual AS (
 SELECT filename, checksum FROM aweb.schema_migrations WHERE module_name='aweb-aweb'
)
SELECT COALESCE(e.filename,a.filename) AS filename,
       e.checksum AS expected_checksum, a.checksum AS applied_checksum,
       CASE WHEN e.filename IS NULL THEN 'UNEXPECTED_APPLIED'
            WHEN a.filename IS NULL THEN 'PENDING'
            WHEN e.checksum=a.checksum THEN 'MATCH'
            ELSE 'CHECKSUM_DRIFT' END AS status
FROM expected e FULL JOIN actual a USING(filename)
ORDER BY COALESCE(e.ord,999), COALESCE(e.filename,a.filename);

-- All 010-012 target and temporary objects must be absent on production.
SELECT 'table' AS object_type, 'aweb.session_admission_leases' AS object_name,
       to_regclass('aweb.session_admission_leases') IS NOT NULL AS present
UNION ALL SELECT 'table','aweb.chat_message_reads',
       to_regclass('aweb.chat_message_reads') IS NOT NULL
UNION ALL SELECT 'index','aweb.idx_session_admission_leases_expiry',
       to_regclass('aweb.idx_session_admission_leases_expiry') IS NOT NULL
UNION ALL SELECT 'index','aweb.idx_chat_message_reads_participant',
       to_regclass('aweb.idx_chat_message_reads_participant') IS NOT NULL
UNION ALL SELECT 'constraint-index','aweb.aapc_chat_messages_session_message_unique',
       to_regclass('aweb.aapc_chat_messages_session_message_unique') IS NOT NULL
UNION ALL SELECT 'constraint-index','aweb.chat_messages_session_message_unique',
       to_regclass('aweb.chat_messages_session_message_unique') IS NOT NULL
UNION ALL SELECT 'temporary-function','aweb.aapc_skip_orphan_chat_message_read()',
       to_regprocedure('aweb.aapc_skip_orphan_chat_message_read()') IS NOT NULL;

SELECT c.conrelid::regclass AS relation, c.conname, c.contype,
       pg_get_constraintdef(c.oid) AS definition
FROM pg_constraint c
WHERE c.connamespace='aweb'::regnamespace
  AND c.conname IN (
    'aapc_chat_messages_session_message_unique',
    'chat_messages_session_message_unique',
    'chat_message_reads_pkey',
    'chat_message_reads_agent_id_fkey',
    'chat_message_reads_session_id_did_fkey',
    'chat_message_reads_session_id_message_id_fkey'
  )
ORDER BY c.conrelid::regclass::text,c.conname;

SELECT t.tgrelid::regclass AS relation, t.tgname
FROM pg_trigger t
WHERE NOT t.tgisinternal
  AND t.tgname='trg_aapc_skip_orphan_chat_message_reads';

-- Record and validate prerequisite deployed constraints/indexes.
SELECT c.conrelid::regclass AS relation, c.conname, c.contype,
       pg_get_constraintdef(c.oid) AS definition
FROM pg_constraint c
WHERE c.conrelid IN (
  'aweb.chat_messages'::regclass,
  'aweb.chat_participants'::regclass,
  'aweb.chat_read_receipts'::regclass
)
ORDER BY c.conrelid::regclass::text,c.conname;

SELECT 'aweb.chat_messages' AS relation,
       to_regclass('aweb.chat_messages') IS NOT NULL AS table_present,
       to_regclass('aweb.chat_messages_pkey') IS NOT NULL AS primary_index_present,
       to_regclass('aweb.idx_chat_messages_session') IS NOT NULL AS session_index_present
UNION ALL SELECT 'aweb.chat_participants',
       to_regclass('aweb.chat_participants') IS NOT NULL,
       to_regclass('aweb.chat_participants_pkey') IS NOT NULL,
       NULL
UNION ALL SELECT 'aweb.chat_read_receipts',
       to_regclass('aweb.chat_read_receipts') IS NOT NULL,
       to_regclass('aweb.chat_read_receipts_pkey') IS NOT NULL,
       NULL;

SELECT c.conrelid::regclass AS relation, c.conname, c.contype,
       pg_get_constraintdef(c.oid) AS definition
FROM pg_constraint c
WHERE c.connamespace='aweb'::regnamespace
  AND c.conname IN (
    'agents_pkey',
    'chat_sessions_pkey',
    'chat_messages_pkey',
    'chat_messages_session_id_fkey',
    'chat_messages_from_agent_id_fkey',
    'chat_participants_pkey',
    'chat_participants_session_id_fkey',
    'chat_participants_agent_id_fkey',
    'chat_read_receipts_pkey',
    'chat_read_receipts_session_id_fkey',
    'chat_read_receipts_agent_id_fkey',
    'chat_read_receipts_last_read_message_id_fkey'
  )
ORDER BY c.conrelid::regclass::text,c.conname;

SELECT 'chat_messages' AS relation, count(*) AS rows,
       pg_total_relation_size('aweb.chat_messages') AS total_bytes FROM aweb.chat_messages
UNION ALL SELECT 'chat_read_receipts', count(*), pg_total_relation_size('aweb.chat_read_receipts') FROM aweb.chat_read_receipts
UNION ALL SELECT 'chat_participants', count(*), pg_total_relation_size('aweb.chat_participants') FROM aweb.chat_participants;

SELECT pg_database_size(current_database()) AS database_bytes;

SELECT COALESCE(sum(n-1),0) AS duplicate_session_message_rows
FROM (SELECT count(*) AS n FROM aweb.chat_messages
      GROUP BY session_id,message_id HAVING count(*)>1) d;

SELECT count(*) AS orphan_participant_receipts
FROM aweb.chat_read_receipts r
LEFT JOIN aweb.chat_participants p ON p.session_id=r.session_id AND p.did=r.did
WHERE p.session_id IS NULL;

SELECT
 count(*) FILTER (WHERE r.last_read_message_id IS NOT NULL AND w.message_id IS NULL) AS missing_watermark,
 count(*) FILTER (WHERE w.message_id IS NOT NULL AND w.session_id<>r.session_id) AS cross_session_watermark,
 count(*) FILTER (WHERE r.agent_id IS NOT NULL AND a.agent_id IS NULL) AS missing_agent,
 count(*) FILTER (WHERE p.session_id IS NULL) AS missing_participant
FROM aweb.chat_read_receipts r
LEFT JOIN aweb.chat_messages w ON w.message_id=r.last_read_message_id
LEFT JOIN aweb.agents a ON a.agent_id=r.agent_id
LEFT JOIN aweb.chat_participants p ON p.session_id=r.session_id AND p.did=r.did;

WITH candidate AS MATERIALIZED (
 SELECT r.session_id,r.did,m.message_id,r.agent_id,
        COALESCE(r.last_read_at,current_timestamp) AS read_at
 FROM aweb.chat_read_receipts r
 JOIN aweb.chat_messages w
   ON w.message_id=r.last_read_message_id AND w.session_id=r.session_id
 JOIN aweb.chat_messages m
   ON m.session_id=r.session_id AND m.from_did<>r.did
  AND m.created_at<=w.created_at
 WHERE EXISTS (SELECT 1 FROM aweb.chat_participants p
               WHERE p.session_id=r.session_id AND p.did=r.did)
)
SELECT count(*) AS candidate_backfill_rows,
       COALESCE(sum(pg_column_size(ROW(session_id,did,message_id,agent_id,read_at))),0)
         AS estimated_tuple_payload_bytes
FROM candidate;
COMMIT;
```

The prerequisite constraint inventory must contain the following deployed definitions: primary keys on `agents(agent_id)`, `chat_sessions(session_id)`, `chat_messages(message_id)`, `chat_participants(session_id,did)`, and `chat_read_receipts(session_id,did)`; session FKs from messages/participants/receipts to `chat_sessions(session_id)`; agent FKs from messages/participants/receipts to `agents(agent_id)`; and the receipt watermark FK to `chat_messages(message_id)`. `idx_chat_messages_session` must index `(session_id,created_at)`. Record `pg_get_constraintdef` output and stop if any name, referenced relation/column, key column/order, or action differs.

PostgreSQL relation sizes do not reveal provider quota. Separately record Neon storage used, plan/quota, and remaining headroom from the console/API. Do not call tablespace size “free capacity.”

### Production stop conditions

Stop without further production access if:

- `transaction_read_only` is not `on`;
- any NULL-module row, `CHECKSUM_DRIFT`, or `UNEXPECTED_APPLIED` appears;
- `001`–`009` are not all `MATCH`, or any of `010`/`010a`/`011`/`012` is already applied;
- duplicate, cross-session-watermark, missing-watermark, or missing-agent count is nonzero;
- either new table, either new named index, either new unique constraint/index, any `chat_message_reads` constraint, the temporary trigger, or the temporary function is present;
- prerequisite old tables, primary keys, `idx_chat_messages_session`, receipt watermark/agent FKs, or participant/message session FKs are absent or differ from the recorded deployed definitions;
- query timeout, connection instability, or material production load occurs;
- provider remaining capacity cannot be established.

Never run `EXPLAIN ANALYZE` or a migration command on production.

## Phase 2: data-only dump and old-schema clone restore

1. Reconfirm production and clone service names differ. The clone database/branch name must contain an explicit rehearsal marker. A second person reads the target before restore. Start the four-hour retention clock and write its expiry into the evidence record.
2. With `umask 077`, use the pinned AC `prod_db_reset.py dump` path after repeating the clean-SHA, file-digest, and service-only-DSN checks from Phase 0. Configure it with `DATABASE_URL=service=<production-service>`. It runs `pg_dump --data-only` for `aweb`, `aweb_cloud`, and `server`. The private dump includes migration metadata, but the supported restore path filters that metadata so the target's freshly applied migration records remain authoritative. Wrap the dump with `/usr/bin/time -p`. Record wall time, dump bytes, and the dump artifact SHA-256. Never publish the dump or credential-bearing output.
3. Provision a fresh disposable clone. Run `python -m aweb_cloud.cli migrate` from the production `v0.7.8` image by immutable digest against **only** the clone to create the deployed old schema.
4. Use AC `prod_db_reset.py restore` against **only** the clone. It filters migration metadata, checks COPY shape, truncates clone application tables, restores atomically, and compares all application-table counts. Wrap it with `/usr/bin/time -p`. Any count mismatch is a hard stop.
5. Use the dump's COPY counts and `prod_db_reset.py` count verification as the restore source of truth. Run the Phase-1 read-only inventory on the clone and use that restored state as the exact candidate/backfill baseline. Do **not** require it to equal the earlier live Phase-1 counts: those observations use different snapshots while production remains writable, so ordinary intervening writes are expected. If one-snapshot equality is ever required, redesign this phase around one explicitly exported snapshot and obtain a new review first.

This phase proves the data-only backup reconstructs the deployed old schema in isolation. It does not prove the forward migration.

## Phase 2A: digest-independent clone size estimate

Run this only on the disposable restored clone. It writes temporary relations in the operator's session and rolls them back; it must never be pointed at production. The probe reproduces the final column/primary-key/participant-index storage and the guarded backfill selection without modifying the canonical `aweb` schema. It estimates final heap/index bytes but does not reproduce persistent DDL locks, FKs, migration bookkeeping, or full migration timing.

```sql
BEGIN;
SET LOCAL statement_timeout = '10min';

CREATE TEMP TABLE aasn_chat_message_reads_probe (
    session_id UUID NOT NULL,
    did TEXT NOT NULL,
    message_id UUID NOT NULL,
    agent_id UUID,
    read_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id, did, message_id)
) ON COMMIT DROP;
CREATE INDEX aasn_chat_message_reads_participant_probe
    ON aasn_chat_message_reads_probe (session_id, did);

INSERT INTO aasn_chat_message_reads_probe
    (session_id, did, message_id, agent_id, read_at)
SELECT r.session_id, r.did, m.message_id, r.agent_id,
       COALESCE(r.last_read_at, current_timestamp)
FROM aweb.chat_read_receipts r
JOIN aweb.chat_messages w
  ON w.message_id=r.last_read_message_id AND w.session_id=r.session_id
JOIN aweb.chat_messages m
  ON m.session_id=r.session_id AND m.from_did<>r.did
 AND m.created_at<=w.created_at
WHERE EXISTS (SELECT 1 FROM aweb.chat_participants p
              WHERE p.session_id=r.session_id AND p.did=r.did)
ON CONFLICT DO NOTHING;

CREATE TEMP TABLE aasn_session_admission_leases_probe (
    team_id TEXT NOT NULL,
    principal_agent_id UUID NOT NULL,
    session_id TEXT NOT NULL,
    session_key_hash BYTEA NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1,
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (team_id, principal_agent_id)
) ON COMMIT DROP;
CREATE INDEX aasn_session_admission_leases_expiry_probe
    ON aasn_session_admission_leases_probe (expires_at);

SELECT 'chat_message_reads_estimate' AS relation,
       count(*) AS rows,
       pg_relation_size('pg_temp.aasn_chat_message_reads_probe') AS heap_bytes,
       pg_indexes_size('pg_temp.aasn_chat_message_reads_probe') AS index_bytes,
       pg_total_relation_size('pg_temp.aasn_chat_message_reads_probe') AS total_bytes
FROM aasn_chat_message_reads_probe
UNION ALL
SELECT 'session_admission_leases_empty_estimate', count(*),
       pg_relation_size('pg_temp.aasn_session_admission_leases_probe'),
       pg_indexes_size('pg_temp.aasn_session_admission_leases_probe'),
       pg_total_relation_size('pg_temp.aasn_session_admission_leases_probe')
FROM aasn_session_admission_leases_probe;

ROLLBACK;
```

Record elapsed time, row count, heap bytes, index bytes, and total bytes. Confirm after rollback that both `to_regclass('pg_temp.aasn_chat_message_reads_probe')` and `to_regclass('pg_temp.aasn_session_admission_leases_probe')` are null. This estimate plus Neon remaining capacity is digest-independent evidence; Phase 3's persistent measured delta supersedes it.

If Phase 3 is still blocked, immediately destroy the clone and dump after capturing sanitized Phase 2A evidence. Never retain them while waiting for a tag, pin, image, approval, reschedule, or review. If Phase 3 is ready in the same session, it must still complete before the recorded four-hour expiry; otherwise clean up and later start from a fresh dump.

## Phase 3: exact-byte forward rehearsal on clone only

This phase is blocked until a reviewed candidate AC image digest exists. Reconfirm its embedded aweb identity and independently extract/recompute all normalized migration checksums from the image.

1. Capture clone database and relation sizes before migration.
2. Run `python -m aweb_cloud.cli migrate` from the candidate image by immutable digest against **only** the clone, wrapped with `/usr/bin/time -p`. Never use a mutable tag or production endpoint.
3. Record pgdbm `execution_time_ms` for each newly applied `aweb-aweb` row and overall real/user/sys time. A clone has production data shape but no live contention, so lock timing is a lower bound.
4. Verify exactly `010`, `010a`, `011`, and `012` were added with expected checksums. No other module may gain an unplanned migration.
5. Verify final shape: `session_admission_leases` and `chat_message_reads` exist; published unique constraint, FKs, and index exist; temporary `010a` trigger/function/constraint are absent.
6. Verify `chat_message_reads` count equals the guarded candidate count and no row references an absent participant, agent, or message. Legacy receipt/message counts must remain unchanged.
7. Record post-migration database size and heap/index/total sizes for both new tables. The measured before/after delta supersedes Phase 2A's temporary estimate. A later decision must choose explicit additional headroom; this runbook does not pre-authorize a threshold.
8. Run the same migration command a second time on the clone. It must report up-to-date, add no rows, and preserve checksums/counts.
9. Preserve only sanitized evidence. Securely delete the dump and clone immediately after evidence capture and record deletion confirmation. Cleanup is mandatory before the operator ends the session and on every stop, timeout, failure, or reschedule path; the four-hour expiry is an absolute maximum, not a target.

## Meaning, cost, and evidence package

The rehearsal proves that the supported dump restores with exact counts; exact release bytes advance a production-shaped old schema; backfill cardinality, storage delta, per-file/overall runtime, final constraints, and idempotence are known. It does **not** prove production lock wait under live traffic, remove provider variance, authorize production apply, or make a database restore a routine rollback.

Reserve up to **two hours** of credentialed operator time: 10–15 minutes setup/inventory, data-dependent dump and restore (the long pole), 10–20 minutes migration/verification, then cleanup and evidence packaging. Temporary storage cost is one private dump plus one disposable database copy. This is a planning budget, not a runtime claim; exact measured wall times become evidence. If the window is exceeded, clean up immediately and reschedule rather than compress verification. Regardless of progress, dump and clone retention may never exceed four hours.

The sanitized evidence package contains timestamps; exact source/image SHAs and digests; tool versions; normalized migration status; counts/sizes/anomalies; provider used/free capacity; dump bytes/hash and dump/restore timing; restored-count verdict; Phase 2A temporary heap/index estimate; per-migration and total clone timing once Phase 3 is unblocked; persistent before/after table sizes; final-shape/idempotence verdict; and clone/dump deletion confirmation.

Never include URLs, credentials, customer rows, the dump, headers, or raw application data.
