# AASN migration evidence runbook

Status: **evidence gathering only**. Juan approved read-only production observations, a data-only production dump, and writes/migrations only on a disposable restored clone. This does **not** authorize a production migration, schema write, Render change, release tag, image change, or live heartbeat repair. Tess must approve this runbook before a credentialed operator connects to production.

## Ownership and boundaries

- **Sol:** pins source and normalized manifests, authors this plan, and reviews sanitized evidence. Sol has no production environment file or Render/Neon credentials and cannot run credentialed steps.
- **Credentialed human operator:** reads Neon capacity, runs production read-only SQL and dump, provisions/destroys the clone, and restores/rehearses there.
- **Tess:** reviews this plan before execution and independently reviews the resulting evidence.
- **Juan:** approved evidence gathering only. Production publication, migration, deploy, and live repair remain separately gated.

Pinned canonical aweb release boundary: `55c01511382e6918620427d110422c4c1e9ef098`. `main` has moved; never substitute `main`, `HEAD`, or a branch ref.

Production baseline: AC `v0.7.8`, AC SHA `1f291a72`, embedded aweb SHA `1fb4ea88`, `server-v1.26.24`.

The exact candidate AC image digest does not yet exist. Production inventory/dump and old-schema restoration can occur after plan approval, but final migration timing must wait for a reviewed candidate image—or another separately reviewed exact-source harness—containing the `55c0151` migration bytes. An unpinned image tag cannot complete the rehearsal.

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

1. Use a private clean AC worktree, never a dirty shared checkout. Record its full SHA.
2. Record `psql`, `pg_dump`, Docker, and `/usr/bin/time` versions. PostgreSQL client major version must be compatible with the server.
3. Create a mode-`0700` evidence directory on encrypted private storage and set `umask 077`.
4. Configure separate mode-`0600` PostgreSQL service/password files for production and clone. Logs and commands identify service names only, never URLs/passwords. Visually label separate environment files `READ-ONLY PROD` and `DISPOSABLE CLONE`.
5. Obtain direct/unpooled endpoints for dump and migration operations. Record only provider project/branch identifiers.
6. Record the production image by immutable digest from Render and verify `/health`. Later record the candidate image by immutable digest and source attestation. Mutable tags fail the gate.

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

PostgreSQL relation sizes do not reveal provider quota. Separately record Neon storage used, plan/quota, and remaining headroom from the console/API. Do not call tablespace size “free capacity.”

### Production stop conditions

Stop without further production access if:

- `transaction_read_only` is not `on`;
- any NULL-module row, `CHECKSUM_DRIFT`, or `UNEXPECTED_APPLIED` appears;
- `001`–`009` are not all `MATCH`, or any of `010`/`010a`/`011`/`012` is already applied;
- duplicate, cross-session-watermark, missing-watermark, or missing-agent count is nonzero;
- query timeout, connection instability, or material production load occurs;
- provider remaining capacity cannot be established.

Never run `EXPLAIN ANALYZE` or a migration command on production.

## Phase 2: data-only dump and old-schema clone restore

1. Reconfirm production and clone service names differ. The clone database/branch name must contain an explicit rehearsal marker. A second person reads the target before restore.
2. With `umask 077`, use AC's audited `prod_db_reset.py dump` path from the pinned clean worktree, configured with `DATABASE_URL=service=<production-service>`. It runs `pg_dump --data-only` for `aweb`, `aweb_cloud`, and `server`. The private dump includes migration metadata, but the supported restore path filters that metadata so the target's freshly applied migration records remain authoritative. Wrap the dump with `/usr/bin/time -p`. Record wall time, dump bytes, and the dump artifact SHA-256. Never publish the dump or credential-bearing output.
3. Provision a fresh disposable clone. Run `python -m aweb_cloud.cli migrate` from the production `v0.7.8` image by immutable digest against **only** the clone to create the deployed old schema.
4. Use AC `prod_db_reset.py restore` against **only** the clone. It filters migration metadata, checks COPY shape, truncates clone application tables, restores atomically, and compares all application-table counts. Wrap it with `/usr/bin/time -p`. Any count mismatch is a hard stop.
5. Run the Phase-1 read-only inventory on the clone. Counts and `001`–`009` migration state must match the production snapshot.

This phase proves the data-only backup reconstructs the deployed old schema in isolation. It does not prove the forward migration.

## Phase 3: exact-byte forward rehearsal on clone only

This phase is blocked until a reviewed candidate AC image digest exists. Reconfirm its embedded aweb identity and independently extract/recompute all normalized migration checksums from the image.

1. Capture clone database and relation sizes before migration.
2. Run `python -m aweb_cloud.cli migrate` from the candidate image by immutable digest against **only** the clone, wrapped with `/usr/bin/time -p`. Never use a mutable tag or production endpoint.
3. Record pgdbm `execution_time_ms` for each newly applied `aweb-aweb` row and overall real/user/sys time. A clone has production data shape but no live contention, so lock timing is a lower bound.
4. Verify exactly `010`, `010a`, `011`, and `012` were added with expected checksums. No other module may gain an unplanned migration.
5. Verify final shape: `session_admission_leases` and `chat_message_reads` exist; published unique constraint, FKs, and index exist; temporary `010a` trigger/function/constraint are absent.
6. Verify `chat_message_reads` count equals the guarded candidate count and no row references an absent participant, agent, or message. Legacy receipt/message counts must remain unchanged.
7. Record post-migration database size and heap/index/total sizes for both new tables. The measured before/after delta is the capacity estimate. A later decision must choose explicit additional headroom; this runbook does not pre-authorize a threshold.
8. Run the same migration command a second time on the clone. It must report up-to-date, add no rows, and preserve checksums/counts.
9. Preserve only sanitized evidence. Securely delete the dump and clone after review and record deletion confirmation.

## Meaning, cost, and evidence package

The rehearsal proves that the supported dump restores with exact counts; exact release bytes advance a production-shaped old schema; backfill cardinality, storage delta, per-file/overall runtime, final constraints, and idempotence are known. It does **not** prove production lock wait under live traffic, remove provider variance, authorize production apply, or make a database restore a routine rollback.

Reserve up to **two hours** of credentialed operator time: 10–15 minutes setup/inventory, data-dependent dump and restore (the long pole), 10–20 minutes migration/verification, then cleanup and evidence packaging. Temporary storage cost is one private dump plus one disposable database copy. This is a planning budget, not a runtime claim; exact measured wall times become evidence. If the window is exceeded, stop and reschedule rather than compress verification.

The sanitized evidence package contains timestamps; exact source/image SHAs and digests; tool versions; normalized migration status; counts/sizes/anomalies; provider used/free capacity; dump bytes/hash and dump/restore timing; restored-count verdict; per-migration and total clone timing; before/after table sizes; final-shape/idempotence verdict; and clone/dump deletion confirmation.

Never include URLs, credentials, customer rows, the dump, headers, or raw application data.
