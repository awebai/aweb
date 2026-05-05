# Pre-existing duplicate active 1:1 conversation cleanup (one-time)

This is an operational data update, not a packaged migration.

The post-aame architectural completion (server commit on top of e0f01f3) enforces
'one active 1:1 conversation per participant pair' via ConflictError → 409 when
`find_active_one_to_one_conversation_between` matches more than one row. The
conversation lifecycle continues to use the 30-day sliding TTL — active
conversations expire lazily on read after 30 days of inactivity unless touched
by continuation.

Pre-existing data may have multiple active 1:1 conversations between the same
participant pair (created before the dedup logic landed; for example Aida↔Zeus
accumulated 6 distinct conversation_ids from address-routed sends earlier in
the launch-day cycle). Without a one-time cleanup before the new server code
takes traffic, sends between such pairs will 409 with "Multiple active
conversations match these participants".

Run against the `aweb` schema during the coordinated production cutover, AFTER
the new image is deployed but BEFORE customer traffic resumes:

```sql
-- Pre-check: count duplicate active 1:1 conversation pairs.
-- Read-only. If rows return, the collapse below is required.
WITH two_party AS (
    SELECT
        c.conversation_id,
        c.conversation_type,
        c.updated_at,
        ARRAY_AGG(cp.did ORDER BY cp.did) AS participant_dids
    FROM aweb.conversations c
    JOIN aweb.conversation_participants cp
      ON cp.conversation_id = c.conversation_id
    WHERE c.status = 'active'
    GROUP BY c.conversation_id, c.conversation_type, c.updated_at
    HAVING COUNT(*) = 2
)
SELECT conversation_type, participant_dids, COUNT(*) AS conversation_count
FROM two_party
GROUP BY conversation_type, participant_dids
HAVING COUNT(*) > 1;

-- Collapse duplicate active 1:1 conversations: keep the most-recent active
-- per participant pair; close the older duplicates. Closed conversations
-- remain readable but are no longer eligible as automatic continuation
-- targets.
BEGIN;

WITH two_party AS (
    SELECT
        c.conversation_id,
        c.conversation_type,
        c.updated_at,
        ARRAY_AGG(cp.did ORDER BY cp.did) AS participant_dids
    FROM aweb.conversations c
    JOIN aweb.conversation_participants cp
      ON cp.conversation_id = c.conversation_id
    WHERE c.status = 'active'
    GROUP BY c.conversation_id, c.conversation_type, c.updated_at
    HAVING COUNT(*) = 2
),
ranked AS (
    SELECT
        conversation_id,
        ROW_NUMBER() OVER (
            PARTITION BY conversation_type, participant_dids
            ORDER BY updated_at DESC, conversation_id DESC
        ) AS rn
    FROM two_party
)
UPDATE aweb.conversations c
SET status = 'closed',
    closed_at = NOW(),
    updated_at = NOW()
FROM ranked r
WHERE c.conversation_id = r.conversation_id
  AND r.rn > 1;

COMMIT;
```

Do not run this as a bundled migration. Confirm row counts before and after,
and keep already-closed conversations untouched. If the pre-check returns
zero rows, the collapse step is unnecessary and may be skipped.

The 30-day sliding TTL behavior is the new default and applies forward; no
data update is required to make existing 'active' rows behave correctly under
the new code (they will age out lazily on read after 30 days of inactivity,
or extend their `expires_at` on continuation).
