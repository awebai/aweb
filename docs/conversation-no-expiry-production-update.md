# Conversation No-Expiry Production Update

This is an operational data update, not a packaged migration.

The application change removes lazy age-based conversation expiry. Active
conversations now remain active until an explicit close or explicit expire
operation. Production rows that were expired only because of the old 30-day
lazy TTL need to be restored when this change ships.

Run against the `aweb` schema during the coordinated production cutover:

```sql
-- Pre-check possible duplicate active-or-reactivated 1:1 conversations.
-- This query is intentionally read-only. If it returns rows, confirm they are
-- expected historical duplicates before running the transaction below.
WITH two_party AS (
    SELECT
        c.conversation_id,
        c.conversation_type,
        c.status,
        c.updated_at,
        ARRAY_AGG(cp.did ORDER BY cp.did) AS participant_dids
    FROM aweb.conversations c
    JOIN aweb.conversation_participants cp
      ON cp.conversation_id = c.conversation_id
    WHERE c.status = 'active'
       OR (c.status = 'expired' AND c.closed_at IS NULL)
    GROUP BY c.conversation_id, c.conversation_type, c.status, c.updated_at
    HAVING COUNT(*) = 2
)
SELECT conversation_type, participant_dids, COUNT(*) AS conversation_count
FROM two_party
GROUP BY conversation_type, participant_dids
HAVING COUNT(*) > 1;

BEGIN;

UPDATE aweb.conversations
SET status = 'active',
    expires_at = NULL,
    updated_at = NOW()
WHERE status = 'expired'
  AND closed_at IS NULL;

UPDATE aweb.conversations
SET expires_at = NULL,
    updated_at = NOW()
WHERE status = 'active'
  AND expires_at IS NOT NULL;

-- Collapse duplicate active 1:1 conversations after the reactivation step.
-- Keep the most-recent conversation active for each participant pair and close
-- older duplicates. Closed conversations remain readable, but are no longer
-- eligible as automatic continuation targets.
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
and keep closed conversations closed. The transaction must complete before the
new server code receives traffic; otherwise known historical duplicate 1:1
channels will surface ambiguity conflicts.
