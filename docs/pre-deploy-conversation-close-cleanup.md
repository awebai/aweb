# Pre-deploy conversation close — one-time cleanup (post-1.20.1 / v0.5.22 follow-up)

This is the second-pass operational cleanup, complementing
`duplicate-1to1-conversation-cleanup.md`. The duplicate-1to1 collapse
already ran during the v0.5.22 cutover (211 conversations across 16 pairs,
collapsed to one most-recent active per pair).

After deploy, two distinct issues surfaced on cleanup-preserved
pre-deploy state:

1. **Mail 409 on a SUBSET of pre-deploy active conversations.**
   Pair-specific, not pre-deploy-blanket — 96317ca9 (hestia↔athena,
   created post-aame-1.19.0) works fine for sends in both directions
   despite being pre-1.20.1-deploy. Other older conversations
   (athena↔sofia) 409. Likely cause: stale identity columns (older
   `did_aw`, missing `address`, removed `agent_id`) in
   `conversation_participants` rows for the broken pair, which the
   1.20.1 `/v1/conversations` visibility query doesn't match against
   the actor's current auth identity. The server-side
   `_existing_mail_conversation_for_target` uses a more permissive
   lookup that DOES find the conversation — that asymmetry produces
   the 409.

2. **Chat 403 on continuation of all pre-aame chat sessions.** 1.20.1's
   W3 protection rejects continuation when "the latest signed message
   does not bind conversation_id". Pre-aame messages were signed
   without that binding by construction. Affects ALL 240 pre-deploy
   chat sessions because none of them have post-aame-binding messages
   as their latest. The CLI's `shouldProbeExistingSession` finds these
   sessions via `/v1/chat/sessions` (which has no age filter), tries
   continuation, server 403s.

Both reduce to: pre-deploy data is incompatible with post-1.20.1
code paths in specific ways. Backfilling signed payloads is impossible
(original signing keys aren't ours). The clean fix is:

- Mail: **close only the SUBSET of pre-deploy active conversations
  that are actually broken** (identified empirically via probe send,
  or via the staleness-detection query below). Do NOT blanket-close
  all pre-deploy conversations.
- Chat: **DELETE all pre-deploy chat_sessions outright** (cascades to
  `chat_messages`, `chat_participants`, `chat_read_receipts` per FK
  ON DELETE CASCADE). All 240 are functionally broken for resumption;
  chat_sessions has no `expires_at` column to use a softer mechanism.

Customers retain mail history (closed mail conversations remain
readable via `aw mail show <conversation_id>`); pre-aame chat history
is lost (was un-continuable anyway, and at dogfooding scale this is
small).

## Schema gotcha banked

`aweb.chat_sessions` columns (verified against prod):
`session_id, team_id, created_by, wait_seconds, wait_started_at,
wait_started_by, created_at`. NO `expires_at`. NO `updated_at`. An
earlier draft of this procedure assumed both columns existed (mirroring
the duplicate-1to1 cleanup's UPDATE shape) — wrong. Same recurring
class as `aweb.agents.updated_at` and `aweb.teams.updated_at`. **Always
verify column existence against prod `\d <table>` before drafting
ops SQL.**

## When to run

Post-deploy, ideally during a quiet traffic window. If customer traffic
is currently active, current state is "specific pairs hit 409/403,
others work" — visible to anyone who tries to continue an old thread,
but not catastrophic. Run during the next quiet window.

## Pre-check (read-only)

```sql
-- Mail half: count pre-deploy active mail conversations and identify
-- which ones have stale participant identity columns vs current
-- aweb.agents state. Stale rows are the suspect-set for closure.
SELECT
    'mail conversations to investigate' AS category,
    COUNT(*) AS rows
FROM aweb.conversations
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at < '2026-05-05T21:27:26Z'

UNION ALL

SELECT
    'mail conversations untouched (post-deploy active)',
    COUNT(*)
FROM aweb.conversations
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at >= '2026-05-05T21:27:26Z'

UNION ALL

SELECT 'chat sessions to delete (pre-deploy)', COUNT(*)
FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z'

UNION ALL

SELECT 'chat sessions untouched (post-deploy)', COUNT(*)
FROM aweb.chat_sessions
WHERE created_at >= '2026-05-05T21:27:26Z'

UNION ALL

SELECT 'chat_messages attached to pre-deploy sessions', COUNT(*)
FROM aweb.chat_messages cm
JOIN aweb.chat_sessions s ON s.session_id = cm.session_id
WHERE s.created_at < '2026-05-05T21:27:26Z'

UNION ALL

SELECT 'chat_participants attached to pre-deploy sessions', COUNT(*)
FROM aweb.chat_participants cp
JOIN aweb.chat_sessions s ON s.session_id = cp.session_id
WHERE s.created_at < '2026-05-05T21:27:26Z';
```

## Mail-half: identify broken pairs (staleness-detection query)

```sql
-- Conversations where at least one cp row's identity columns do not
-- match the current state of that participant in aweb.agents.
SELECT
    c.conversation_id,
    c.created_at AS conv_created,
    cp.alias    AS cp_alias,
    cp.did      AS cp_did,
    cp.agent_id AS cp_agent_id,
    cp.address  AS cp_address,
    a.did_aw    AS agent_did_aw,
    a.address   AS agent_address,
    CASE
        WHEN a.agent_id IS NULL                                   THEN 'cp.agent_id no longer in agents'
        WHEN a.did_aw IS NOT NULL AND cp.did <> a.did_aw          THEN 'cp.did stale vs agent.did_aw'
        WHEN cp.address IS NULL AND a.address IS NOT NULL          THEN 'cp.address missing, agent has address'
        WHEN cp.address IS NOT NULL AND a.address IS NOT NULL
             AND cp.address <> a.address                           THEN 'cp.address stale vs agent.address'
    END AS staleness_reason
FROM aweb.conversations c
JOIN aweb.conversation_participants cp
  ON cp.conversation_id = c.conversation_id
LEFT JOIN aweb.agents a
  ON a.agent_id = cp.agent_id
   OR (a.did_aw = cp.did AND cp.did LIKE 'did:aw:%')
WHERE c.conversation_type = 'mail'
  AND c.status = 'active'
  AND c.created_at < '2026-05-05T21:27:26Z'
  AND (
       (a.agent_id IS NULL)
    OR (a.did_aw IS NOT NULL AND cp.did <> a.did_aw)
    OR (cp.address IS NULL AND a.address IS NOT NULL)
    OR (cp.address IS NOT NULL AND a.address IS NOT NULL AND cp.address <> a.address)
  )
ORDER BY c.conversation_id, cp.alias;
```

Each `conversation_id` returned is a candidate for closure. Cross-check
empirically: from one of the participants' workspaces, send
`aw mail send --to <other-participant>`. If it 409s with "Existing
active conversation found", that conversation is broken — close it.
If it sends cleanly, leave it.

At 9 pre-deploy active mail conversations (current count), empirical
testing all 9 pairs is the most reliable approach. The staleness query
is a hint about which ones likely need closure, not a definitive answer
(there could be cases where the staleness columns match but some
secondary asymmetry still produces the 409, or vice versa).

## Mail-half: close confirmed-broken conversations only

```sql
BEGIN;

UPDATE aweb.conversations
SET status = 'closed',
    closed_at = NOW(),
    updated_at = NOW()
WHERE conversation_id IN (
    -- Replace with the set of conversation_ids confirmed broken
    -- via empirical probe (each one 409'd on send).
    '<uuid-1>',
    '<uuid-2>'
    -- ...
);

COMMIT;
```

Closed conversations remain readable via `aw mail show
<conversation_id>` and are NOT considered "active 1:1" by the dedup
logic, so the next send between those pairs creates a fresh
conversation cleanly.

## Chat-half: DELETE all pre-deploy chat sessions

```sql
BEGIN;

DELETE FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z';

COMMIT;
```

Cascade behavior: `chat_sessions` has FK ON DELETE CASCADE from
`chat_messages.session_id`, `chat_participants.session_id`, and
`chat_read_receipts.session_id`. So a single DELETE on `chat_sessions`
removes all attached state cleanly. **Verify this assumption against
prod schema before running** (`\d aweb.chat_messages`,
`\d aweb.chat_participants`, `\d aweb.chat_read_receipts` — look for
ON DELETE CASCADE on the FK to chat_sessions).

If cascade is NOT configured, do explicit per-table deletes in
dependency order:

```sql
BEGIN;

DELETE FROM aweb.chat_read_receipts
WHERE session_id IN (
    SELECT session_id FROM aweb.chat_sessions
    WHERE created_at < '2026-05-05T21:27:26Z'
);

DELETE FROM aweb.chat_messages
WHERE session_id IN (
    SELECT session_id FROM aweb.chat_sessions
    WHERE created_at < '2026-05-05T21:27:26Z'
);

DELETE FROM aweb.chat_participants
WHERE session_id IN (
    SELECT session_id FROM aweb.chat_sessions
    WHERE created_at < '2026-05-05T21:27:26Z'
);

DELETE FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z';

COMMIT;
```

## Post-check

```sql
-- Should both be 0.
SELECT 'pre-deploy non-closed broken mail remaining', COUNT(*)
FROM aweb.conversations
WHERE conversation_id IN ('<uuids-closed-above>')
  AND status = 'active'

UNION ALL

SELECT 'pre-deploy chat sessions remaining', COUNT(*)
FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z';
```

## Acceptance signal

After cleanup:

- `aw mail send --to sofia` (and any other pair previously hit) from
  athena's CLI on this machine should succeed cleanly (no 409, fresh
  conversation created in a new conversation_id).
- `aw chat send-and-wait sofia` should open a new session_id and
  succeed cleanly (no 403, fresh signed payloads).
- `aw mail send --to hestia` should continue to attach to 96317ca9
  (the post-aame-binding conversation that was already working).
- The post-check counts return 0.

If any pair still 409s or 403s after cleanup, that's a NEW bug —
escalate.

## Why this is correct (architectural read)

The 1.20.1 design assumes participant rows have current identity
columns matching the actor's auth identity at preflight time, AND
assumes signed payloads bind their conversation_id. Pre-deploy data
violates both assumptions in places. Backfilling either is impossible
(re-signing requires the original sender's key, which is theirs not
ours). Closing the broken state and forcing fresh-start is the
clean migration path that doesn't require a permanent compat
carve-out in code.

Surgically closing only the affected mail conversations preserves
working pre-deploy threads (e.g., 96317ca9 hestia↔athena, which
post-dates aame's 1.19.0 first-class-conversation landing on
2026-05-04 evening, has properly-populated participant rows, and
works fine for sends in both directions). Blanket-closing all
pre-deploy conversations would lose those working threads
unnecessarily.

## Rollback

If a closed conversation turns out to be working and was closed in
error, reactivate it:

```sql
UPDATE aweb.conversations
SET status = 'active',
    closed_at = NULL,
    updated_at = NOW()
WHERE conversation_id = '<uuid>'
  AND status = 'closed';
```

Pre-aame chat session DELETE is not safely reversible — there is no
restore from soft-delete because the DELETE is hard. If a live
restore is needed, it would have to come from a pre-cleanup database
backup. Only run the chat DELETE if you're committed to losing
pre-aame chat history.
