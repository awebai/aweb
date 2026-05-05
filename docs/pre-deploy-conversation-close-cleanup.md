# Pre-deploy conversation close — one-time cleanup (post-1.20.1 / v0.5.22 follow-up)

This is the second-pass operational cleanup, complementing
`duplicate-1to1-conversation-cleanup.md`. The duplicate-1to1 collapse
already ran during the v0.5.22 cutover (211 conversations across 16 pairs,
collapsed to one most-recent active per pair).

The verified-live smoke probes after deploy attached cleanly to a
freshly-created conversation (post-deploy hestia↔athena, conversation
`96317ca9`). But sends and chats touching the *cleanup-preserved
pre-deploy* conversations surface two distinct bugs:

1. **Mail 409 on send between pairs whose preserved active 1:1
   conversation was created pre-deploy.** Server's
   `_existing_mail_conversation_for_target` finds the conversation and
   409s ("Existing active conversation found; continue that conversation
   instead"), but the CLI's `/v1/conversations` preflight doesn't surface
   that conversation in a form `mailConversationMatchesTarget` matches —
   so the CLI sends fresh, hitting server dedup. Same A.6a-shape, but on
   pre-existing data not exercised by Hestia's freshly-created smoke
   conversations.

2. **Chat 403 on continuation of any pre-aame chat session.** Server's
   1.20.1 W3 protection rejects continuation when "the latest signed
   message does not bind conversation_id". Pre-aame chat messages were
   signed without `conversation_id` in the signed payload, so the check
   fails. Affects every chat session whose latest message predates
   aame W3 binding.

Both reduce to: pre-deploy conversation/session state is incompatible
with post-1.20.1 code paths. Backfilling signed payloads is impossible
(original signing keys aren't ours). The clean fix is to close
pre-deploy active conversations + expire pre-deploy chat sessions.
Customers retain history (closed conversations remain readable via
`mail show <conversation_id>`); the next send between any pair starts a
brand-new conversation that's fully visible to the new code paths and
cleanly bound.

## When to run

Post-deploy, ideally during the same no-traffic window the duplicate-1to1
cleanup ran in. If that window has already closed and customers are
sending traffic, run during the next quiet window — current state is
"pre-deploy pairs hit 409/403, post-deploy pairs work" which is
visible to anyone who tries to continue an existing thread.

## Pre-check (read-only)

```sql
-- Count what the cleanup would touch.
SELECT
    'mail conversations to close' AS category,
    COUNT(*) AS rows
FROM aweb.conversations
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at < '2026-05-05T21:27:26Z'

UNION ALL

SELECT
    'chat sessions to expire',
    COUNT(*)
FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z'
  AND (expires_at IS NULL OR expires_at > NOW())

UNION ALL

SELECT
    'mail conversations untouched (post-deploy)',
    COUNT(*)
FROM aweb.conversations
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at >= '2026-05-05T21:27:26Z'

UNION ALL

SELECT
    'chat sessions untouched (post-deploy)',
    COUNT(*)
FROM aweb.chat_sessions
WHERE created_at >= '2026-05-05T21:27:26Z'
  AND (expires_at IS NULL OR expires_at > NOW());
```

The first two rows tell you the scope of closure. The last two tell you
how many post-deploy conversations/sessions exist and would be left
untouched (sanity check — should be small at dogfooding scale, since
the only post-deploy traffic so far is Hestia's smoke probes plus
whatever's happened between deploy and the run window).

## Close + expire (atomic)

Replace the timestamp below with the actual deploy time. From
`app.aweb.ai/health`'s `started_at` field at the moment of cutover:
**2026-05-05T21:27:26Z**.

```sql
BEGIN;

-- 1. Close all pre-deploy active mail conversations.
--    Closed conversations remain readable but are not considered
--    "active 1:1" by the dedup logic, so the next send between a
--    pair creates a fresh conversation cleanly.
UPDATE aweb.conversations
SET status = 'closed',
    closed_at = NOW(),
    updated_at = NOW()
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at < '2026-05-05T21:27:26Z';

-- 2. Expire all pre-deploy chat sessions.
--    The CLI's shouldProbeExistingSession only finds non-expired
--    sessions, so chat resumption opens a new session_id with
--    properly-bound signed payloads. The W3 continuation check
--    never sees legacy un-bound messages.
UPDATE aweb.chat_sessions
SET expires_at = NOW(),
    updated_at = NOW()
WHERE created_at < '2026-05-05T21:27:26Z'
  AND (expires_at IS NULL OR expires_at > NOW());

COMMIT;
```

## Post-check

```sql
-- Should both be 0.
SELECT
    'pre-deploy active mail conversations remaining' AS category,
    COUNT(*) AS rows
FROM aweb.conversations
WHERE conversation_type = 'mail'
  AND status = 'active'
  AND created_at < '2026-05-05T21:27:26Z'

UNION ALL

SELECT
    'pre-deploy non-expired chat sessions remaining',
    COUNT(*)
FROM aweb.chat_sessions
WHERE created_at < '2026-05-05T21:27:26Z'
  AND (expires_at IS NULL OR expires_at > NOW());
```

## Rollback

If the cleanup turns out to be wrong (it shouldn't, but in case):

```sql
BEGIN;

-- Reactivate mail conversations closed by THIS cleanup specifically.
-- Match by closed_at near the cleanup timestamp.
UPDATE aweb.conversations
SET status = 'active',
    closed_at = NULL,
    updated_at = NOW()
WHERE conversation_type = 'mail'
  AND status = 'closed'
  AND created_at < '2026-05-05T21:27:26Z'
  AND closed_at >= '<cleanup-run timestamp>';

-- Re-extend chat sessions that were expired by this cleanup.
-- This is best-effort; if 30 days have already passed since the original
-- last-message activity, the conversations would have lazy-expired
-- under the standard TTL anyway. So extending to NOW + 30d is safe.
UPDATE aweb.chat_sessions
SET expires_at = NOW() + INTERVAL '30 days',
    updated_at = NOW()
WHERE created_at < '2026-05-05T21:27:26Z'
  AND expires_at >= '<cleanup-run timestamp>'
  AND expires_at < '<cleanup-run timestamp>' + INTERVAL '1 minute';

COMMIT;
```

The rollback is bounded by `closed_at` / `expires_at` falling within
the cleanup window — that distinguishes "closed by this run" from
"closed legitimately by user action or prior cleanup."

## Why this is correct (architectural read)

Two distinct mechanisms in 1.20.1 have a hard incompatibility with
pre-deploy data:

- **One-active-1:1 dedup** (server `find_active_one_to_one_conversation_between`,
  routes/messages.py:797-801): legitimate guard, but assumes the CLI
  preflight surface (`/v1/conversations`) returns the conversation in a
  form the CLI can match. Pre-deploy conversation_participants rows may
  have stale identity columns (did before rotation, address before
  managed-namespace bind, agent_id before ac-side migration) that don't
  match the actor's *current* auth identity in the participant index.
  The new `find_active_one_to_one_conversation_between` is more lenient
  (matches by did OR agent_id OR address); the listing path in
  routes/conversations.py is constrained by the messages-table JOIN
  surface. Closing legacy conversations sidesteps the asymmetry.

- **W3 cross-conversation replay protection** (server-side check on the
  latest signed message): assumes every signed payload binds the
  session's conversation_id. Pre-aame messages don't, by construction.
  Cannot be backfilled (would require re-signing with the original
  sender's key, which isn't ours). Forcing fresh sessions for
  resumption gives the W3 check only post-aame messages to evaluate.

Both are one-time data issues, not code bugs. The architectural
decision is to *not* add a permanent compat carve-out (e.g., "exempt
messages older than X from the binding check") for what's actually
a one-shot migration cost.

## Acceptance signal

After this cleanup runs:

- `aw mail send --to <peer>` between any two prod participants who had
  a pre-deploy conversation should succeed (no 409, fresh conversation
  created). Verify with one or two test pairs.
- `aw chat send-and-wait <peer>` likewise should succeed (new
  session_id, fresh signed payloads).
- The post-check counts return 0.

If any of those still fail, that's a NEW bug — escalate.
