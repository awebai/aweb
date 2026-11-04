---
type: Decision
title: Per-request facts live in the request memo, never in a cache
description: Facts a request reads once (the auth snapshot, Cloud's sender-billing snapshot) are shared through the connection scope's request memo, which closes at response start; each reader uses it only for the exact key the snapshot read and otherwise queries, and there is no cross-request cache. Reviewed, not yet landed on main.
tags: [decision, database, caching, request-lifecycle, auth, billing]
timestamp: 2026-11-04
---

The rule is "no cache, one read per request". A fact several parts of one
request need is read once and shared through the memo of the request's
connection scope. The next request reads afresh, so a retirement, a removal or
a billing change takes effect on the next request.

# Decision

- **The memo lives in the connection scope.** `request_memo()` returns it
  while the scope is open and `None` after. The scope closes when the response
  starts, so a streaming body, a background task, outbox recovery or anything
  else that outlives the request reads afresh. The reviewer's condition was
  that the memo be unusable after response start.
- **A reader answers from the snapshot only for the exact key it read** (for
  the auth snapshot: agent, org, team key form and team row) and otherwise
  queries as before. Callers outside a request (scheduler, recovery, admin)
  are therefore unchanged.
- **Uses so far:** the auth snapshot, and Cloud's sender-billing snapshot,
  which the pre-send limit check and the post-commit metering hook share.

# Rejected alternatives

- **A per-process cache with invalidation.** Ruled out by the reviewer
  ("no cache"). Invalidation would have to track every way an agent, team or
  billing fact can change.

A future consolidation that needs a fact more than once per request reuses
the memo instead of introducing a cache.

**Status (2026-11-04):** the memo is OSS commit 09570a577 and the billing use
is Cloud commit 681bedd98, both reviewed by the auth/data reviewer as the
source reported; neither is on main. The memo extends the per-request
connection scope from the same seat, which was itself still in review.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/request-memo-for-per-request-facts.md.
