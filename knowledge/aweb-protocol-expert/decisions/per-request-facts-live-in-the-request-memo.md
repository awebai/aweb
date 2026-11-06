---
type: Decision
title: Per-request facts live in the request memo, never in a cache
description: Facts a request reads once (the auth snapshot, a host's sender-billing snapshot) are shared through the connection scope's request memo, which closes at response start; each reader uses it only for the exact key the snapshot read and otherwise queries, and there is no cross-request cache. On main and in server-v1.27.47.
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
- **Uses so far:** the auth snapshot, and a host's sender-billing snapshot,
  which the pre-send limit check and the post-commit metering hook share.

# Rejected alternatives

- **A per-process cache with invalidation.** Ruled out by the reviewer
  ("no cache"). Invalidation would have to track every way an agent, team or
  billing fact can change.

A future consolidation that needs a fact more than once per request reuses
the memo instead of introducing a cache.

**Status (verified 2026-11-06):** the memo is on main (72b7a7281) and first
released in server-v1.27.47; the auth/data reviewer reviewed it, as the source
reported. The billing use lives in the embedding host's code and is not checked
here. The memo extends
[one connection per request](/aweb-protocol-expert/decisions/one-connection-per-request-is-lent-never-a-transaction.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/request-memo-for-per-request-facts.md.
