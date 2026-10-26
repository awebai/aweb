---
type: Lesson
title: Evidence freshness must survive lock waits
description: Moving a remote authority lookup out of a transaction must not move the freshness decision before the wait; carry the producer's original expiry across the lock wait and check it after acquiring the lock, never restarting a window on receipt, cache hit or lock acquisition.
tags: [lesson, authority, freshness, concurrency, naapp]
timestamp: 2026-10-21
---

Moving a remote authority lookup outside a transaction solves network work
under a row lock, but opens a gap between observing the evidence and using it.
A queued row lock can consume the whole freshness window. The two-phase check
ruled for capability links on 2026-10-21 came with binding conditions from the
security reviewer: freshness comes from the facts' own expiry, never from call
time plus a fixed window, or a cache hit could stretch staleness to twice the
window; and the second phase reads the clock after acquiring the lock, through
an injectable clock.

# How to apply

- Carry the producer's original, scoped evidence and its expiry across the wait.
  Check it locally at the point of locked use.
- Never start a fresh window on receipt, cache hit or lock acquisition; that
  silently extends evidence the producer never renewed.
- The test must show the operation really waited on the database lock, advance
  the evidence clock during that wait, and check that it refuses afterwards. An
  already-expired input misses the ordering question, and sleeping without
  proving the lock wait leaves it ambiguous.

The mechanisms are in `docs/page-links.md` and `docs/app-registry.md`; this
records the design rule. The same gap appears in
[lock order in authority and approval transactions](/aweb-expert/lessons/lock-order-in-authority-and-approval-transactions.md)
("recheck after every blocking wait").

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-pages-design` (note
`authority-proof-ages-while-waiting.md`; security reviewer 68e1e1d0).
