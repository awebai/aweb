---
type: Decision
title: The agent event stream is push-driven
description: Writers record wakes in a scope owned by the outermost transaction and publish after its commit, never through the replaceable on_mutation hook; lost wakes are recovered by a 15 s reconcile that is one Redis MGET of change counters with no database statements when idle; a per-tick snapshot and Postgres change-mark triggers were rejected. Accepted, not yet on main.
tags: [decision, event-stream, wake, redis, performance, transactions]
timestamp: 2026-11-04
---

Ruled by the security and identity reviewer on 2026-11-04 in the push-driven stream design thread
(c3299855: design e7aa29ec, counters 586c8c9c, retry task b81ae05c). The
ruling followed a gate budget for idle streams: at most one round trip per
15 s and at most 0.1 ms CPU per stream-second.

**Status:** accepted; implemented on the source's review branch, not on main,
and not yet run in production. The figures below are a local bench.

# Decision

- **Publish after the outermost commit.** Writers record wakes in a scope that
  the owner of the outermost transaction opens. The scope publishes on normal
  exit, so a wake never announces a row a caller's transaction can still roll
  back.
- **Not through `on_mutation`.** An embedder can replace that hook, which
  would silently drop wakes.
- **Publisher failure is retried** by one process-wide task with coalesced
  keys and backoff capped at 5 s.
- **Reconcile reads counters, not Postgres.** Each wake also increments a
  per-(key, kind) Redis counter in the same pipeline as the publish. The 15 s
  reconcile is one `MGET` of those counters; a database snapshot is taken only
  for kinds whose counter moved. Order on open: subscribe, read counters, then
  snapshot, storing the pre-snapshot values; counters expire after 24 h and are
  compared by inequality.
- **Redis down:** the stream reconciles every 15 s only. There is no 1 s
  polling fallback, because it would recreate the CPU storm this design
  removed.
- **Residual loss** (a Redis fault together with process death) is bounded by
  the 300 s stream cap; accepted in the ruling.

# Rejected

- **A full database snapshot per reconcile:** about 25 statements per cycle,
  failing the one-round-trip gate by construction.
- **Postgres change-mark triggers:** they would cover a forgotten write site,
  but cost a migration plus write-path load and hot-row upserts on the very
  resource being freed. A forgotten site is instead a bug class guarded by a
  wake-latency test per write surface.

# Evidence

A bench against the Cloud app on TLS Postgres with statement cache 0: idle
stream 25.0 → 0.0 statements per stream-second, CPU 1.97 → 0.05 ms per
stream-second, mail write plus wake p50 7.7 ms.

This applies the aweb-cloud lesson that event consumers cover every write
surface, with a per-surface test for each write site, and refines it: counters
replace a database re-check as the backstop.

Related:
[stream wakes target the resolved identity](/aweb-protocol-expert/decisions/stream-wakes-target-the-resolved-identity.md),
[stream room authority is re-proved lazily](/aweb-protocol-expert/decisions/stream-room-authority-is-re-proved-lazily.md),
[a mounted app gets no lifespan](/aweb-protocol-expert/lessons/a-mounted-app-gets-no-lifespan.md),
[admission is not the effect transaction](/aweb-protocol-expert/lessons/admission-is-not-the-effect-transaction.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/stream-reconcile-redis-counters.md.
