---
type: Decision
title: The agent event stream is push-driven
description: Writers record wakes in a scope owned by the outermost transaction and publish after its commit on every exit, never through the replaceable on_mutation hook; lost wakes are recovered by a 15 s reconcile that is one Redis MGET of change counters with no database statements when idle, and bookmarks advance only for kinds actually read; a hard writer crash is an accepted residue with a 2 s shutdown flush; a per-tick snapshot, Postgres change-mark triggers, a durable outbox and a periodic Postgres probe were rejected. On aweb main since the 2026-11-04 hot-path merge.
tags: [decision, event-stream, wake, redis, performance, transactions]
timestamp: 2026-11-04
---

Ruled by the security and identity reviewer on 2026-11-04 in the push-driven stream design thread
(c3299855: design e7aa29ec, counters 586c8c9c, retry task b81ae05c). The
ruling followed a gate budget for idle streams: at most one round trip per
15 s and at most 0.1 ms CPU per stream-second.

**Status:** accepted; on aweb main since the 2026-11-04 hot-path merge
(server 1.27.47rc1, a release candidate). This record does not show it running
in production. The figures below are a local bench.

# Decision

- **Publish after the outermost commit, on every exit.** Writers record wakes
  in a scope that the owner of the outermost transaction opens, so the scope
  closes only after that transaction ends. It publishes on every exit,
  exceptions included: a request can commit and then fail inside the scope,
  and dropping its wakes left the recipient waiting for the 300 s stream cap.
  A wake for a write that rolled back costs only one snapshot.
  - **The scope encloses the outermost transaction, not the inner call.** A
    wake published inside the transaction lets the stream take its snapshot
    before the row is visible. The stream still stores the moved counter, so
    the reconcile sees nothing new and the miss lasts until that kind's
    counter next moves. Eventual-reconcile tests do not catch this quickly.
    Any change that adds or widens a transaction on a write path must
    therefore move the scope outward to the new outermost transaction. This
    happened when a first mail send became one transaction for its
    conversation and first message. A per-request lent connection that opens
    no transaction does not change where the scope belongs.
  - **Testing publish-on-every-exit** needs a write that commits on its own
    before the failure, such as a continuation send. When a single-transaction
    write such as a first send fails, everything rolls back, so no wake is due
    and the test proves nothing.
- **Not through `on_mutation`.** An embedder can replace that hook, which
  would silently drop wakes.
- **Publisher failure is retried** by one process-wide task with coalesced
  keys and backoff capped at 5 s. The task runs only while wakes are pending
  (see [process helpers keep no idle tasks](/aweb-protocol-expert/lessons/process-helpers-keep-no-idle-tasks.md)).
- **Reconcile reads counters, not Postgres.** Each wake also increments a
  per-(key, kind) Redis counter in the same pipeline as the publish. The 15 s
  reconcile is one `MGET` of those counters; a database snapshot is taken only
  for kinds whose counter moved. Order on open: subscribe, read counters, then
  snapshot, storing the pre-snapshot values; counters expire after 24 h and are
  compared by inequality.
- **Bookmarks advance only for what was read.** Every snapshot also reads each
  kind whose counter moved, and the stream advances only the bookmarks of the
  kinds it actually read. Storing every counter after a single-kind snapshot
  absorbed another kind's lost publication.
  - A read bounded by a `LIMIT` keeps its kind pending while the batch comes
    back full.
  - A transient (5xx) failure of one kind's dependency is not an empty read.
    The kind stays pending, its bookmark is unmoved, and it is retried on its
    own backoff (capped at 5 s), so an outage of one kind's authority never
    ends the stream for the others. A 4xx refusal still shows nothing.
- **Redis down:** the stream reconciles every 15 s only. There is no 1 s
  polling fallback, because it would recreate the CPU storm this design
  removed.
- **Residual loss** (a Redis fault together with process death) is bounded by
  the 300 s stream cap; accepted in the ruling.
- **A hard writer crash is an accepted residue.** A writer process killed
  between commit and wake publication can delay the notification until the
  stream reopens or the recipient next reads. The data stays durable and
  readable. Graceful shutdown must flush pending wakes, bounded at 2 s.
  Ruled by the security and identity reviewer (R4, 1d846649).
- **Constraint on future work:** a later long-lived or resumable stream must
  keep a bound on hard-crash delay by comparing stored state on reconnect,
  never by a periodic probe.

# Rejected

- **A full database snapshot per reconcile:** about 25 statements per cycle,
  failing the one-round-trip gate by construction.
- **Postgres change-mark triggers:** they would cover a forgotten write site,
  but cost a migration plus write-path load and hot-row upserts on the very
  resource being freed. A forgotten site is instead a bug class guarded by a
  wake-latency test per write surface.
- **A durable outbox for wakes** (to cover a hard writer crash): it costs a
  write and a drain on every mail and chat write.
- **A periodic Postgres probe per connected agent** (same purpose): about C/60
  queries per second for C connected agents.

# Evidence

A bench against the Cloud app on TLS Postgres with statement cache 0: idle
stream 25.0 → 0.0 statements per stream-second, CPU 1.97 → 0.05 ms per
stream-second, mail write plus wake p50 7.7 ms.

The publish-on-every-exit rule (R1, cb615508), the bookmark rules and the
hard-crash ruling came from review of the implementation. Each was a real bug
or gap that green tests had not caught, and each now has a real-stack
regression test.

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
Recovery rules: second OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/stream-reconcile-redis-counters.md (revised).
Outermost-transaction scope and its test: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/wake-scope-encloses-outermost-transaction.md.
