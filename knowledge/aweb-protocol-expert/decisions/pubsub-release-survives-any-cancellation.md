---
type: Decision
title: A PubSub release survives any cancellation
description: Stream subscribers open and release Redis PubSubs through aweb.redis_subscriptions, whose release runs as its own strongly referenced task awaited under asyncio.shield inside an AnyIO shield and, when aclose fails, deregisters the reconnect callback, clears the channels and returns the connection itself; an AnyIO shield alone was rejected because a native asyncio task.cancel() still interrupts it.
tags: [decision, redis, pubsub, cancellation, anyio, asyncio, connections]
timestamp: 2026-11-06
---

Pooled Redis connections were leaking from event and chat streams. Two facts,
neither visible in the code that leaked, explain why.

# Discoveries

- **redis-py's `PubSub.aclose` disconnects before it releases the connection to
  the pool** (observed on redis-py 7.1). A cancellation during that disconnect,
  or a `TimeoutError` raised by it, leaves the lease checked out for good. An
  interrupted `aclose` also skips deregistering `on_connect` and clearing
  `channels`, so the connection's next reconnect resubscribes the dead PubSub
  through a newly checked-out connection (measured: one lease held after a PING
  reused the connection).
- **`anyio.CancelScope(shield=True)` stops only AnyIO cancellation.** It
  protects against cancel-scope cancellation, which is what Starlette's response
  task group uses on client disconnect. A native asyncio `task.cancel()` still
  raises `CancelledError` inside the shielded block. A shielded release
  cancelled that way stranded one lease (measured against real Redis).

# Decision

- Every per-stream subscriber opens and releases through
  `aweb.redis_subscriptions`.
- The release runs as its own task, kept in a module-level set because the
  event loop holds only weak references to tasks. The caller awaits it under
  `asyncio.shield` inside `anyio.CancelScope(shield=True)`: the AnyIO shield
  makes the normal path wait for completion, and `asyncio.shield` lets the task
  finish if the caller is natively cancelled.
- If `aclose` raises, the release itself deregisters `on_connect`, clears the
  channels and patterns, and returns the connection to the pool.

**Rejected:** an AnyIO shield alone. It covers client disconnect and leaks on
any native cancellation, so the leak returns under the next caller that cancels
a task directly. This is the limit of the advice to wrap SSE cleanup in an AnyIO
shield ([SSE cleanup is cancelled on client disconnect](/aweb-protocol-expert/lessons/sse-cleanup-is-cancelled-on-disconnect.md)): that is enough for Starlette's disconnect, not for cleanup that must
finish whoever cancels it.

**Open point:** the process-level agent wake subscriber in
`server/src/aweb/agent_wake.py` still creates its PubSub directly and closes it
with a bare `aclose` (aweb main at 07f1c8f0c). The decision as landed names
streams; whether it covers that subscriber is not ruled.

# Evidence

Twelve real-Redis lease tests in `server/tests/test_pubsub_lease_ownership.py`
(nine functions, three parametrized twice), each red before the fix, which was
reviewed and landed as 5bce5814c. The harvester checked the module and tests
against aweb main at 07f1c8f0c.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/anyio-shield-does-not-stop-task-cancel.md.
