---
type: Lesson
title: SSE cleanup is cancelled on client disconnect
description: Under uvicorn (ASGI spec 2.3) Starlette cancels the response task group on http.disconnect, so every await in an SSE generator's finally is cancelled too; cleanup must run under anyio.CancelScope(shield=True) or be synchronous.
tags: [lesson, sse, starlette, anyio, cancellation, chat]
timestamp: 2026-11-04
---

Discovered on 2026-11-04 while measuring wake latency. The failure is silent:
nothing errors, the cleanup simply never happens.

# What happens

uvicorn reports ASGI spec version 2.3 for HTTP, so Starlette's
`StreamingResponse` runs its disconnect listener in a task group and cancels
the stream when the client disconnects. The cancellation is anyio level
cancellation: every later await in that scope is cancelled as well, including
the awaits in the generator's `finally:`.

Observed effect: an instrumented chat SSE generator raised `CancelledError` at
the first await in its `finally`. The chat waiting entry was not removed, so
`sender_waiting` stayed true until the 90 s staleness cutoff after the waiter
had left, and the session pubsub was not closed.

# How to apply

- Wrap every await in an SSE generator's `finally:` in
  `anyio.CancelScope(shield=True)`, or keep that cleanup synchronous.
- Prove a new SSE cleanup with a test that disconnects the client and checks
  the cleanup's effect, not only that the stream closed. The chat fix carries
  such a test on the source's review branch.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-stream-push, 2026-11-04; notes/sse-finally-cancelled-on-disconnect.md.
