---
type: Lesson
title: Advance a fake clock only on client-observed bytes
description: A real-socket stream client can be driven on node:test mock timers only if every clock advance waits for client-side evidence that the previous bytes were read, real-time waits use performance.now because Date is mocked, and listener leaks are counted with events.getEventListeners on the captured session signal rather than inferred from the MaxListeners warning.
tags: [lesson, testing, timing, node, mock-timers, streams]
timestamp: 2026-11-27
---

Learned on 2026-11-27, testing the built Pi extension's stream client against
an owned 127.0.0.1 event server with `mock.timers` on `setTimeout` and `Date`:
a stream closes at its requested deadline, a stream silent for 75 s is closed
and retried, and settled 503 backoffs leave no abort listeners behind. Each
obvious approach failed first.

# What failed, and what worked

- **A `Date.now()` wait loop never ends**, because Date is the fake clock.
  Real-time waits use `performance.now()` and a saved real `setTimeout`.
- **Ticking right after a socket write races the client's read**, and makes
  the watchdog look broken. Writing bytes is not evidence the client read
  them. Advance only after a client-side observation: here the client's own
  receive receipt records its heartbeat time from the fake clock, so "receipt
  time equals fake now" shows the read happened.
- **Backoff with unknown jitter:** tick in 1 s steps until the next request
  arrives, with a step bound.
- **The MaxListeners warning is not an oracle**; the reviewer rejected it as
  unreliable. Capture the session AbortSignal at the host boundary (wrap
  `globalThis.AbortController` for the one construction the session start
  makes, then restore it), and read `events.getEventListeners(signal, "abort")`
  at the same point in every cycle. No product hook is needed.
- **Teardown in `finally`:** reset the mock timers before shutdown (a pending
  fake timer would deadlock it), await the session shutdown, close the server
  and wait for every socket's close event.
- Capture and assert the client's `console.warn` state lines so the test
  output stays pristine.

This is the fake-clock form of waiting on progress in
[elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md):
each step waits for evidence, not for time.

# Limits

The observation point (the receive receipt) is specific to this client.
Another client needs its own evidence that it read the bytes. Seen in one
client; three consecutive clean runs.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/fake-clock-against-real-sockets.md. The harvester read
`scripts/typescript-dist/pi_bundle.test.mts` in commit 3686733463 (E8.1
follow-up branch, not yet on main): it enables mock timers on `setTimeout`
and `Date`, waits on `performance.now()`, and counts listeners with
`getEventListeners`. The race, the hanging Date loop, the reviewer's
rejection of the warning and the clean runs are source-reported.
