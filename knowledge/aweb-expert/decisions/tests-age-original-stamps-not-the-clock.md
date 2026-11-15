---
type: Decision
title: Tests age original stamps, never the clock
description: When an app test needs elapsed time against SDK evidence that keeps its own original timestamps, it moves every original stamp in the producer and the app back by the same amount; it never replaces a clock, fakes Redis TIME, or ages only the app's derived expiry.
tags: [decision, testing, timing, evidence, clocks]
timestamp: 2026-11-14
---

Ruled by the OSS coordinator on 2026-11-14 and agreed by the signer-boundary
seat, for an app test migration onto the shared SDK original-age evidence store.
That migration was later closed unrun when the code it tested was removed by an
architecture decision. The rule does not depend on that code: it applies to any
test of an app over an SDK store that owns evidence lifetime through original
timestamps.

# Decision

A test that needs time to have passed moves every **original** stamp back by
the same amount, in the producer and in the app alike:

- producer fetch starts and negative (refusal) epochs;
- back-off deadlines, keeping their failure counts;
- invalidation fences;
- the app's derived fact windows and its unknown-refresh stamps.

The elapse never moves:

- the clock-regression fence or high-water mark;
- admission capacity tokens, since moving them would claim capacity;
- scheduled or in-flight refreshes.

It never gives anything a new fetch start.

# Why

The SDK store, not the app, owns how old evidence is. A replaced module clock
ages only the app's copy while the store keeps its own original timestamps, so
the test runs in a world that cannot exist: the app believes time passed and
the store does not. Such a test passes or fails for the wrong reason. In the
case that prompted this, it could not run at all, because the product called a
clock method the fake lacked. Real sleeps were too slow: about 5 s per window
crossing across some 40 parametrized cases.

# Rejected

- **A replaced module clock**: ages only the app's copy.
- **Teaching the fake clock new methods**: keeps the impossible world and grows
  the fake with every product change.
- **A fake Redis TIME/EVAL**: fakes the store's clock instead of the app's, with
  the same split.
- **Keeping a removed cache tier alive for the test.**
- **Aging only the app's derived expiry**: the still-fresh producer serves the
  refresh, so the faulted read the test exists to exercise never happens.

# Precedent and limits

Moving stored timestamps instead of the clock is already how the naapp-lib
outbox tests age events and deliveries (`_age` in
`naapp-lib/tests/outbox/test_outbox.py` moves every timestamp of the selected
rows). This decision extends that from one store to a consistent elapse of the
whole app and its producer. An awid helper that ages revocation entries the
same way was cited as precedent, but on 2026-11-15 it existed only on unlanded
branches, not on main. The whole-app elapse helper itself never ran in a gate.

Related: [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md)
covers varying how long a failure takes; this decision covers how a test makes
time pass.

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-15; notes/age-original-stamps-not-the-clock.md.
