---
type: Lesson
title: Elapsed time is a test input
description: Vary how long a failure takes, not only what it returns: a fast failure hid a retry storm that a realistic ten-second failure exposed, and a fixed wall-clock barrier failed only on slow hosts; inject latency into the test's own stub to reproduce, then wait on progress with a stall bound and a cap.
tags: [lesson, testing, timing, retries, flaky-tests]
timestamp: 2026-11-13
---

Two investigations where duration, not response, decided the outcome.

- **Retry windows.** A failure-coalescing test passed with an immediate upstream
  refusal. With a failure lasting about as long as the real verifier timeout,
  every waiting caller retried, because the cooldown was measured from fetch
  start and the failed fetch had consumed it. Sixteen requests retried a fetch
  that should have been tried once.
- **Fixed barriers.** A release candidate failed once on a test that bounded
  out-of-process work with a fixed wall clock. Fifty loaded runs, an
  oversubscribed container and the release runner itself never reproduced it.
  A slowed stub for the second cycle reproduced the exact message, line and
  timing in one run.

# How to apply

- For time-sensitive recovery, vary failure duration across the policy window
  and assert an observable result: upstream call count, recovery after the
  window.
- Keep a refusal cooldown (timed from when a failure completes) separate from
  the age of verified facts (timed from when they were fetched); suppressing a
  retry must not renew old facts.
- When load does not reproduce a timing flake, inject latency into the test's
  own stub until it is red deterministically, then wait on progress: fail on a
  stall plus an absolute cap, not on total elapsed time.
- Injected latency proves the particular premature barrier it removes. Fifty
  isolated passes do not clear a failure seen in a full repeated matrix, and do
  not explain every later timeout.
- A test that holds a lock across a fixed "is the other side still waiting?"
  sleep also races the waiter's server-side timeouts, which the test never
  names. The aweb test database pool runs with a 5000 ms `lock_timeout` (awid's
  database configuration defaults), so a host stall during the hold made
  Postgres cancel the waiter (`LockNotAvailableError`) and the probe failed.
  Prove the block in the database, not by elapsed time: wait until
  `pg_blocking_pids(waiter)` contains the holder, release at once, and run the
  waiter with `SET LOCAL lock_timeout = 0` so only the test's named bounds
  decide. When a database test fails once under load, look for server-side
  timeouts on the blocked side.

Related: [acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-data` (note
`failure-latency-is-a-test-input.md`; verify NACK decb0233) and seat
`aweb-protocol-expert-agent-activity` (note `flake-repro-by-injected-latency.md`).

Evidence: OKF proposal from aweb-expert/aweb-expert-wake-fixes, 2026-11-13;
notes/lock-hold-probe-races-the-waiters-lock-timeout.md. A loaded
session-sequence test failed once. Sixty loaded runs never reproduced it; a
deterministic 5.5 s event-loop stall during the hold did, and the fixed test
passes that stall and 60/60 loaded runs. The original traceback was not kept,
so the mechanism is the reproduced one consistent with the failure, not a
captured trace of it.
