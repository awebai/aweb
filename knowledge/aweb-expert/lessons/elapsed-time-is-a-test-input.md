---
type: Lesson
title: Elapsed time is a test input
description: Vary how long a failure takes, not only what it returns: a fast failure hid a retry storm that a realistic ten-second failure exposed, and fixed wall-clock barriers failed on slow or contended hosts; inject latency into the test's own stub to reproduce, order processes on a readiness signal, and wait on progress with a stall bound and a cap.
tags: [lesson, testing, timing, retries, flaky-tests, harness]
timestamp: 2026-11-25
---

Three investigations where duration, not response, decided the outcome.

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
- **Sleep as a process barrier.** A gate harness step slept one second before
  stopping a database, assuming a worker had opened its connection pool by
  then. Once the gate's lanes ran without CPU caps and contended for CPU, the
  worker met the stopped database at pool creation and failed with a pool
  error instead of the fail-closed 503 the step asserts. A forced delay
  reproduced it red; a readiness line made it green.

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
- Never order two processes with a fixed sleep. Have the process emit a real
  readiness signal once the resource is open (for example a stderr line after
  its first successful query), hold it on an explicit release (for example a
  read on stdin) until the harness has acted, and wait for the signal with a
  bounded wait that fails loudly if the process exits or stays silent. Replace
  such sleeps before a run, not after one goes red: any change that adds
  contention, such as removing CPU limits, shrinks every sleep's margin at once.

Related: [acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md),
and [a zombie counts as gone in ps](/aweb-expert/lessons/a-zombie-counts-as-gone-in-ps.md)
for the matching mistake when proving a process ended.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-data` (note
`failure-latency-is-a-test-input.md`; verify NACK decb0233) and seat
`aweb-protocol-expert-agent-activity` (note `flake-repro-by-injected-latency.md`).

Evidence (sleep as a process barrier): OKF proposal from
aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/sleep-barrier-under-contention.md. Gate run vm-3501ee54 (task aweb-adyd)
red; green in vm-06bed6ed and vm-b3ec44c0; fixed at aweb fcbc8d9bd1. One run
per observation.
