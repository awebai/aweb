---
type: Decision
title: The protected-service client waits out throttling only within bounds it can justify
description: aw retries a 429/503 from a protected service only on an explicit delta-seconds Retry-After, waits max(poll, hint) checked against the operation's recorded expiry or aw's own invocation bound, runs every attempt under that bound and rechecks it after waking, and resends a throttled prepare with identical bytes.
tags: [decision, aw, protected-operations, retries, throttling, deadlines]
timestamp: 2026-11-12
---

How aw's protected-service client recovers when the service throttles it.
The case that forced this was a Resume POST for a changed act. The service
answered 503 with a 13 s hint (lane run 22, red). The first fix was NACKed in
review (R d4831e18). The fix that passed review is a5284ec94 (R SOURCE ACK
1fc42b35). Deploy-team run 24 at c14a8a827 exercised it against the
registry's real limiter, with hints of 47 s and 56 s. The control run with the
previous CLI failed.

# Decision

- **Only an explicit delta-seconds `Retry-After` is a hint.** A malformed
  value means no hint, so a generic 503 at prepare stays a refusal.
- **An overflowing value saturates.** A value too large for a duration
  becomes the maximum duration, so it fails the deadline check instead of
  wrapping.
- **The wait is max(poll interval, hint)**, so a zero hint cannot spin.
- **Durations are compared, never added to a time**:
  `wait >= expiry.Sub(now)`, never `Time.Add(huge)`, which can wrap.
- **There are two clocks, and aw keeps them apart:**
  - the service's frozen `expires_at`, once aw knows it;
  - before that, aw's own invocation bound (`RetryWithin`), shared by
    prepare and by reconciling a lost answer.
  - aw never makes up an operation deadline.
- **Every attempt runs under the bound** (`context.WithDeadline(until)`), and
  the bound is checked again after each wait.
- **A throttled prepare is resent with identical bytes.** The service's
  same-id, same-body rule answers the original operation. A changed body is
  still a conflict, so the changed-act case ends in `operation_conflict`, not
  in a silent replacement.

# Rejected

- **Bounding only the waits** (rejected in review). A hanging request or an
  oversleep outlives the bound. That is why every call runs under the deadline
  and the bound is rechecked after waking.
- **Waiting the raw hint** (`pause(hint)`). A zero hint made the loop spin.

# Evidence limits

Request markers in unit tests prove fresh calls, not that the signer acted
once. Only the joined journey's signer audit proves a single signature.
Treat a green unit suite here as evidence about requests, not about effects.
[Elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md)
applies: test with realistic hints, not only instant answers.

**Status (verified by the harvester 2026-11-12):** a5284ec94 is on the branch
`agents/aweb-expert-owner-acts-roundtrip`, not on main at 88fbf7b4f.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-12;
notes/protected-client-throttle-recovery.md. The review verdicts and lane
runs are the source's report.
