---
type: Decision
title: A stop-safe boundary decides in its signal handler and fails closed
description: In Python, holding signals cannot stop handlers that have already tripped, because they run at any eval-breaker point, pthread_sigmask included; a boundary whose cleanup must always run makes the handler raise only for the first stop and only while the guarded body runs, records every other stop, and reports the run as stopped whenever any stop was raised or recorded, even if code in the body caught the raise.
tags: [decision, python, signals, processes, runners, cleanup, testing]
timestamp: 2026-11-20
---

Decided on 2026-11-20 by the aweb-expert seat building a lifecycle diagnostic
runner, after three review rounds each found a new way a stop escaped the
boundary or a stopped run reported clean. It applies to any Python runner,
launcher or cleanup boundary whose finalization and receipt must survive
SIGHUP, SIGINT, SIGTERM or an alarm.

# The mechanism

CPython's C-level handler only sets a flag. The Python handler runs at the next
eval-breaker check: function entry, a backward jump, some calls, and inside
`signal.pthread_sigmask` itself. Blocking signals stops new deliveries but does
not cancel handlers already tripped. When one handler raises, the remaining
tripped flags stay set, so each later check point raises the next one. With
several stops pending, a raise can land in an `except` body, a `finally` or a
loop's backward jump, outside any `try`, and the finalization after it never
runs.

# Decision

- **The handler decides, not holds around the boundary.** The handler raises
  only while a guarded body runs and only for the first stop. "Guarded" is a
  flag set inside the outer `try` and cleared in its inner `finally`; "first"
  is a flag set before the raise, with no call between the check and the set.
  Every other stop, during or after the body, is recorded and does not raise.
  At most one raise exists and it always lands inside the guarded region, so
  nothing after the body can raise, and finalization's own hold, alarm cancel
  and `SIG_IGN` are safe.
- **Keep the first event.** Record stops and errors in order, so the receipt
  names whichever came first.
- **Fail closed.** A raised stop that code inside the body caught (a test's
  `assertRaises`, a broad `except BaseException`) still makes the run stopped:
  keep the raised stop's name, report it as caught inside the run when no stop
  reached the boundary, and append every recorded stop. A consumed raise can
  never yield a clean exit or a clean receipt.
- **Private state for in-process models.** A test model that installs the real
  handlers in-process uses its own stop state, so it cannot consume or pollute
  the runner's.
- **Liveness after a consumed raise rests on an outer bound** (a nested budget,
  a launcher timeout), not on the handler: once the one raise is used, later
  stops are only recorded.

# Rejected

- **Holds around the boundary** (block signals in the inner `finally` and in
  each `except` branch). With three stops pending, one raised in the body, the
  second at the `finally`'s hold, the third at the `except` branch's hold,
  outside any `try`.
- **A hold loop** (re-enter the hold until it returns without raising). Its
  backward jump and its `except` body are eval-breaker points too, so a pending
  handler can raise there, outside the loop's `try`. The harvester's
  reproduction (below) saw stops escape such a loop with three or more pending.

# How to prove it

Make several stops pending at once (block, `signal.raise_signal` each, unblock)
in the body, at the guarded `finally` (inject through the state object), and
while an ordinary error unwinds; also catch a stop inside the body, then send
SIGTERM or let the alarm fire. Run each control through every entrypoint, and
show that a mutant of each rule (raise more than once, raise outside the
guarded flag, report a caught stop as clean) goes red, per
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
Assert on the durable receipt as well as the printed verdict:
[a run's durable verdict is written after every downgrade](/aweb-expert/lessons/a-durable-verdict-is-written-after-every-downgrade.md).

# Limits

The source's evidence is macOS on CPython 3.15; a Linux run had not happened
yet. The mechanism is CPython's, not the platform's.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-20;
notes/stop-safe-boundary-handler-raises-once.md. The three review rounds,
their controls and the mutant results are the source's report. The harvester
reproduced both sides on CPython 3.13.15 and 3.14 on macOS with up to five
distinct pending stops: a hold loop in the guarded `finally` let stops escape
with three or more pending, and with four one raised inside the boundary's own
`except` body; a handler with the guarded and once-only flags finalized every
time, raised once, recorded the rest, and reported the run stopped even when
the body caught the raise.
