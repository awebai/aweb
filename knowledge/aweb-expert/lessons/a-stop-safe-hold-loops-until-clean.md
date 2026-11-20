---
type: Lesson
title: A stop-safe hold loops until it returns cleanly
description: In CPython, blocking signals does not cancel Python handlers whose C-level flags have already tripped, so a hold-then-catch-once handoff escapes when several distinct stops are pending; re-enter the hold in a loop until it returns cleanly, and test with several distinct pending signals at once.
tags: [lesson, python, signals, processes, testing, review]
timestamp: 2026-11-20
---

Learned on 2026-11-20 while reviewing a stop-safe finalization in a lifecycle
diagnostic. The pattern looked correct and passed one-stop and two-stop
controls. It still lost its cleanup and its final receipt.

# The mechanism

CPython's C-level signal handler only sets a flag for the signal. The Python
handler runs later, when the interpreter checks for signals: at an eval-breaker
check, or in `PyErr_CheckSignals`, which `signal.pthread_sigmask` itself calls.
When one Python handler raises, the flags of the other tripped signals stay
set, so the next check point raises again.

`pthread_sigmask(SIG_BLOCK, ...)` stops new deliveries. It does not cancel the
handlers that have already tripped, and the call that blocks is itself a check
point. A "hold, then catch the stop once" handoff therefore survives a few
pending stops but not several. A raise inside the `except` clause that re-holds
escapes that clause, and the finalization after it never runs.

# How to apply

- Re-enter the hold in a loop and leave the loop only when the hold returns
  without raising. Only then is no handler tripped while every stop is blocked.
- Do not rely on installing `SIG_IGN` after the first stop is caught. In the
  harvester's reproduction, setting the disposition was itself a check point,
  and the next tripped handler raised from inside it.
- Test with several distinct pending signals at once: block them, send each
  one to yourself, then unblock inside the guarded body. One stop injected at a
  single point does not test this.

A stop handler that runs cleanup is a control that must be shown to fail:
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
applies, and the multi-signal control above is the red it needs.

# Limits

The source's model ran the reviewed `finalized()` on CPython 3.15 on macOS:
one or two pending stops were caught; with three (SIGTERM, SIGINT, SIGHUP),
the stop escaped and the finalization ran zero times. How many stops a given
handoff survives depends on how many check points it has, so the count is
specific to that code. The harvester reproduced the mechanism on CPython
3.13.15 on macOS with a simpler single-catch handoff, which already escaped
with two pending stops, and saw the hold loop finalize with one, two and three.
The mechanism is CPython's, not the platform's.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-20; notes/held-signals-do-not-cancel-tripped-python-handlers.md. The
review of the diagnostic and its three-stop result are the source's report.
The harvester's CPython 3.13.15 reproduction of the mechanism, the loop and the
failed `SIG_IGN` variant is described under Limits.
