---
type: Lesson
title: Reproduce an ordering flake by stress, not by a gate
description: When the bug is "A is not ordered before B", a gate that holds A makes the old code red but hangs a correct fix, which must wait for A, so no deterministic both-ways test exists without a timeout or stack inspection; reproduce with a race build at low GOMAXPROCS and a bounded -count, and classify failures by message, because loopback runs that exhaust macOS ephemeral ports look like reproductions.
tags: [lesson, testing, flaky-tests, go, concurrency]
timestamp: 2026-11-27
---

A Go loopback test failed about once in 2,000 runs because a listener's close
was not ordered before the waiter returned: the accepted response could be cut
off by an asynchronous close.

# Why a gate does not work

Holding the close behind a test gate makes the old code red every time. A
correct fix, though, makes the waiter block on that same close, so with the
gate held the fixed code hangs. Only a timed release could free it, and a timed
release is a sleep. Nothing observable separates "blocked" from "slow" without
a timeout or inspecting goroutine stacks. For an ordering bug there is no
deterministic test that is red before the fix and green after it.

This is the limit of [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md):
injected delay reproduces a premature barrier, which a fix removes, but it
cannot be made to pass a fix that correctly waits.

# What worked

- The `-race` build changes scheduling enough to raise the rate. With
  `GOMAXPROCS=2` and `-count=4000`, 258 iterations failed before the fix (about
  6%) and 0 of 12,000 after. A plain build failed 11 of 20,000 before.
- Keep `-count` bounded and repeat runs rather than making one huge run.

# The trap: port exhaustion looks like reproduction

Each loopback iteration uses an ephemeral port, and macOS's range is about
16,000 ports. One 20,000-iteration run produced about 1,700 "failures" that
were `can't assign requested address`, not the bug. Classify every failure line
by its message before counting it as a reproduction; this is the rule of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
that a red counts only if its text names the property.

# Limits

Seen on one flake, on macOS. The rates are source-reported; the harvester did
not rerun them. The iteration count at which ports run out depends on how many
connections each iteration opens and how fast closed ports leave TIME_WAIT.

Evidence: OKF proposal from aweb-expert/aweb-expert-release-flakes, 2026-11-27; notes/ordering-flake-repro-needs-stress-not-a-gate.md. Gate run vm-c233588b for server-v1.27.56; fix 5393ff902e, red at 138bdd540a.
