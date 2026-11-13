---
type: Lesson
title: A cross-key invariant needs a home-wide lock and a recheck under it
description: When a local command's refusal rule covers the whole home rather than one key, decide read-only, do the slow checks unlocked, take a home-wide cross-process lock, then decide again and record under it; a per-key lock cannot see the conflict, and partial on-disk state counts.
tags: [lesson, concurrency, aw-cli, identity, testing]
timestamp: 2026-11-13
---

Learned on 2026-11-13 building `aw id team install-cert`, whose rule is that a
local identity home holds one team's membership only. The rule was checked,
then the registry was read, then the certificate was written. Two installs of
*different* teams' certificates into one home both passed the check, and both
were recorded. It took three review rounds to find each gap in turn: the
cross-team case, then partial on-disk state, then the race. The fix (3106f6fb0,
on main) decides the home's status again under a home-wide lock.

# The rules

For a local command that must refuse before it writes, where the refusal rule
is about the whole home rather than one key:

1. **Decide read-only first**, so a sequential refusal leaves the home as it
   was: no lock file, no state.
2. **Do the slow checks outside any lock**, for example registry reads.
3. **Take a lock as wide as the invariant**: home-wide and cross-process (a
   lock file in the home), not per key. The contenders that break a cross-key
   invariant hold different keys, so a per-key lock never sees them collide.
4. **Decide again under the lock, and record while holding it.**

- **Partial on-disk state counts in the decision.** A certificate file with no
  membership row, or a membership row with no certificate file, is a home that
  already holds that team. Both halves must be read.
- **Rejected: a per-team lock** (it cannot see the conflict), and **removing
  the lock file after success** (Windows cannot remove an open file).

# Testing the race

Only a barrier reproduces it. The test holds both contenders at the slow
registry lookup until both have passed the first read-only decision, then
releases them; it asserts exactly one installed, one refused and one stored.
Before the fix it failed with two installed and two stored, and a mutation of
the fix was caught. Without the barrier the race does not reproduce, and the
test is not evidence (see
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).
The rule to recheck after every blocking wait is the same one recorded for
database transactions in
[lock order in authority and approval transactions](/aweb-expert/lessons/lock-order-in-authority-and-approval-transactions.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/cross-key-invariant-needs-home-wide-lock.md. Commit 3106f6fb0 is on main;
its message describes the read-only decision and the home-wide lock, and its
test `TestConcurrentInstallsOfTwoTeamsIntoOneLocalHomeInstallOnlyOne` holds both
contenders at a barrier. The review NACKs and ACKs (9fe8ce67, f486db3c,
414a79d7, 802fe4dd) are the source's report.
