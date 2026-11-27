---
type: Lesson
title: Register fewer certificates to speed up a history test
description: In naapp-lib's tests each certificate registered through the in-process AWID test registry costs a roughly constant CPU time that does not grow with history size, and asyncio concurrency gains nothing because the work runs in the test's own event loop; make a slow history test cheaper by sharing one real history across cases, not by gathering registrations or inserting rows by SQL.
tags: [lesson, testing, performance, awid, naapp]
timestamp: 2026-11-27
---

Tests in naapp-lib that need a long certificate history, such as the
page-bound cases that need more than 20,000 certificates, build it through the
in-process AWID test registry. Every registration runs the signed writer: it
signs, verifies and inserts. All of that is CPU work in the test's own event
loop.

# What was measured

- Per-registration cost is roughly constant. Batches of 1,000 took 7 to 21 s
  depending on host load and did not get slower over 6,000 certificates, so
  the size of the history is not the cost.
- Concurrency gains nothing. 1,000 serial registrations took 6.8 s, and 2,000
  under `gather` with 50 in flight took 11.1 s, about the same rate. Gathering
  only interleaves CPU work on one loop.

# How to apply

- Make such a test cheaper by registering fewer certificates. When cases
  differ only in team state, such as visibility, build one real history and
  switch the state between cases through AWID's own team-controller route.
  In the measured change, two page-bound cases of about 82 s each became one
  case of 85 s, and the module went from 219 s to 139 s on CI.
- Do not batch or gather registrations; it does not help.
- Do not insert history rows by SQL. That skips the signed writer the
  fixtures use on purpose, so the test would no longer exercise the real
  write path.
- To show the assertions survived the restructuring, run code mutants
  against the real path and check that each fails on its intended assertion.
  A test that reads synthetic responses is not that evidence; see
  [a harness must be shown to fail](a-harness-must-be-shown-to-fail.md).

Limits: measured on one shared host and on GitHub runners. Per-registration
time varies with host load, so compare timings taken under similar load.

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-27
(task aweb-advk.9, naapp commit 9c967e41); notes/registration-cost-is-cpu-bound.md.
