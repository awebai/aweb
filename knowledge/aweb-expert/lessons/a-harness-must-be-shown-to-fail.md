---
type: Lesson
title: A harness must be shown to fail
description: A red is evidence only if its failure text names the property; a zero is evidence only if the detector was shown positive on the real pattern in a separate invocation; a validated detector is still not a valid experiment until removing the fix makes the harness go red.
tags: [lesson, verification, review, testing]
timestamp: 2026-07-26
---

Recorded by the OSS coordinator role on 2026-07-26 as the durable output of a
security-remediation epic: a handful of real code defects were found, and in the
same period nine failures in the team's own measuring instruments — each of
which would have produced a confident wrong answer, none caught by inspection.

# The rules

- A red is evidence only if its failure text names the property. Environmental
  failures present as timeouts and killed processes and cannot name a property.
  Quote the assertion text, never a pass/fail count.
- A zero is evidence only if the detector was shown positive on the actual
  pattern, repeatably, in a separate invocation; a control in the same
  invocation puts the literal into the searcher's own arguments.
- A validated detector is not a valid experiment. A passing control proves the
  instrument can see; only removing the fix proves the harness can produce the
  condition.
- The control you need depends on the claim's direction: an absence claim needs
  a known positive; a presence claim needs a known negative.
- A partial red is evidence; widening the mutation until everything reds
  destroys the information. Classify every non-red after predicting the
  sensitivity set: expected-sensitive-but-passed is a vacuous guard.
- The harnesses most likely to lack all of this are the ones that are not tests:
  log greps, process counts, exit-code checks, read-backs, roster queries.

# A test of a bound asserts the bound

Added 2026-11-27. A test for "the helper pools hold 1 to 5 connections"
counted the pool's connections in pg_stat_activity. It went red on the
unfixed code, which opened 10 at once. But an idle pool opens only its
minimum, so the test stayed green with both maxima loosened back to 20. The
break-proof had covered the starting state (the minimum), not the property
the change was for (the maximum). Review returned it.

- For any bound (a pool size, a timeout, a rate, a retry count), assert the
  configured bound from the component that enforces it, such as pgdbm's
  `get_pool_stats()` `min_size` and `max_size`. Otherwise drive load past
  the bound and assert that it holds. A snapshot below the bound cannot see
  the bound.
- Break-prove with the mutation that loosens exactly that bound, plus one
  mutation per other bound. Proving red only on the starting state leaves
  the claimed property untested.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/limit-tests-assert-the-limit.md. Task aweb-adzx. Checked by the
harvester: the source's test-pool-size branch at 29aaa58df asserts
`get_pool_stats()` in `server/tests/test_testing_server.py` and
`naapp-lib/tests/test_db.py`. The review return and the four mutations are
source-reported.

# Review standard

Any verdict citing a harness carries one of two lines: "the fix was removed and
it redded, at these assertions" or "I did not check whether this harness can
fail." Silence is not acceptable.
