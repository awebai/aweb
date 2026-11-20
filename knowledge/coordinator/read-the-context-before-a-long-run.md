---
type: Decision
title: Read the context before a long run
description: Before authorizing a long acceptance run, audit the exact head's contracts, fixtures and assertion reachability, fix every finding in the affected lane, and spend the run only to confirm.
tags: [acceptance, testing, coordination]
timestamp: 2026-11-14
---

A long or expensive run is admitted only after a context read of the exact
thing it will test. This applies to long unit stages, candidate and hosted
gates, VM journeys and matrix rows. The coordinator and the domain owners do
the read together:

- Bind the exact implementation head and the exact runner and fixtures the run
  will use.
- Check the current consumer contracts the run depends on, and ask the contract
  owner early when a contract is unclear.
- Confirm that the intended assertions are reachable on that head, so that a
  green result means the claimed operation was exercised.
- Resolve stale setup assumptions before execution.

Audit the whole affected lane, including old or ungated parts of it, not only
the change that prompted the run. Fix the findings together, then use one run
to confirm the reviewed composition. A run is not the way to discover
incompatibilities the source already shows.

Why: repeated expensive runs were finding incompatibilities that a reading of
the source would have shown. Each such run cost its full duration to report one
defect at a time. A focused read first makes the run informative and protects
the delivery it gates.

Limits: the read does not replace real execution or real acceptance. It does
not weaken assertions or grant any infrastructure authority beyond what already
exists. It does not create a competing review roster.

This decision moves two lessons earlier in the cycle. [Reproduce the whole test
context](reproduce-the-whole-test-context.md) covers faithful reproduction
after a failure; this read checks the same prerequisites, environment and
boundaries before the first run. [Acceptance must exercise the claimed
operation](acceptance-must-exercise-the-claimed-operation.md) sets what the
run must prove; this read checks that the run can prove it before it is spent.

## Acceptance

Operator direction of 2026-11-14, relayed to the source coordinator by its
parent coordinator by mail. The harvester could not read that record, so the
acceptance is **source-reported**, not verified.

## Provenance

Evidence: OKF proposal from coordinator/servers, 2026-11-14;
notes/context-before-long-runs.md.
