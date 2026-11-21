---
type: Decision
title: Complete heads get one VM run; no per-fix VM proofs
description: Each seat finishes its whole area as one complete head proved on the Mac, then gets one focused VM run covering all its callers; no VM run proves a single step, partial heads do not go to trains, and the coordinator composes combined trains.
tags: [decision, testing, gates, trains, vm, coordination]
timestamp: 2026-11-18
---

The operator's direction of 2026-11-18, relayed by the coordinator. The
acceptance is source-reported: the source's note records the relay, and this
harvest could not read the original record.

# Decision

- A seat completes its whole rule area as one head, including its cleanup and
  the quality items it owns. Partial heads do not go to trains.
- No VM run proves a single small step: no runs that only show a RED, no
  per-fix focused runs, no solo or two-head trains.
- Everything that can run on the Mac is proved there. The VM is kept for what
  needs Postgres, Docker or a browser, as one focused run per complete head
  that covers all its callers.
- The coordinator composes combined trains; seats do not ask for a gate. A
  finished head is reported in one message: SHA, reviewer ACK, local green
  lines and what is still open.

# Why

Per-fix VM proofs and small trains had become the bottleneck: each round cost a
VM allocation, a review and a report. One stop-path series alone asked for a
separate interruption run, a memory follow-up and its own train. Batching
keeps the proof as strong, because every caller is still exercised by one real
run, and removes the per-step overhead.

# Rejected

- **A VM run per fix or per RED.** It proves the same callers repeatedly and
  spends a VM allocation, a review and a report on each step.
- **Solo and two-head trains.** They pay a whole train's cost for one or two
  heads.

# How to apply as lead

When a seat proposes a focused VM run, first ask whether its head is complete.
If it is not, fold the remaining items in and hold the run. A release of a run
given before this direction no longer stands unless the run already happened.

The report of a finished head still names a full-diff review at its exact head:
[train-ready names a full-diff review at the exact head](/aweb-expert/lessons/train-ready-names-a-full-diff-review-at-the-head.md).
Combined trains remain the only place a change meets its consumers' whole
suites:
[skipping the train skips the only full run](/aweb-expert/lessons/skipping-the-train-skips-the-only-full-run.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-18; notes/complete-heads-and-combined-runs-2026-11-18.md. The
operator's direction and the coordinator's relay are source-reported.
