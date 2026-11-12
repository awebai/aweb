---
type: Decision
title: Authors prove the cheap checks before any train or VM handoff
description: Before handing a change to a train or a VM gate, its author runs the container-free checks and every touched package's own tests and pastes the pass lines, so failures that take minutes to find are not first found by a 90-minute train.
tags: [decision, testing, gates, trains, review]
timestamp: 2026-11-12
---

The operator's direction of 2026-11-12. The acceptance is source-reported: the
source's note records it, and this harvest could not read the original record.

# Decision

- Before any train or VM gate handoff, the author runs the container-free
  checks and the own tests of every package the change touches.
- The handoff carries the pass lines of those runs, not a statement that they
  passed.

# Why

Several 90-minute train failures, and VMs spent on them, came from import
order, lint and package-contract breaks. The container-free checks and the
package's own tests catch each of those in minutes. A train is the only place
a change meets the whole suite
([skipping the train skips the only full run](/aweb-expert/lessons/skipping-the-train-skips-the-only-full-run.md)),
so a train spent on a cheap failure delays every head queued with it.

# Relationship to other knowledge

This sets a floor on the author's focused proof; it does not replace it.
[Review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
and
[focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md)
still say which further tests a change needs. The pasted pass lines are
evidence in the sense of the
[evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md).

**Status** (checked 2026-11-12): main at 71e608a1c has no single make target
named for the container-free checks; which targets count is set by the team's
current instructions.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-12; notes/gate-lessons-2026-11-12.md. The operator's acceptance and
the train failures it answers are the source's report.
