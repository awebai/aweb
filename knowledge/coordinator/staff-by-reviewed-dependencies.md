---
type: Lesson
title: Staff by reviewed dependencies
description: Staff every task whose dependencies are at least ACKed, stacked on those branches, instead of waiting for them to land; break serial chains by having the provider publish its consumer interface first so consumers fit-check it and build in parallel.
timestamp: 2026-10-23
---

On 2026-10-20 the operator asked "what are you waiting for to implement
secrets? i asked you 8 h ago". The coordinator had staffed only the shared
substrate and contracts and spent the day routing reviews and landings; nobody
was on the app tasks, although their dependencies were already ACKed or on main.
The coordinator's own conclusion: the delay was its sequencing, not a real
dependency.

On 2026-10-23 two seats were blocked one after another on a third seat's broker.
The ruling was to publish the broker's consumer interface first as a docs
commit. One consumer's fit check found a real gap within minutes, before any
code was written.

## How to apply

- When a plan has a dependency graph, staff every task whose dependencies are
  at least ACKed, stacked on those branches. Re-check the graph after every
  landing round, not only when dependencies reach main.
- When two or more consumers wait on one provider in series, the provider
  publishes its consumer interface (signatures, bodies, replay, transitions)
  first; consumers fit-check it and build in parallel.
- Surface operational tasks with no owner on the day they are found.
- Under small staffing, a competent non-author reviewer from an adjacent lane
  can review a reproduction rather than spawning a new seat; do not borrow a
  seat another coordinator assigned without asking that coordinator.

## Provenance

Harvested 2026-10-25 from the `secrets` coordinator seat (note
`staff-app-early.md`; operator turn of 2026-10-20T15:33Z; log of 2026-10-23,
"ruled interfaces-first") and the `integrations` coordinator seat (note
`staffing-reuse-reviewer.md`).
