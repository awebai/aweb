---
type: Decision
title: Every full gate runs on its own VM; VMs remove queuing, not per-gate time
description: Every full gate, focused runs included, runs on its own labelled provider VM through one dispatcher command, several in parallel, with the shared Mac as fallback; at the same 2-CPU runner cap a dedicated VM ran the server suite about 1.5x slower per test than the Mac, so gate time comes only from using the VM's width.
tags: [decision, testing, release, gates, infrastructure, performance]
timestamp: 2026-11-11
---

Decided by the operator on 2026-11-11, relayed by the coordinator. The
acceptance is source-reported: the source's note records it, and this harvest
could not read the original record.

**Status:** decided and being built. The dispatcher (`scripts/vm-gate/`) is
not on main at 7f4be32fa.

# Decision

- Trains, release candidates, other teams' gates and focused runs all go
  through one dispatcher command in the aweb repository, `scripts/vm-gate/`.
- Each run gets its own labelled VM, created from a snapshot. The dispatcher
  ships a git bundle of the exact SHA, checks the host tools against pins
  derived from that SHA, runs the gate as a non-root user, returns the logs
  and a summary, and deletes everything. Every run starts with a reap of
  leftover VMs.
- Several gates run in parallel, one VM each. The shared Mac stays as the
  fallback.
- Host-specific values live in local configuration outside the repository.
- Provider capacity is guarded by refusal at create time:
  [gate capacity is guarded by refusal at create](/aweb-expert/decisions/gate-capacity-is-guarded-by-refusal-at-create.md).

# Why

- Queuing for the one shared Mac was the visible waste.
- A VM per run also removes interference between concurrent runs.

# VMs do not make a gate faster

This is the part a future reader is most likely to get wrong.

- At the same 2-CPU runner cap, the server suite took about 0.59 s per test on
  a dedicated VM (4,351 tests in 2,580 s, acwx 579b220bd) and about 0.39 s per
  test on the Mac host (3,952 tests in 1,551 s, the rc3 baseline). That is
  about 1.5x slower per test.
- So a VM gate is slower per run (the source estimates about 2 h against about
  89 min) until the gate uses the VM's width: a wider runner, parallel suites
  and sharding (the in-run parallelism lever).
- VMs remove the queue; in-run parallelism removes the time. Do not expect
  per-run VMs alone to meet a gate-time target.
- Stage budgets are measured on the VM, where gates now run, not on the Mac.

Limits of the measurement: one sample, at the 2-CPU cap only, on two different
SHAs and test counts. The full Linux gate result at 579b220bd was still
pending when this was recorded.

# Rejected

- **A separate private repository for the dispatcher.** The coordinator chose
  the aweb repository, with host configuration kept outside it.
- **Waiting for more measurement before building the dispatcher.** The
  operator chose to start now.

Related: [the first run on a new host type is a portability test](/aweb-expert/lessons/first-run-on-a-new-host-is-a-portability-test.md),
and [a timed-out qualification completes with its never-run stages](/aweb-expert/decisions/timed-out-qualification-completes-with-never-run-stages.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-11; notes/gates-move-to-vms-2026-11-11.md and
notes/ephemeral-vm-gate-findings.md. The run times are the source's report of
runs on 2026-11-11; the harvester did not rerun them.
