---
type: Decision
title: Gate concurrency comes from machine isolation
description: Running release or lane gates concurrently needs one fresh, ephemeral VM per gate run; concurrency on the single shared Docker host is not tried again, because every attempt produced load-induced failures and fell back to serial. Accepted direction, not yet built.
tags: [decision, testing, release, gates, infrastructure]
timestamp: 2026-11-10
---

Approved by the operator on 2026-11-10 as lever B of the gate-speed plan (epic
aweb-acww). The acceptance is source-reported: the source's note records the
operator's approval of the plan in a session, which this harvest could not
read.

**Status:** accepted direction, not built. Until it lands, gates on the shared
host stay serial.

# Decision

- Concurrency between gates comes from running each gate on its own fresh,
  ephemeral VM, created for the run and deleted after it, with a reaper for VMs
  a killed dispatcher leaves behind.
- No further slot rules, worker caps or parallel-slot experiments on the single
  shared Docker host.
- Remote execution is a place to run the same gate scripts, not a different
  gate: the same test path, the same pass counts, and a known-bad SHA must go
  red remotely before it counts.
- The shared host stays the fallback, so fixes for leaks it suffers are still
  made.

# Why

- Every attempt to run gates concurrently on the shared host (two isolated
  slots in October 2026, then two teams' gates in parallel) ran into
  load-induced failures: lock timeouts, port collisions, Docker DNS timeouts.
  Each was answered with a rule (at most two workers, one suite at a time, one
  gate at a time) and ended serial again.
- The gate's VM-wide cleanup check counts host resources, so concurrent runs on
  one host fail each other's cleanup check by design.
- A finals gate failed while a concurrent gate ran (P0 aweb-acwx), costing
  reruns.
- One VM per run also removes the need for a host-wide gate lock, and resource
  leaks die with the VM.

# Rejected

- More rules on the shared host: each round cost reruns and ended serial.
- Moving the same serial run to a bigger remote host: it makes no single run
  faster; speed inside a run is a separate lever (parallelism within the run),
  under [a speed-up counts only on the release path](/aweb-expert/lessons/a-speed-up-counts-only-on-the-release-path.md).

See also [never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md),
another hazard of agents sharing one host.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-10; notes/test-speed-plan-2026-11-10.md and
notes/why-gate-speedups-did-not-stick.md (epic aweb-acww, P0 aweb-acwx).
