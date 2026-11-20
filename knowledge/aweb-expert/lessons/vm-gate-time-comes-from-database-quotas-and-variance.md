---
type: Lesson
title: VM gate time comes from database quotas and run-to-run variance
description: On dedicated VMs, database CPU quotas and run-to-run variance dominate gate timing; throttled databases made parallel groups slower than serial, identical settings on identical VMs varied by 30 to 50 percent, so a time budget is set from a distribution of runs, never from one.
tags: [lesson, testing, gates, performance, postgres, infrastructure]
timestamp: 2026-11-12
---

Measurements of the gate on dedicated provider VMs (2026-11-11..12, about five
runs on one instance type) found two effects larger than the runner's CPU.

- **Database quotas.** With the test databases capped at 0.05 to 0.35 of a CPU,
  they were throttled in about 90% of scheduling periods. Parallel test groups
  then ran slower than serial ones, and the server stage hit
  `TooManyConnections` errors and timeouts under load. Raising the database CPU
  fixed the server stage and removed both.
- **Variance.** Identical settings on identical VMs varied by 30 to 50% in unit
  stage wall time.

# How to apply

- When a gate stage on a VM is slow or flaky under parallelism, check the
  database containers' CPU throttling before the runner's CPU or the tests.
  Parallelism against a throttled database adds contention, not speed.
- Set a stage's time budget from a distribution of runs at the same settings,
  never from one run. A single run can sit anywhere in a 30 to 50% spread.
- Compare two settings only with several runs of each. One run apiece cannot
  separate a change from the noise.
- Gates emit per-test durations so that samples accumulate with every run, at
  no extra cost.

**Status** (checked 2026-11-12): per-test duration output is not on main at
71e608a1c. On main the isolated unit stage gives its PostgreSQL and Redis one
CPU each (`scripts/test-egress/docker.py`). The fractional quotas above are the
source's report of its parallel-group experiments.

**Limits:** about five runs on one instance type. The figures say what
dominates, not the size of the distribution elsewhere.

This says how stage time budgets are sized; that every stage carries one is a
separate rule. Repeated runs here
measure timing on unchanged code; they are not reruns after a failure, which
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
and the gate ledger govern.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-12; notes/gate-lessons-2026-11-12.md. The measurements (the
gates-parallel A/B/C runs and the unit-evidence run at 74a2ecea0) are the
source's report; the harvester did not rerun them.
