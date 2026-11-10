---
type: Lesson
title: A gate speed-up counts only when landed and measured on the release path
description: A test speed-up is done only when it has landed on main, is measured in the summary of the gate releases use, and every stage carries a time budget that fails on regrowth; three rounds of faster tests left release time unchanged because each missed one of these.
tags: [lesson, testing, release, gates, performance]
timestamp: 2026-11-10
---

By November 2026 three rounds of "make the tests faster" had left the time to
release where it was. Nothing was reverted; each gain was lost in a different
way.

- **Wrong path.** An accepted speed-up (task aweb-acmy) sharded the server
  suite and parallelised the isolated suites, but only in the GitHub Actions
  test workflow. Releases and trains are gated by the local candidate gate
  (`candidate-docker-gate.sh`, then `candidate-suite.sh`, then
  `test-egress/docker.py`), which never received the change.
- **Accepted, never landed.** Its PR met acceptance on 2026-10-28 (three green
  runs at 12.9 to 14.1 minutes) and was still open on 2026-11-10: stacked on an
  unfinished product PR, then caught in release freezes and version-bump
  rebases. Acceptance stopped at "PR green", and nobody owned "landed and
  measured on the release path".
- **Hidden inner cap.** `scripts/test-egress/docker.py` hard-coded the isolated
  unit runner to 2 CPUs and 8 GB whatever the outer runner was given, so
  raising the gate host to 14 cores could not reach the unit stage.
- **Unbudgeted growth.** The OSS server suite grew from 1,147 tests to 3,952
  and still ran serially, taking 26 of the release gate's 89 minutes. Another
  team's gate that had been cut from 47 to 16 minutes drifted back to about 30
  as its suite grew. No stage had a time budget, so nobody saw the regrowth.

The common pattern: a mechanism works where it was added, and a second entry
path, a later default or growth quietly undoes it.

# How to apply

- **One test path.** Speed work lands in the scripts and make targets that CI,
  the candidate gate and the release all call. A faster path that releases do
  not use is not a release speed-up.
- **The done-signal is a release-path measurement.** A speed-up task is done
  when its change is on main and a release-path `summary.tsv` on a stated SHA
  shows the new times, not when its PR is green.
- **Every stage has a budget that fails on breach.** Record the budget beside
  the stage's time in the summary; ratchet it down, never up silently, so test
  growth forces scaling work when it happens rather than months later.
- **No hidden caps.** Every resource limit is a recorded gate setting that
  inner runners inherit; a limit hard-coded inside a stage makes resizing the
  host a no-op.
- **Never weaker.** The same tests run with the same pass counts, and each
  harness change is shown to go red on a known-bad input first
  ([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

The elimination route is the gate itself: per-stage budgets in the summary and
recorded resource settings turn this lesson into a failing check. Until those
land, a reviewer asks for the release-path measurement before calling a
speed-up done.

This extends
[skipping the train skips the only full run](/aweb-expert/lessons/skipping-the-train-skips-the-only-full-run.md):
the release gate is the one place the whole suite runs, so it is also the only
place a speed-up counts. Concurrency between gates is a separate decision:
[gate concurrency comes from machine isolation](/aweb-expert/decisions/gate-concurrency-comes-from-machine-isolation.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-10; notes/why-gate-speedups-did-not-stick.md and
notes/gate-time-budget-2026-11-09.md (task aweb-acmy; release-candidate gate
summary at 182f9ef49). Times are the source's reading of the recorded gate
summaries; the source ran no gate itself for this claim.
