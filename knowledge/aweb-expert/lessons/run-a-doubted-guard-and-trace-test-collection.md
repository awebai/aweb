---
type: Lesson
title: Run a doubted guard, and trace test collection, before calling anything unused
description: In an unused-code cleanup, a doc saying a check runs in the gate is not evidence and a grep of named targets does not show a test never runs; run every doubted guard on current main, and if it is kept, fix it, wire it into a stage that runs, show it red once and correct the doc in the same change; check package collection, shard manifests and top-level discovery before calling a test unused, and delete a running test with the otherwise-unused code it exercises.
tags: [lesson, cleanup, gates, testing, verification]
timestamp: 2026-11-24
---

On 2026-11-24 an inventory-driven cleanup of aweb (main at da869f7143) found
both kinds of claim wrong.

- **A guard the docs said protects the build was wired to nothing, and red.**
  The accepted audit design says a source-derived inventory pins every
  `on_mutation` call site and "a build check rejects added, removed or
  non-literal sites". That check, `check-extension-docs`, is a Make target no
  gate stage reaches. Run at da869f7143 it fails on two non-literal call sites
  and one call site that moved, all introduced after 2026-11-18. A second guard,
  `check-node-audit --self-test`, had been broken since 2026-08-04 because its
  provenance test read two release workflows that 662f3a3ba deleted.
- **Tests the inventory called never run do run in every gate.** The
  team-deployment helper tests are collected by the Secrets package suite and
  listed in `candidate-gate/secrets-shards.json`, which a shard check requires
  to list every collected module. A trace of Make targets, CI and named
  discovery missed them. Separately, `make test-scripts` discovers every
  top-level `scripts/test_*.py`, so a script's unit test runs even when the
  script itself runs nowhere.

Trusting the doc keeps a broken check. Trusting the inventory can delete the
only enforcement of an accepted design, or delete tests that run in the gate.

# How to apply

- For every guard an inventory doubts, run it on current main before deciding
  to keep or delete it. A doc claim ("the gate runs X", "a build check rejects
  Y") is a question, not evidence.
- If the guard is kept, fix it, wire it into a stage that actually runs, show
  it red once on a deliberate break, and correct the doc in the same change.
  If it is deleted, correct the doc that claimed it too.
- Before calling a test unused, check pytest collection for each package suite,
  the shard manifests and top-level discovery, not just named targets.
- A test that runs but exercises only code nothing else runs is still unused.
  It is deleted with that code.

This applies [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
to guards whose existence is only asserted. It is the guard and test side of
the "confirm nothing calls it" rule in
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md).

The durable fix is a check that every guard the docs name is reachable from a
gate stage. Until that check exists, this lesson does the job by hand.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-24;
notes/unwired-guards-rot-silently.md and
notes/never-run-claims-need-sharded-manifests.md. At da869f7143 the harvester
reproduced the `check-extension-docs` failure, confirmed that no gate stage
runs it, and confirmed the shard-manifest entries and the `test-scripts`
discovery. The `check-node-audit` breakage and the fixes (on a review branch,
not landed) are source-reported.
