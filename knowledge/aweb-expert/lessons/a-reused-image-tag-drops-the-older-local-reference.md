---
type: Lesson
title: A reused image tag drops the older run's local reference
description: The team-deployment image builder tags cli-control by its control source commit, so rebuilding for a new run with the same control left the previous run's local cli-control@digest reference unresolvable, although the content was identical and both indexes stayed in the registry; record this when a kept run's evidence relies on local image references, and do not repair it by pulling or retagging.
tags: [lesson, deployment, images, evidence, e2e]
timestamp: 2026-11-13
---

Observed on 2026-11-13 in the run47 build. `scripts/e2e/team-deployment-images.sh`
tags every candidate image by the checkout's commit. It tags the control CLI
(`cli-control`) by its control source commit instead, and that commit is the
same from run to run. Rebuilding for run47 moved that tag. The gate's
kept-state check then found that run46's local `cli-control@<digest>`
reference no longer resolved. Nothing had been lost: the old and the new index
both stayed in the registry and resolved to the same platform manifest, so the
content was identical. The run46 teardown was unaffected, because it uses
run46's own Compose inputs and runs no images. The gate recorded the loss as a
limitation of the kept state.

# How to apply

- A kept run's local image references are not stable across a later build
  that reuses one of its tags. Before a kept run's evidence depends on them,
  check whether a later build has reused the tag, and record any reference
  that no longer resolves as a limitation.
- Establish identity through the registry and the platform manifest, not
  through a local reference that a rebuild can move.
- Do not repair a missing local reference by pulling or retagging. That
  changes the kept state that serves as evidence, so it is the integration
  owner's decision.
- The elimination route is in the builder: a per-run tag for `cli-control`, or
  an images file that a kept run can resolve against the registry alone. That
  change is the script owner's call.

Related: [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13; notes/rebuilt-control-tag-drops-old-local-reference.md.
The harvester checked `scripts/e2e/team-deployment-images.sh` at f874fda72
(the `build` function, and the `cli-control` build tagged `$control`). The
script is unchanged on main at f37f8c4cb.
