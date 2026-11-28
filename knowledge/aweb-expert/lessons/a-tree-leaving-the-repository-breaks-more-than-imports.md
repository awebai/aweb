---
type: Lesson
title: A tree leaving the repository breaks more than its imports
description: When a library or app tree moves to its own repository and the consumer switches to the published package, the switch fixes only imports; survey tree-path readers, gate wiring and in-consumer journeys that build the moved apps, give each its owner, and name who keeps testing vectors the consumer keeps canonical.
tags: [lesson, repository-split, removal, gate, release, planning]
timestamp: 2026-11-27
---

Switching the consumer to the published package fixes the consumer's imports
and nothing else. A survey on 2026-11-27 of all 220 aweb files that refer to
the naapp trees (aweb fbfa65f22, before the trees were removed) found a single
broken import name, which the dependency switch already fixed. The other
breakage fell into three classes, and each needs its own owner and plan.

# The three classes

- **Readers of the moved tree's files by path.** Tests and checks that open
  migrations directories, app manifests, compose files, inventory exemptions
  or ceilings tables by their path in the consumer tree. They break even with
  the dependency on the registry. About nine aweb files fell here. Each one
  reads through the installed package (for Python, `importlib.resources`) or
  vendors a pinned copy.
- **Gate wiring that names the moved suites.** Make targets, the candidate
  suite list, measured-work and budget tables, and the gate's own tests. In
  aweb that was the Makefile, candidate-suite, measured-work, the vm-gate
  budget and the gate tests. They change in the same commit as the removal,
  or the gate's self-checks go red.
- **Journeys that stay in the consumer but build the moved apps from its
  tree.** Once the tree is gone they need published artifacts pinned by
  digest. That turns the code move into a release dependency, and often into
  a human approval of the release. Four aweb journeys needed published images.

# The vector gap

A vector the consumer keeps canonical by decision can lose its last
consumer-side test when the tree that exercised it leaves. Four vectors that
naapp's README keeps canonical in aweb were in that position. The removal plan
names who tests each one afterwards. Without an owner the vector stays
canonical and is never exercised.

# How to apply

- Before planning a split (the planned contracts package is the next one),
  survey every file that refers to the moved tree and sort each hit into
  imports, tree-path readers, gate wiring, journeys and vectors. Do not treat
  "depend on the published package" as the whole job.
- Land readers and gate wiring with the removal as one reviewed change.
- Treat each journey as a release dependency: list the artifacts it needs,
  get the release approved and published first, and pin the digests.
- Record the owner of each orphaned canonical vector in the plan.

The search itself follows
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md),
and the gate wiring is an instance of
[focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md):
the gate's own tables and tests are sites of the removal.

Limits: one split, surveyed before the removal was carried out. The class
counts are from that survey, not from the landed removal.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-27;
notes/aweb-naapp-lane-boundaries-after-split.md. The survey and its counts are
source-reported. The harvester confirmed that aweb main is fbfa65f22 and still
holds `naapp/` and `naapp-lib/`.
