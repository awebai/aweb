---
type: Decision
title: naapp deploys move forward only; going back is rollback
description: The naapp deploy tool deploys an approved commit that is on the configured branch, read live from the remote, and strictly ahead of the live commit; going back stays rollback of a built artifact, and a repository move is an explicit, twice-confirmed path guarded by two live git checks. No gate-receipt field.
tags: [decision, naapp, deploy, rollback, ops]
timestamp: 2026-11-25
---

Design accepted by the naapps lane lead (rulings ebc5db0b and 0b90adc8) and
landed in naapp PR #46 (merge 522d62bf, "Deploy an approved commit on the
configured branch, strictly ahead of live").

# Decision

- **Target.** The tool deploys an approved commit C that is the tip T of the
  configured branch or an ancestor of it. T is read from the remote at deploy
  time, and the tool fetches it itself, so ancestry is computed on real
  objects and never on a stale local ref.
- **Forward only.** The live commit L must be a strict ancestor of C. L is the
  commit of the named rollback artifact, and the tool checks that this
  artifact is live before any git check.
- **Going back is rollback**, which redeploys an already built artifact. A
  deploy never rebuilds an older commit.
- **Repository move.** The first deploy after a service changes repositories
  names the previous repository (`--from-repository`) and repeats it in a
  confirmation (`--confirm-from-repository`). The tool then requires two live
  facts: L is absent from the configured branch, and L is present on the
  previous repository's branch. This is the only case that skips the forward
  check.

# Why

- Requiring the exact branch tip broke as soon as the branch moved past a
  gated commit: an operator had to run the tool's steps by hand to deploy an
  approved commit 72 commits behind main.
- Accepting any ancestor of the tip without the forward check would let a
  deploy move production backwards by rebuilding an old commit under today's
  service settings. That is exactly what rollback, an artifact redeploy,
  exists to avoid.
- The hosting provider's deploy records carry no repository, so "the live
  deploy's recorded repository" cannot be read. The two live git checks stand
  in for it, and the repeated flag makes the move deliberate.

# Rejected

- **A gate-receipt or `approval_note` field.** A field that looks like a check
  but checks nothing is worse than no field (the lane lead's ruling).
- **Silently skipping the forward check** when the live commit is not found on
  the branch. That is a silent bypass; the explicit repository-move path is
  the only exception.
- **Exact-tip deploys**, for the reason above.

# Status (2026-11-25)

- The rule exists twice: in naapp-lib's shared ops and in Library's own
  `render_ops`. Nothing checks that the two copies agree; the planned fix is
  for Library to use naapp-lib's shared ops. Until then a change to the rule
  is made in both copies.
- No deploy had run through the new rule when this was recorded.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/deploy-target-forward-only.md. The harvester read naapp
PR #46 (merged at 522d62bf), whose description states the rule, the
repository-move checks, the rejected receipt field and the planted-defect
tests in both copies. The lane-lead rulings are source-reported.
