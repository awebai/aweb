---
type: Decision
title: One shared deploy tool for every naapp
description: Every naapp deploys to Render with naapp-lib's shared ops tool and one shared verify; an app's specifics live in its own config file and in app-owned steps after the verify, never in a per-app copy of deploy logic. Library's own deploy tool, AATK and the legacy rollback bridge are retired with the move.
tags: [decision, naapp, deploy, render, ops, retired]
timestamp: 2026-11-25
---

Ruled by the naapps lane lead in November 2026 (the task d172cee7, the design
64498671, the deletions 72bee01b and the AATK retirement 40c808fb, as the source
reported them). The change is naapp PR #53. On 2026-11-25 it was still a draft,
at head df5a351e. It lands only after the operator seat has verified Library's
first deploy from the naapp repository and has dry-run the production make
targets.

# Decision

- Every naapp deploys with one tool, naapp-lib's `aweb_naapp.ops`. Library's
  own `render_ops.py` is retired. No app gets its own copy of deploy logic.
- What is specific to an app goes in two places. The first is its
  `ops/render-production.json` (app id, service slug, evidence settings). The
  second is app-owned steps that run after the shared verify. Library's
  production gate (`library_prod_gate.py`) is one such step.
- The shared verify applies to every app. The deployed build must answer on both
  the origin URL and the public URL. Its identity must include `service`,
  `build.git_sha` and the deployment commit, and other keys are allowed. An
  answer that is "not yet" (a 503 from a unit still waiting for its database,
  for example) is retried until a deadline. An answer that cannot be right fails
  at once.
- The operator's evidence directory stays, under `<app_id>.health-evidence.v1`.

# Retired with the move

- **AATK**: Library's `aatk.py`, its manifest, the capability transcripts and
  the CI step. Its real-transcript path was both broken and unreachable. The
  repository root it computed did not match the path it expected for the deploy
  script, and nothing produced capability evidence. The operator seat and the
  Library seat both confirmed that nobody ran it.
- **The legacy rollback bridge**: `render_ops` move-build (the settings move was
  finished on 2026-11-06), the `ALLOW_LEGACY_MISSING_BUILD_FOR` path and the
  production gate's current-incumbent mode. Their removal rests on tests showing
  that rollback and recovery to an older artifact need no git and none of these
  paths. A test must fail on a planted defect. The ruling's stop rule still
  applies: if any of these paths turns out to be needed, stop and take it back
  to the lane lead before deleting it.

# Rejected

- **Keep Library's copy and port each rule to both copies.** naapp #46 had
  already left the forward-only rule in two copies with nothing checking that
  they agreed. Every rule added after that would have been another chance for
  the copies to drift apart.
- **Weaken the shared verify for one app.** The operator seat confirmed that
  both live apps meet it (e1e3581a). An app that needs more adds its own step
  after the verify.
- **Port health-client-proof.** Giving the shared tool its own User-Agent
  solves the same problem.

# Consequences

- When an app needs something the shared tool lacks, add it to the shared tool
  or to an app-owned step after the verify. Do not add a per-app deploy script.
- Do not bring back AATK, move-build or the legacy bridge. If a capability or
  rollback need comes up again, design it against the shared tool.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/adxc-inputs.md. naapp PR #53 (draft, head df5a351e) was
checked by the harvester; the rulings are source-reported.
