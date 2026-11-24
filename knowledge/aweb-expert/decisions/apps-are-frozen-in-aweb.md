---
type: Decision
title: The applications live in awebai/naapp; aweb's copies are frozen
description: As of 2026-11-24 the naapp-lib runtime and the Secrets, Logs, Folio and Library apps live in github.com/awebai/naapp; OSS changes in aweb leave naapp-lib/, naapp/, their docs and their CI, gate and Make wiring untouched and drop app-only cleanup rows, until a separate task removes the apps from aweb.
tags: [decision, boundary, naapp, cleanup, repository]
timestamp: 2026-11-24
---

Decided by the operator on 2026-11-24. The OSS coordinator relayed the decision
by aweb mail during the aweb-advf cleanup. Acceptance is **source-reported**:
the harvester could not read the mail.

# Decision

- The applications now live in their own repository, github.com/awebai/naapp.
  That covers the naapp-lib runtime and the Secrets, Logs, Folio and Library
  apps. That repository is canonical.
- aweb's copies are frozen. OSS changes do not edit `naapp-lib/`, `naapp/`,
  their docs (page-store, secrets-*) or their CI, gate and Make wiring.
- Cleanup inventories drop app-only rows rather than deleting app code one
  piece at a time.
- The freeze holds until a separate task removes the apps from aweb. That task
  supersedes this decision.

# Why

An instance cleaning or fixing aweb would otherwise "helpfully" edit or prune
app code there. The aweb copy would then diverge from the canonical
repository. Nothing in aweb records the move.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-24;
notes/apps-frozen-in-aweb.md.
