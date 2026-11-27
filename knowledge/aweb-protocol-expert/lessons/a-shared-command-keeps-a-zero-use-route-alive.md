---
type: Lesson
title: A shared command keeps a zero-use feature's route alive
description: Every released aw workspace status (aw 1.36.13 to 1.36.59) calls GET /v1/reservations and GET /v1/status and fails if either errors, so those coordination reads stay while released aw is in the field, even though reservations had no use in 90 days; measure the feature and the commands that read it separately.
tags: [lesson, compatibility, coordination, removal, released-clients, measurement]
timestamp: 2026-11-27
---

A feature with zero use can still have a read route that cannot be removed.
This happens when an everyday command reads that route on every run. Removing
coordination from aweb looks like a case where the feature's own use decides
the matter. It is not.

# The case

- Every released `aw workspace status`, from aw-v1.36.13 to aw-v1.36.59,
  calls `client.ReservationList` (GET `/v1/reservations`) and then
  `client.CoordinationStatus` (GET `/v1/status`). It returns the error if
  either call fails (`runWorkspaceStatus` in `cli/go/cmd/aw/workspace.go`,
  checked by the harvester at tags aw-v1.36.13, .33, .54 and .59).
- The OATS aweb provider runs that command for its roster and for retained
  seats, and pi-extension runs it at startup (the source checked
  oats-aweb f3f5e02 and `pi-extension/src/index.ts`).
- The operator read production totals: 0 reservations in 90 days. That figure
  is an aggregate reported by the source.

If those routes are removed, every frozen deployment of released aw breaks:
`aw workspace status` fails, and so do the OATS roster, retained seats and
pi-extension startup. This is the
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
rule. A route stays while a shared command depends on it, whatever the
feature's own use.

# Not every coordination read is pinned

- A failed roles read is tolerated. `resolveRole` falls back to the requested
  role when fetching the roles bundle fails (`cli/go/cmd/aw/workspace.go`).
- channel-core maps a 404 from the activity route to `route_absent`
  (`channel-core/src/activity/publish.ts`).

# How to apply

- Before removing a coordination route, list every released command that
  calls it. Count that command's use, not only the feature's use.
- Check how the caller handles failure at each released tag. A route whose
  failure the client tolerates is removable. A route whose failure the client
  returns is not removable while that release is in the field.
- Elimination route: a test that runs pinned released clients against the
  server would catch this. Until one covers `aw workspace status`, this lesson
  is the guard.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-classify, 2026-11-27; notes/workspace-status-pins-two-coordination-reads.md.
