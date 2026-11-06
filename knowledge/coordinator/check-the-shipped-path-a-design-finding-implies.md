---
type: Lesson
title: Check the shipped path a design finding implies
description: When a design review finding implies that an already-shipped mechanism has the same flaw, verify the shipped path at once instead of parking it behind the design, and split a pre-existing defect into its own task, review and landing rather than bundling it into the feature.
timestamp: 2026-10-22
---

A design review of a new feature found that app keys must derive from
digest-pinned manifest bytes. The same reasoning applied to an install path that
was already shipped. The coordinator had the shipped path checked immediately
rather than parked behind the design ("that would be a live bug, so I'm having
it checked now"), and it was a real defect, fixed as its own first step before
the feature.

On 2026-10-22 the OSS coordinator ruled the same shape for a defect found during
a feature review that predated the feature: it became its own priority task,
with its own branch, review and landing, shipped independently of the feature
delta.

## How to apply

- For every design finding, ask whether anything already shipped makes the same
  assumption, and check it the same day.
- A pre-existing defect found in a feature review gets its own task and landing;
  bundling it delays the fix and hides it in an unrelated diff.

Related: [review every site on both axes](../aweb-expert/lessons/review-every-site-on-both-axes.md)
covers sites within a change; this covers parallel paths outside it.

## Provenance

Harvested 2026-10-25 from the `secrets` coordinator seat (session transcript
of 2026-10-20T04:23Z; log of 2026-10-19 local time) and the `integrations`
coordinator seat (note `email-notice-design.md`, "Related"; OSS coordinator
ruling 68c7c3d4).
