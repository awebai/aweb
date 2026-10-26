---
type: Lesson
title: Main CI is a separate signal
description: Green local train gates do not show that main's hosted CI is green, and branch protection that exempts admins turns a required check into an advisory one for train pushes; after every landing, read CI for the landed SHA and treat red main as a P0 owned by the lane that landed it.
timestamp: 2026-10-25
---

A required CI check on OSS main failed on every commit for about two and a
half days in October 2026 while every local train gate was green, and nobody
noticed until the operator did: "failing on every commit since 2026-10-22 what
is going on? you are holding the team back." The coordinator that had set up
the required check had not watched it. Branch protection required the check but
exempted admins, and trains push to main as admin, so landings went through.

The cause of that CI failure was still a hypothesis when this was recorded (a
floating-point comparison of clock deltas against an exact bound, which differs
on hosted runners); the coordination lesson does not depend on it.

## How to apply

- After every landing, read CI for the landed SHA (`gh run list --workflow
  <name> --branch main`). A red result on main is a P0 owned by the lane that
  landed it.
- A required check that admins bypass enforces nothing for admin pushes; treat
  it as advisory and make watching it part of the landing.
- The OSS coordinator ruled on 2026-10-25 that lane trains touching the affected
  app also need green main CI before landing.

Related: [separate publication, installation and live adoption](separate-publication-installation-and-adoption.md).

## Provenance

Harvested 2026-10-25 from the `naapps` coordinator seat (note
`main-ci-is-a-separate-signal.md`; operator turn of 2026-10-25T18:28Z; OSS
coordinator ruling 931dd215). Root-cause status confirmed by the seat in
db078d42.
