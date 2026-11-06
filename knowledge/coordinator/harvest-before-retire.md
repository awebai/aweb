---
type: Decision
title: Harvest before retire
description: Every seat, coordinators included, is harvested before it is retired; open-framework knowledge goes to the public OSS base and hosted knowledge to the private hosted base, and turning harvest on in configuration covers only future spawns, so existing seats need an explicit harvest.
timestamp: 2026-10-24
---

Ruled by the operator on 2026-10-24, when seats were about to be retired in a
team cleanup: "the harvester has to harvest before you retire seats", including
the coordinator seats themselves; "we need two harvesters", and "of course oss
harvesting and knowledge has to be in the oss package, and cloud knowledge has
to be in the [hosted] package."

## Decision

- No seat is retired until it is harvested, or the harvest found nothing
  durable. The coordinator holds retirements until then.
- Two bases, two harvesters: open-framework knowledge goes to this public base;
  hosted, customer and operations knowledge goes to the private hosted base,
  and never to this one.
- Cleanup order: harvest; retire finished seats after checking their claims;
  remove stray worktrees; delete superseded branches.

## Discovery

Turning the harvest setting on affects only future spawns and never captures
earlier sessions, so enabling it harvests nothing from seats that already
exist. A retirement recovery copy is not a substitute for harvesting first.

Related: [operating continuity](operating-continuity.md) and the decision that
[OSS and Cloud are separate teams](../aweb-expert/decisions/oss-and-cloud-are-separate-teams.md).

## Provenance

Harvested 2026-10-25 from the `naapps` coordinator seat (note
`harvest-before-retire.md`; operator turns of 2026-10-24T16:33Z to 16:36Z in its
session transcript). The note's claim that a harvest reads only notes and the
transcript is not carried over: this harvest also read STATE and logs.
