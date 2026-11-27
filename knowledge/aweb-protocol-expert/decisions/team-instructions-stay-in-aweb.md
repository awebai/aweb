---
type: Decision
title: Shared team instructions stay in aweb; the rest of coordination leaves
description: Shared team instructions are essential and stay in aweb, while roles, tasks, work, claims and locks are the coordination leaving for an app; because the default instructions are built from the roles bundle, roles are removed only after that coupling is cut.
tags: [decision, coordination, instructions, roles, removal, roadmap]
timestamp: 2026-11-27
---

Accepted by Juan on 2026-11-27. The acceptance is **source-reported**: an
integration coordinator's record (806b9cd7), relayed by the aweb coordinator
(6f6cbf3a). The harvester could not read either record.

# Decision

- Shared team instructions are essential and stay in aweb.
- Roles, tasks, work, claims and locks are the coordination that leaves aweb
  for an app.

# Consequence for the order of removal

Reading the active team instructions with `bootstrap_if_missing` (the
default) first bootstraps the team's roles bundle. If the bundle has legacy
invariants, the default instructions body is built from them
(`get_active_team_instructions` in
`server/src/aweb/coordination/routes/team_instructions.py`, checked at aweb
main 5c2ee7bad). So the instructions that stay depend on the roles that
leave. Cut that dependency first, so that instructions no longer read or
bootstrap the roles bundle. Remove roles only after that.

Other limits on the removal:

- Some routes must survive the removal for released clients. See
  [a shared command keeps a zero-use feature's route alive](/aweb-protocol-expert/lessons/a-shared-command-keeps-a-zero-use-route-alive.md).
- The work and claim wakes have no producer. See
  [coordination wakes have no producer, and tool use is not measured](/aweb-protocol-expert/lessons/coordination-wakes-have-no-producer.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-classify, 2026-11-27; notes/instructions-are-essential-ruling.md.
