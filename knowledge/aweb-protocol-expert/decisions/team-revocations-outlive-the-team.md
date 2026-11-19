---
type: Decision
title: A team's revocations outlive the team and its namespace
description: AWID keeps a team's revoked certificate rows when the team or its namespace is deleted, and the revocation list for a team covers every team ever created under that domain and name; refusing re-creation with the same key was rejected because it breaks the released CLI's delete-then-create flow and misses keys rotated away before the delete. Coordinator decision; not on main as of 2026-11-19.
tags: [decision, awid, teams, revocation, certificates, security]
timestamp: 2026-11-19
---

**Status (2026-11-19):** a coordinator decision of 2026-11-16, not the
operator's (source-reported; the source first attributed it to the operator by
mistake and corrected that the same day). No human acceptance is claimed. Implemented on the source's review branch
(f9822754ba, 9673e02ed9); aweb main at ecb9d825a still deletes the rows.

# The defect

Team delete and namespace delete in AWID hard-deleted the team's
`team_certificates` rows, and the aweb server reads revocations by team. So
re-creating the same team name with the same key produced an empty revocation
set, and revoked certificates verified again. The released CLI does exactly
this by default: `aw id team delete` keeps the local team key and
`aw id team create` reuses it.

# Decision

- Keep the certificate rows when a team or namespace is deleted. All of them
  are revoked by then, because an active certificate blocks both deletes.
- List a team's revocations across every incarnation of its (domain, name).
- No migration: kept rows already carry their team's id. Rows deleted before
  the fix are gone and cannot be recovered; a read-only census
  (`awid/ops/team-recreation-census.sql` on the review branch) counts the
  teams that were deleted and re-created, and states that limit.

# Rejected

**Refusing re-creation with the same key** (the one-check fix first proposed).
It breaks the released CLI's delete-then-create flow, which
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
forbids. It also misses a key that was rotated away before the delete, because
AWID stores no earlier team keys.

# Why it generalises

This is [key authority history spans every path](/aweb-protocol-expert/decisions/key-authority-history-spans-every-path.md)
applied to team certificates: revocation is one-way, and its history is kept
across every path to the identity, delete and re-create included. A fresh key
does not need the old revocations, since old certificates fail its signature
check, but listing them is harmless because certificate ids are UUIDs chosen
by the issuer.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-19; notes/team-revocations-outlive-the-team.md. The harvester confirmed both commits exist on the source's review branch and that main still deletes the rows.
