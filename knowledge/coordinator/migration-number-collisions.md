---
type: Decision
title: Migration number collisions
description: When unlanded branches pick the same migration numbers, the first to land keeps them and the later branch renumbers as a reviewed rename-only delta; no lower number lands after a higher one, the landing coordinator assigns ranges when lanes overlap, and authors re-check numbers at every main merge.
timestamp: 2026-10-23
---

Agreed between the OSS coordinator and the integrations coordinator on
2026-10-21, after several lanes independently picked the same OSS migration
numbers, and applied consistently since in both the OSS and hosted repositories.
Existing migrations are never edited, so a collision can only be resolved by
renumbering the branch that has not landed.

## Decision

- The first branch to land keeps its numbers.
- The later branch renumbers as a reviewed, rename-only delta: byte-identical
  SQL plus the packaged migration manifest, which the reviewer verifies as a
  pure rename.
- No lower number lands after a higher one.
- When lanes overlap, the landing coordinator assigns ranges (for example "one
  lane takes three numbers; the next starts after them").
- Authors re-check their numbers at every main merge and before sending a
  landing request.

This harvest is the rule's first durable record; the team instructions and the
coordination skill do not state it.

Related: [focused proof includes the contract guards](../aweb-expert/lessons/focused-proof-includes-the-contract-guards.md)
(the packaged migration chain is its own guard).

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (log of
2026-10-21 to 2026-10-23; OSS coordinator mails e2d94fe5, 55e01927, e3f19324;
reply 0f0571be confirming no other durable home).
