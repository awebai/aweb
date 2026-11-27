---
type: Lesson
title: Inventory a caller's released versions, not its main
description: An inventory of what a caller asks of aw, built from the caller's main, misses calls its released versions still make; deployments run releases, so read every released tag that can still be running in argv form and diff it against main before writing a contract or a removal.
tags: [lesson, compatibility, contracts, removal, released-clients, inventory]
timestamp: 2026-11-27
---

The first inventory of what OATS asks of `aw` read the OATS aweb provider's
main, in argv form through its helpers. It missed `aw check --online`. Main had
dropped that call, but released providers from v1.17 still run it and rely on
its exit status, and deployments run those releases (a deployed instance
home recorded provider 1.18.1). Diffing the argv across the released tags also found
older releases calling `aw team join`, and `wake register`/`deregister` and
`id team members` in other forms than main.

A contract written from main would have frozen too little, and a removal
justified from main would have broken every deployment still on a release.

# How to apply

- Before writing a contract with a caller, or removing anything a caller uses,
  list the caller's released tags that can still be running, not only main.
- Read each tag in argv form: helpers, spread arguments and flag builders, not
  only literal command strings. Most argv are built from variables, so a regex
  over literal arrays is a diff hint, never the inventory.
- Diff each release against main and carry every call that a release still
  makes into the inventory, with how that release handles its failure.

This applies [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
to building an inventory: the released callers of aw are consumers in the
sense of [review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md).
Seen once, for the OATS provider; the durable fix would be a test that runs
the pinned released callers against the current aw.

Evidence: OKF proposal from aweb-expert/aweb-expert-aw-contract, 2026-11-27; notes/inventory-released-callers-not-main.md. Source-reported: the miss was found by another seat and relayed by the coordinator.
