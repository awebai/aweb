---
type: Decision
title: Home and work isolation in aw team commands
description: An agent home created by the aw team commands holds identity and instructions only and never hosts git work; every agent gets a worktree on its own branch, and agents that legitimately touch main reach it through an explicitly named handle; a home is never moved after its identity is registered.
tags: [decision, aw-cli, team, worktree, identity]
timestamp: 2026-07-03
---

Decided with the operator on 2026-07-03 after a materialised developer agent
did git work inside its home, a subdirectory of the main checkout, and hijacked
the main checkout's branch. Verified on 2026-09-21 that the aw team commands
still carry the `tracks_main` profile flag in `cli/go/cmd/aw/team_human.go`.
Scope: this governs homes created by the aw team commands themselves. Instances
managed by OATS follow OATS's own home and work contract, which applies the
same separation.

# Decision

- The home holds the identity state and the agent's body. Coordination commands
  run there; git never does.
- Every agent gets a worktree of the project on a branch named after it, the
  default and safe place for git and builds; accidental commits land on the
  agent's branch, never on main.
- Only agents whose profile tracks main also get an explicitly named handle to
  the main checkout; the name carries the caution, and the default working
  directory is always the safe worktree.
- Retirement removes the worktree, unlinks the main handle, deletes the
  workspace registration and then the home.
- A home is never moved or renamed after its identity is registered: the
  registry binds the identity to the path and reaps it when the path disappears.

# Why

Naming the work directory by mode and giving every agent a worktree removed the
accident class at almost no cost; the previous model gave coordination agents
only a main symlink, so their default directory was main.
