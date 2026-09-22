---
type: Decision
title: Home and work isolation in aw team commands
description: An agent home created by the aw team commands holds identity and instructions only and never hosts git work; when the home sits in a repository or a work directory is given, the agent gets a worktree on its own branch, and agents whose profile works on main reach it through an explicitly named handle; a home is not moved casually after its identity is registered, because the registration is bound to that path.
tags: [decision, aw-cli, team, worktree, identity]
timestamp: 2026-07-03
---

Decided with the operator on 2026-07-03 after a materialised developer agent
did git work inside its home, a subdirectory of the main checkout, and hijacked
the main checkout's branch. Verified on 2026-09-21 in
`cli/go/cmd/aw/team_human.go`: the profile flag is `works_on_main`, and the
worktree setup runs only when the home lies inside a Git repository or a work
directory is supplied (it returns without one). Scope: this governs homes
created by the aw team commands themselves. Instances managed by OATS follow
OATS's own home and work contract, which applies the same separation.

# Decision

- The home holds the identity state and the agent's body. Coordination commands
  run there; git never does.
- When the home sits in a repository or a work directory is given, the agent
  gets a worktree of the project on a branch named after it, the default and
  safe place for git and builds; accidental commits land on the agent's branch,
  never on main.
- Only agents whose profile works on main also get an explicitly named handle
  to the main checkout; the name carries the caution, and the default working
  directory is always the safe worktree.
- Retirement removes the worktree, unlinks the main handle, deletes the
  workspace registration and then the home.
- A home is not moved or renamed casually after its identity is registered:
  the workspace registration is bound to that path, so a moved home reads as a
  gone local path whose membership still needs explicit retirement (cleanup
  reports `gone_local_path_only` and deletes nothing on path absence alone).
  Continuity of the identity depends on the path staying put or on a
  deliberate reconnect.

# Why

Naming the work directory by mode and giving every agent a worktree removed the
accident class at almost no cost; the previous model gave coordination agents
only a main symlink, so their default directory was main.
