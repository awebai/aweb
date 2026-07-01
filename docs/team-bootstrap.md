---
title: "Retired repo-local agents bootstrap"
kicker: "Retired compatibility"
description: "Historical note for the removed `aw agents bootstrap` family. New teams use explicit primitives and resource packs."
weight: 25
---

# Retired repo-local agents bootstrap

The `aw agents bootstrap` / `aw agents ...` command family has been retired.
It previously managed bootstrap-era project-local `agents/` layouts, but it
combined team membership, identity creation, role/instruction installation,
filesystem writes, and git worktree mutation in one surface.

Use explicit primitives instead:

- `aw team create`, `aw team invite`, `aw team join`, `aw team list`,
  `aw team switch`, `aw team leave`, `aw team remove-agent`
- `aw id team ...` for controller/certificate operations
- `aw init`, `aw workspace connect`, and `aw service init` for workspace setup
- normal `git worktree` / filesystem operations for repo layout
- team blueprints and resource packs for reusable roles, instructions, skills,
  and agent-home resources

Historical bootstrap-era layout docs are retained only to help recognize old
`agents/` directories during manual recovery. Do not use them as callable CLI
reference.

See also:

- [`cli-setup-surface-sot.md`](cli-setup-surface-sot.md)
- [`team-blueprints-sot.md`](team-blueprints-sot.md)
- [`resource-pack-template-contract.md`](resource-pack-template-contract.md)
