# Retired aw agents layout and lifecycle contract

The `aw agents` command family (`bootstrap`, `plan`, `provision`, `add`,
`add-worktree`, and `remove`) has been retired and is no longer a callable CLI
surface.

This file is kept as a tombstone for older references to bootstrap-era
project-local `agents/` layouts. New setup and recovery guidance should use the
primitive-first surfaces instead:

- `aw team create|invite|join|list|switch|leave|remove-agent`
- `aw id team ...` for controller/certificate operations
- `aw init`, `aw workspace connect`, and `aw service init`
- explicit git/filesystem operations for worktrees and local layout
- team blueprints / resource packs for reusable agent resources

The divergent client-side naming planner from this surface was removed with the
command family; server-authoritative name suggestions are now handled through
`/v1/agents/suggest-alias-prefix`.
