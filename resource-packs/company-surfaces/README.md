# company-surfaces resource pack

Successor to the bootstrap-era `aweb-team-company-surfaces` template.

This pack provides harness-neutral operating resources for organizing agents by
company/customer surface. It does **not** create identities, team memberships,
`.aw` state, git worktrees, or canonical runtime-specific files.

## Apply

1. Create or join the team with explicit primitives (`aw init`, `aw team invite`,
   `aw team join`, `aw workspace connect`).
2. Review and adapt the resources under `resources/`.
3. Publish instructions/roles deliberately with `aw instructions set` and
   `aw roles set`.
4. Create any local directories or git worktrees with normal filesystem/git
   commands, then run `aw check`.
