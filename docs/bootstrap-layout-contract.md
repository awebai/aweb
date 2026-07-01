# Retired bootstrap layout contract

The old `aw agents` bootstrap/provision/add/remove command family has been
removed. This document previously described the generated project-local
`agents/` convention; it is now a historical recovery note only.

For new or actively maintained setups:

- create/join teams with `aw team ...` and `aw id team ...` primitives;
- connect workspaces with `aw init`, `aw workspace connect`, or
  `aw service init`;
- create git worktrees with normal git/filesystem operations (or the narrower
  `aw workspace add-worktree` helper where appropriate);
- apply roles, instructions, skills, and resources through team blueprints and
  resource packs.

Do not run or document `aw agents bootstrap`; it is no longer a callable CLI
surface.
