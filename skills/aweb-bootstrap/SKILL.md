---
name: aweb-bootstrap
description: This skill should be used when recognizing or manually recovering legacy bootstrap-era `agents/` directories, or when migrating old bootstrap template repos toward primitive-first setup and resource packs. The `aw agents` command family is retired; do not recommend running it.
allowed-tools: "Bash(aw *)"
---

# aweb Bootstrap (retired command family)

The `aw agents bootstrap` / `aw agents ...` command family has been retired.
Use this skill only to recognize old bootstrap-era layouts and migrate them to
primitive-first setup. Do **not** instruct users to run `aw agents ...`.

For new setup, use:

- `aweb-team-membership` for invites, joins, certificates, switching, and
  hosted vs BYOT authority decisions;
- `aweb-identity` for local/global identity state, custody, keys, and address
  claims;
- ordinary `git worktree` / filesystem operations for worktrees and copied
  resources;
- team blueprints / resource packs for reusable roles, instructions, skills,
  and harness adapters.

## How to recognize an old bootstrap layout

Legacy repos may contain:

```text
agents/
  team.yaml
  docs/
  roles/
  home/<responsibility>/AGENTS.md
  worktrees/<name>/
```

Some homes or worktrees may contain ignored `.aw/` state and signing keys. Treat
that state as private identity material. Never delete it casually.

## Safe recovery policy

1. Inspect before mutating:
   - list `agents/team.yaml`, `agents/home/*`, `agents/worktrees/*`;
   - check for `.aw/signing.key`, `.aw/identity.yaml`, `.aw/teams.yaml`, and
     `.aw/team-certs/` under homes/worktrees;
   - run `aw workspace status` only from a concrete home/worktree, not from an
     uninitialized repo root.
2. Back up any `.aw/` directory before moving or deleting a legacy home.
3. Recreate needed workspaces with current primitives:
   - create/join teams with `aw team admin create`, `aw team invite`, `aw team join`,
     or controller-side `aw id team ...` primitives;
   - connect existing certs with `aw init`, `aw workspace connect`, or
     `aw service init`;
   - create worktrees with `git worktree add` or the narrower
     `aw workspace add-worktree` helper when appropriate.
4. Apply reusable resources from current team blueprints / resource packs rather
   than treating old `team.yaml` as authority.

## Migration guidance

- Roles and instructions from `agents/roles/` and `agents/docs/` can be copied
  into a resource pack or applied explicitly with `aw roles` / `aw instructions`.
- Per-agent startup text from `agents/home/<responsibility>/AGENTS.md` can move
  into blueprint profile instructions or a manually maintained home.
- Final names, DIDs, addresses, certificates, and `.aw` state must remain local
  runtime state; do not commit them into resource packs.
