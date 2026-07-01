# Retired bootstrap-era layout scenarios

The `aw agents` command family is retired. This reference is historical context
for recognizing old project-local `agents/` directories and planning a manual
migration. Do not run old `aw agents ...` commands from this document.

## Recognize the old layout

A legacy repo-local layout commonly looks like:

```text
agents/
  team.yaml
  docs/
  roles/
  home/<responsibility>/AGENTS.md
  worktrees/<name>/
```

Runtime identity state may exist under `agents/home/*/.aw/` or
`agents/worktrees/*/.aw/`. Back it up before moving or deleting anything.

## Manual migration checklist

1. Inventory responsibilities, roles, and instructions from `agents/team.yaml`,
   `agents/roles/`, and `agents/docs/`.
2. Inventory local identity state from each concrete home/worktree:
   `.aw/signing.key`, `.aw/identity.yaml`, `.aw/teams.yaml`, and
   `.aw/team-certs/`.
3. Recreate or connect active workspaces with current primitives:
   - `aw team invite` / `aw team join` for normal hosted joins;
   - `aw id team request`, controller-side `aw id team add-member`, and
     `aw id team fetch-cert` for BYOT cross-machine joins;
   - `aw init`, `aw workspace connect`, or `aw service init` for service
     binding;
   - `git worktree add` or `aw workspace add-worktree` for extra same-repo
     worktrees.
4. Move reusable role/instruction/home files into current team blueprints or
   resource packs. Do not move final names, DIDs, addresses, certs, or `.aw/`
   state into committed resources.

## Recovery cautions

- Never delete a signing key or team certificate because a layout looks stale.
- Do not treat `agents/team.yaml` as membership authority; team authority lives
  in hosted service state or AWID controller-signed certificates.
- For hosted teams, do not try to sign membership locally; use hosted invite or
  dashboard add-existing-identity flows.
- For BYOT teams, only the controller holder signs certificates.
