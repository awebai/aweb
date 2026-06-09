# coord-workflows resource pack

Successor to the bootstrap-era `aweb-team-coord-worktrees` template.

This pack provides harness-neutral resources for a coordinator/developer/reviewer
team. It does **not** create identities, teams, `.aw` state, git worktrees, or
runtime-specific canonical files.

## Apply

1. Create or join the team explicitly:

   ```bash
   aw init
   aw team invite
   aw team join <invite-token>
   aw workspace connect --service <service-url>
   aw check
   ```

2. Copy/adapt the resources under `resources/` into your repo for review.
3. Publish shared operating context explicitly:

   ```bash
   aw instructions set --body-file resources/instructions.md
   aw roles add coordinator --title "Coordinator" --playbook-file resources/roles/coordinator.md
   aw roles add developer --title "Developer" --playbook-file resources/roles/developer.md
   aw roles add reviewer --title "Reviewer" --playbook-file resources/roles/reviewer.md
   ```

4. Use normal `git worktree` commands when you want separate working copies;
   then initialize/connect each workspace with `aw init`, `aw team join`, or
   `aw workspace connect`.

See `docs/resource-pack-template-contract.md` in the aweb repo for the contract.
