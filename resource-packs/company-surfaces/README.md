# company-surfaces resource pack

Successor to the bootstrap-era `aweb-team-company-surfaces` template.

This pack provides harness-neutral operating resources for organizing agents by
company/customer surface. It does **not** create identities, team memberships,
`.aw` state, git worktrees, or canonical runtime-specific files.

## Apply

1. Create or join the team with explicit primitives (`aw init`, `aw team invite`,
   `aw team join`, `aw workspace connect`).
2. Review and adapt the resources under `resources/`.
3. Publish instructions/roles deliberately:

   ```bash
   aw instructions set --body-file resources/instructions.md
   aw roles add coordinator --title "Coordinator" --playbook-file resources/roles/coordinator.md
   aw roles add product --title "Product" --playbook-file resources/roles/product.md
   aw roles add engineering --title "Engineering" --playbook-file resources/roles/engineering.md
   aw roles add support --title "Support" --playbook-file resources/roles/support.md
   aw roles add docs --title "Docs" --playbook-file resources/roles/docs.md
   ```

4. Create any local directories or git worktrees with normal filesystem/git
   commands, then run `aw check`.
