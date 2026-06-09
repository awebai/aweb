# company-surfaces team operating pattern

Successor to the bootstrap-era `aweb-team-company-surfaces` template.

Choose this pattern when you want agents organized by customer-visible company
surfaces: coordination, product, engineering, support, and docs. The pack gives
you souls, roles, skills, playbooks, and adapters. You then explicitly create
concrete agent instances when you need them.

It does **not** create identities, team memberships, `.aw` state, git worktrees,
or canonical runtime-specific files.

## What is included

- `resources/souls/`: durable agent bodies for each surface.
- `resources/roles/`: team role playbooks publishable with `aw roles add`.
- `resources/playbooks/`: intake and release handoff playbooks.
- `skills/`: optional soul-maintenance guidance.
- `adapters/`: harness notes for Claude Code, Codex, and Pi.

## Apply

1. Create or join the team with explicit primitives (`aw init`, `aw team invite`,
   `aw team join`, `aw workspace connect`).
2. Review and adapt the souls/resources into your repo, commonly under:

   ```text
   souls/<surface>/...
   .agents/skills/<skill>/...
   ```

3. Publish instructions/roles deliberately:

   ```bash
   aw instructions set --body-file resources/instructions.md
   aw roles add coordinator --title "Coordinator" --playbook-file resources/roles/coordinator.md
   aw roles add product --title "Product" --playbook-file resources/roles/product.md
   aw roles add engineering --title "Engineering" --playbook-file resources/roles/engineering.md
   aw roles add support --title "Support" --playbook-file resources/roles/support.md
   aw roles add docs --title "Docs" --playbook-file resources/roles/docs.md
   ```

4. Create concrete instances only when needed, using normal filesystem/git
   commands plus explicit aweb invite/join/init/connect primitives. Then verify
   with `aw check`.
