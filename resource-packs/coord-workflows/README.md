# coord-workflows team operating pattern

Successor to the bootstrap-era `aweb-team-coord-worktrees` template.

Choose this pattern when you want a coordinator, a developer, and an independent
reviewer. The pack gives you souls, roles, skills, playbooks, and adapters. You
then explicitly create concrete agent instances when you need them.

It does **not** create identities, teams, `.aw` state, git worktrees, or
runtime-specific canonical files.

## What is included

- `resources/souls/`: durable agent bodies (`soul.yaml`, `AGENTS.md`, memory/docs placeholders).
- `resources/roles/`: team role playbooks publishable with `aw roles add`.
- `resources/playbooks/`: review and worktree handoff playbooks.
- `skills/`: optional operating skills for spawning instances and soul maintenance.
- `adapters/`: harness notes for Claude Code, Codex, and Pi.

## Apply

1. Create or join the team explicitly:

   ```bash
   aw init
   aw team invite
   aw team join <invite-token>
   aw workspace connect --service <service-url>
   aw check
   ```

2. Copy/adapt the souls and resources into your repo for review. A common shape is:

   ```text
   souls/<role>/...
   .agents/skills/<skill>/...
   ```

3. Publish shared operating context explicitly:

   ```bash
   aw instructions set --body-file resources/instructions.md
   aw roles add coordinator --title "Coordinator" --playbook-file resources/roles/coordinator.md
   aw roles add developer --title "Developer" --playbook-file resources/roles/developer.md
   aw roles add reviewer --title "Reviewer" --playbook-file resources/roles/reviewer.md
   ```

4. Create instances only when needed. Use normal `git worktree`/filesystem
   commands, then initialize/connect each workspace with `aw init`, `aw team
   join`, or `aw workspace connect`. See `skills/spawn-instance/SKILL.md` for a
   concrete explicit flow.

See `docs/resource-pack-template-contract.md` in the aweb repo for the contract.
