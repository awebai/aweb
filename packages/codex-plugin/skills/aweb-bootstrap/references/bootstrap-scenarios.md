# aweb Bootstrap scenarios and checklists

This reference is support material for the aweb-bootstrap skill. Use it when you need concrete examples, troubleshooting checklists, or a quick “what should I run next?” guide.

It is intentionally narrower than docs/team-bootstrap.md: it focuses on common decision points and failure modes.

## Scenario: first-time hosted team from a template (recommended)

Goal: create a new aweb.ai team and provision agent workspaces from a template.

Checklist:

- Run from a directory that is not inside an existing git repo/worktree.
- Pick a template:
  - awebai/aweb-team-dev-review for a minimal 2-agent setup.
  - awebai/aweb-team-company-surfaces for a 6-agent cross-functional setup.

Example (using an existing local work directory):

  aw team bootstrap https://github.com/awebai/aweb-team-dev-review.git --yes --work-directory /path/to/work

Example (clone the work repo into the template checkout):

  aw team bootstrap https://github.com/awebai/aweb-team-dev-review.git --yes --work-repo-url https://github.com/ORG/REPO.git

Notes:

- work-directory and work-repo-url are XOR: set exactly one.
- When work-repo-url is used, bootstrap clones into:

  <template-checkout>/worktrees/<derived-name>/

  where derived-name is the git-style repo directory name (basename with .git stripped).

## Scenario: BYOT (your own controller + namespace)

Goal: bootstrap a team under a namespace you control.

Checklist:

- Confirm you have a controller identity key for the namespace.
- Decide whether bootstrap should auto-provision (interactive) or just print next commands.

Example shape (values are placeholders):

  aw team bootstrap https://github.com/awebai/aweb-team-dev-review.git \
    --yes \
    --namespace example.com \
    --team dev \
    --work-directory /path/to/work

If you are also self-hosting the coordination stack, add:

  --aweb-url http://localhost:8000
  --registry http://localhost:8010

## Scenario: manual mode (print next commands)

Goal: validate the plan and generate the next steps without changing server state.

Checklist:

- Use dry-run to see the plan.
- Use the printed aw init commands inside each agent directory.

Example:

  aw team bootstrap /path/to/template --dry-run --work-directory /path/to/work

## Worktree agents: when to enable and what to expect

Use worktree agents when multiple agents will edit code in parallel.

Requirements:

- The work directory must be a git repo.
- The template must declare a worktrees: block in team.yaml.

What bootstrap does:

- It creates template worktrees/ (if missing) and git-excludes it locally.
- It creates one git worktree per entry.
- Each worktree agent gets its own .aw/ state and local-scope identity.

Common pitfall:

- Alias collisions: worktree agent aliases must not collide with existing team aliases.

## Quick validation after bootstrap

In each generated agent directory (agents/<responsibility>/):

- aw workspace status
- aw whoami

If you are using a wake-up integration:

- start the Pi extension or the Claude Code channel plugin in that directory after initialization

## Troubleshooting patterns

If bootstrap fails:

- Stop and capture the first error.
- Identify which directories were already created.
- Prefer completing the remaining steps rather than deleting existing .aw state.

If you see identity_mismatch or unverified messages in live channel metadata:

- Compare with aw chat history output.
- Confirm the channel plugin / Pi package version is current.
- Prefer collecting a raw fetch payload before changing trust logic.
