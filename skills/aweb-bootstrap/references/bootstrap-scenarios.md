# aweb Bootstrap scenarios and checklists

This reference is support material for the aweb-bootstrap skill. Use it when you need concrete examples, troubleshooting checklists, or a quick “what should I run next?” guide.

It is intentionally narrower than docs/team-bootstrap.md: it focuses on common decision points and failure modes.

## Quick mental model

- Template repo = blueprint for roles, instructions, and responsibility directories.
- Work directory/repo = the project/content agents see as `./work`.
- Team source = the authority the generated agents join.
- First generated workspace = bootstrap anchor. It connects first; roles/instructions install through it; all other generated agents join through invites from that established team context.
- BYOT means bring your own team, including your own namespace/domain and controller key. Do not present a separate domain-only bootstrap mode.

Team-source precedence:

- Explicit sources conflict: use only one of `AWEB_API_KEY`, `--invite-token`, `--username`, or `--namespace/--team`.
- With no explicit source, an initialized caller cwd forwards its current active team.
- With no explicit source and no caller workspace, an interactive run uses hosted onboarding.
- Non-interactive runs need an explicit source or initialized caller workspace.

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

## Scenario: BYOT (bring your own team)

Goal: bootstrap a team under a namespace/domain you control.

Checklist:

- Confirm you have a controller identity key for the namespace/domain.
- Remember BYOT includes bringing your own domain; there is no separate supported domain-only bootstrap mode.
- Bootstrap will connect the first generated workspace, install roles/instructions there, then invite/connect the remaining agents.

Example shape (values are placeholders):

  aw team bootstrap https://github.com/awebai/aweb-team-dev-review.git \
    --yes \
    --namespace example.com \
    --team dev \
    --work-directory /path/to/work

If you are also self-hosting the coordination stack, add:

  --aweb-url http://localhost:8000
  --registry http://localhost:8010

## Scenario: existing hosted team via API key

Goal: provision a template into the hosted team associated with an API key.

Checklist:

- Set AWEB_API_KEY.
- Optionally set AWEB_URL or pass --aweb-url to target a non-default stack; otherwise the hosted default is used.
- Do not also pass --username, --invite-token, or BYOT flags.

Example:

  AWEB_API_KEY=aw_sk_... \
    aw team bootstrap /path/to/template --work-directory /path/to/work

## Scenario: existing team via invite token

Goal: accept an invite into the first generated workspace and use it as the anchor for the rest of bootstrap.

Example:

  aw team bootstrap /path/to/template \
    --invite-token <token> \
    --work-directory /path/to/work

## Scenario: current workspace forwarding

Goal: run bootstrap from an existing aw workspace and forward that active team into the generated template workspaces.

Checklist:

- Confirm `aw workspace status` succeeds in the caller cwd.
- Do not pass another explicit team source.
- Bootstrap will create a one-use invite from the current active team for the first generated workspace.

## Scenario: dry-run planning

Goal: validate the plan and see generated workspace commands without changing files, identities, or server state.

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
