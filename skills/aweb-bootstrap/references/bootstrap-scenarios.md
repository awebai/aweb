# aweb Bootstrap scenarios and checklists

This reference is support material for the aweb-bootstrap skill. Use it when you need concrete examples, troubleshooting checklists, or a quick “what should I run next?” guide.

It is intentionally narrower than docs/team-bootstrap.md: it focuses on common decision points and failure modes.

## Quick mental model

- Template repo = blueprint for roles, instructions, and agent home templates.
- Default generated layout = project-local `agents/` directory containing `home/`, `worktrees/`, `roles/`, `docs/`, and `team.yaml`.
- Work target = what each agent's `work` symlink points at: the repo root (`work: repo_root`) or a generated git worktree (`work: git_worktree`).
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

- Run from the root of the project git repo.
- Confirm the target agents directory does not already exist. Default: `agents/`.
- Pick a template:
  - awebai/aweb-team-coord-worktrees for coordinator + developer/reviewer worktrees.
  - awebai/aweb-team-dev-review for a minimal 2-agent setup.
  - awebai/aweb-team-company-surfaces for a 6-agent cross-functional setup.

Example:

  cd /path/to/project-repo
  aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git --username alice

Example with a non-default agents directory:

  cd /path/to/project-repo
  aw team bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git --username alice --agents-dir aweb-agents

Notes:

- Bootstrap creates `agents/home/<agent>/` for every live agent home.
- Worktree-bound agents get checkouts under `agents/worktrees/<alias-or-agent>/`.
- The repo root is not an aw workspace; humans should start Codex/Claude/Pi from `agents/home/<agent>/`.

## Scenario: customize the template before applying it

Goal: change roles, agent responsibilities, names, aliases, or instructions before any team state is created.

Checklist:

- Clone or fork the template first.
- Edit `team.yaml`, `roles/*.md`, `docs/team.md`, and `home/<responsibility>/AGENTS.md` as needed.
- Run `aw team bootstrap /path/to/template --dry-run` from the project repo root to validate.
- Bootstrap the local template directory only after the plan looks right.

Example:

  git clone https://github.com/awebai/aweb-team-dev-review.git my-team-template
  cd my-team-template
  # edit team.yaml / roles / docs / home
  cd /path/to/project-repo
  aw team bootstrap /path/to/my-team-template --dry-run
  aw team bootstrap /path/to/my-team-template --username alice

## Scenario: BYOT (bring your own team)

Goal: bootstrap a team under a namespace/domain you control.

Checklist:

- Confirm you have a controller identity key for the namespace/domain.
- Remember BYOT includes bringing your own domain; there is no separate supported domain-only bootstrap mode.
- Bootstrap will connect the first generated workspace, install roles/instructions there, then invite/connect the remaining agents.

Example shape (values are placeholders):

  aw team bootstrap https://github.com/awebai/aweb-team-dev-review.git \
    --namespace example.com \
    --team dev

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
    aw team bootstrap /path/to/template

## Scenario: existing team via invite token

Goal: accept an invite into the first generated workspace and use it as the anchor for the rest of bootstrap.

Example:

  aw team bootstrap /path/to/template \
    --invite-token <token>

## Scenario: current workspace forwarding

Goal: run bootstrap from an existing aw workspace and forward that active team into the generated template workspaces.

Checklist:

- Confirm `aw workspace status` succeeds in the caller cwd.
- Do not pass another explicit team source.
- Bootstrap will create a one-use invite from the current active team for the first generated workspace.

## Scenario: dry-run planning

Goal: validate the plan and see generated workspace commands without changing files, identities, or server state.

Example:

  aw team bootstrap /path/to/template --dry-run

## Legacy mode: old out-of-repo bootstrap

Use legacy mode only for existing scripts/templates that still expect the old layout.

- `--work-directory <path>` selects legacy work-directory mode.
- `--work-repo-url <url-or-local-path>` selects legacy clone-then-bootstrap mode.
- The two flags are XOR.
- Do not combine `--agents-dir` with either legacy work flag.

## Worktree-bound agents: when to enable and what to expect

Use `work: git_worktree` when multiple agents will edit code in parallel.

Requirements:

- The project directory must be a git repo.
- The template declares `work: git_worktree` for the relevant agent in `team.yaml`.

What bootstrap does:

- It creates `agents/worktrees/` and writes scoped `.gitignore` entries.
- It creates one git worktree per `work: git_worktree` agent.
- The live agent home remains under `agents/home/<responsibility>/`.
- Each worktree-bound agent gets its own `.aw/` state and local-scope identity.

Common pitfall:

- Alias collisions: worktree agent aliases must not collide with existing team aliases.

## Quick validation after bootstrap

In each generated agent directory (`agents/home/<responsibility>/`):

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
