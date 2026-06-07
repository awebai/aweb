# aweb agents bootstrap scenarios and checklists

This reference is support material for the aweb-bootstrap skill. Use it
when you need concrete examples, troubleshooting checklists, or a quick
"what should I run next?" guide.

It is intentionally narrower than docs/team-bootstrap.md: it focuses on
common decision points and failure modes.

## Quick mental model

- Template repo = blueprint for roles, instructions, and agent home
  templates.
- Default generated layout = project-local `agents/` directory
  containing `home/`, `worktrees/`, `roles/`, `docs/`, and `team.yaml`.
- Work target = what each agent's `work` symlink points at: the repo
  root (`work: repo_root`) or a generated git worktree
  (`work: git_worktree`).
- Team source = the authority the generated agents join.
- Identity prefix = the per-human slug used to avoid alias/address
  collisions in shared repos.
- First generated workspace = bootstrap anchor. It connects first;
  roles/instructions install through it; all other generated agents
  join through invites from that established team context.
- BYOT means bring your own team, including your own namespace/domain
  and controller key. Do not present a separate domain-only bootstrap
  mode.

Team-source precedence:

- Explicit sources conflict: use only one of `AWEB_API_KEY`,
  `--invite-token`, `--username`, or `--namespace/--team`.
- With no explicit source, an initialized caller cwd forwards its
  current active team.
- With no explicit source and no caller workspace, an interactive run
  uses hosted onboarding.
- Non-interactive runs need an explicit source or initialized caller
  workspace.

## Scenario: first-time hosted team from a template

Goal: create a new aweb.ai team and provision agent workspaces from a
template.

Checklist:

- Run from the root of the project git repo.
- Confirm the target agents directory does not already exist. Default:
  `agents/`.
- Pick a template.
- Pick a human-specific `--identity-prefix`.

Example:

  cd /path/to/project-repo
  aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
    --username alice \
    --identity-prefix juan

Example with a non-default agents directory:

  cd /path/to/project-repo
  aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
    --username alice \
    --identity-prefix juan \
    --agents-dir aweb-agents

Notes:

- Bootstrap creates `agents/home/<responsibility>/` for every live
  agent home.
- Worktree-bound agents get checkouts under
  `agents/worktrees/<worktree-name>/`.
- The repo root is not an aw workspace; humans should start
  Codex/Claude/Pi from `agents/home/<responsibility>/`.

## Scenario: second human provisions the same repo

Goal: another human clones the repo and creates their own ignored
identity state for the same committed layout.

Checklist:

- Do not run bootstrap over the existing `agents/` directory.
- Get an invite token, API key, BYOT authority, or current workspace
  context for the same team.
- Use a different `--identity-prefix`.

Example:

  git pull
  aw agents provision --invite-token <token> --identity-prefix maria
  cd agents/home/coordinator
  codex

Expected behavior:

- Committed `agents/team.yaml`, `roles/`, `docs/`, and
  `home/*/AGENTS.md` remain unchanged.
- Local `.aw/` state and `work` symlinks are regenerated under
  `agents/home/*/`.
- Worktree directories are under `agents/worktrees/`.

## Scenario: customize the template before applying it

Goal: change roles, agent responsibilities, naming policy, or
instructions before any team state is created.

Checklist:

- Clone or fork the template first.
- Edit `team.yaml`, `roles/*.md`, `docs/team.md`, and
  `home/<responsibility>/AGENTS.md` as needed.
- Run `aw agents bootstrap /path/to/template --dry-run` from the
  project repo root to validate.
- Bootstrap the local template directory only after the plan looks
  right.

Example:

  git clone https://github.com/awebai/aweb-team-dev-review.git my-team-template
  cd my-team-template
  # edit team.yaml / roles / docs / home
  cd /path/to/project-repo
  aw agents bootstrap /path/to/my-team-template --dry-run --identity-prefix juan
  aw agents bootstrap /path/to/my-team-template --username alice --identity-prefix juan

## Scenario: BYOT

Goal: bootstrap a team under a namespace/domain you control.

Checklist:

- Confirm the namespace is registered and the controller key is
  available locally.
- Remember BYOT includes bringing your own domain; there is no separate
  supported domain-only bootstrap mode.
- Bootstrap will connect the first generated workspace, install
  roles/instructions there, then invite/connect the remaining agents.

Example shape:

  aw agents bootstrap https://github.com/awebai/aweb-team-dev-review.git \
    --namespace example.com \
    --team dev \
    --identity-prefix juan

If you are also self-hosting the coordination stack, add:

  --aweb-url http://localhost:8000
  --registry http://localhost:8010

## Scenario: existing hosted team via API key

Goal: provision a template into the hosted team associated with an API
key.

Checklist:

- Set `AWEB_API_KEY`.
- Optionally set `AWEB_URL` or pass `--aweb-url` to target a
  non-default stack; otherwise the hosted default is used.
- Do not also pass `--username`, `--invite-token`, or BYOT flags.

Example:

  AWEB_API_KEY=aw_sk_... \
    aw agents bootstrap /path/to/template --identity-prefix juan

## Scenario: existing team via invite token

Goal: accept an invite into the first generated workspace and use it as
the anchor for the rest of bootstrap.

Example:

  aw agents bootstrap /path/to/template \
    --invite-token <token> \
    --identity-prefix maria

## Scenario: current workspace forwarding

Goal: run bootstrap from an existing aw workspace and forward that
active team into the generated template workspaces.

Checklist:

- Confirm `aw workspace status` succeeds in the caller cwd.
- Do not pass another explicit team source.
- Bootstrap will create a one-use invite from the current active team
  for the first generated workspace.

## Scenario: dry-run planning

Goal: validate the plan and see generated workspace commands without
changing files, identities, or server state.

Example:

  aw agents bootstrap /path/to/template --dry-run --identity-prefix juan

## Scenario: add a new responsibility later

Repo-root local agent:

  aw agents add support --role support

Worktree-bound local agent:

  aw agents add-worktree developer --role developer

Global BYOT agent:

  aw agents add support \
    --global \
    --namespace example.com \
    --team circle \
    --identity-prefix juan

## Scenario: remove a responsibility

Remove the shared blueprint entry:

  aw agents remove support --remove-layout

Remove this human's local ignored state:

  aw agents remove support --deprovision-local

Delete a global address when you have the required namespace authority:

  aw agents remove support --delete-global-address

`--remove-layout` is not a team-wide revocation. Other humans' local
`.aw/` state and certificates continue until they deprovision or the
certs expire/revoke separately.

## Legacy mode: old out-of-repo bootstrap

Use legacy mode only for existing scripts/templates that still expect
the old layout.

- `--work-directory <path>` selects legacy work-directory mode.
- `--work-repo-url <url-or-local-path>` selects legacy
  clone-then-bootstrap mode.
- The two flags are XOR.
- Do not combine `--agents-dir` with either legacy work flag.

## Worktree-bound agents

Use `work: git_worktree` when multiple agents will edit code in
parallel.

Requirements:

- The project directory must be a git repo.
- The template declares `work: git_worktree` for the relevant agent in
  `team.yaml`.

What bootstrap/add-worktree does:

- It creates `agents/worktrees/` and writes scoped `.gitignore`
  entries.
- It creates one git worktree per `work: git_worktree` agent.
- The live agent home remains under `agents/home/<responsibility>/`.
- Each worktree-bound agent gets its own `.aw/` state and local-scope
  identity.

Common pitfall:

- Alias collisions: in shared repos use `--identity-prefix` and a
  template local alias pattern such as `{user}-{classic-name}`.

## Quick validation after bootstrap/provision

In each generated agent directory (`agents/home/<responsibility>/`):

- aw workspace status
- aw whoami

If you are using a wake-up integration:

- start the Pi extension or the Claude Code channel plugin in that
  directory after initialization

## Troubleshooting patterns

If bootstrap fails:

- Stop and capture the first error.
- Do not retry over an existing `agents/` directory.
- Inspect/back up `.aw/` state before deleting generated directories.
- Prefer `aw agents provision`, `aw agents add`, or
  `aw agents remove` recovery commands over hand-editing identity
  state.

If a multi-human provision hits a conflict:

- Rerun with a different `--identity-prefix` or naming pattern.
- Invite-only flows may discover existing aliases only at mutation
  time; this is expected fail-closed behavior.

If you see identity_mismatch or unverified messages in live channel
metadata:

- Compare with aw chat history output.
- Confirm the channel plugin / Pi package version is current.
- Prefer collecting a raw fetch payload before changing trust logic.
