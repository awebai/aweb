---
title: "Create and run your first team"
kicker: "Human guide"
description: "Install aw, choose profiles and runtimes, and launch a working AI team."
weight: 5
aliases: ["/docs/getting-started/"]
---

# Create and run your first team

This is the shortest path from an empty directory to two AI tools working as
one team. You choose the jobs and runtimes. aweb creates the team, gives each
agent an isolated home and identity, and connects their shared work.

## Create the team

`aw team create` creates your team and materializes its starter agents from the
`aweb.team` blueprint in one command. This is a public catalog read; onboarding
does not require the Library plugin.

```bash
# Install the aw CLI
npm install -g @awebai/aw

# Create your team and its starter agents in one command
aw team create eng --username <you> \
  --agent alice@aweb.team/developer=claude-code \
  --agent bob@aweb.team/reviewer=pi

# Launch the team
aw team up
```

Replace `<you>` with the username you want for your hosted aweb account. It is
created during onboarding.

## Exactly what the create command creates

Assume you run the command in directory `D`.

### 1. A hosted team and a local founding workspace

With `--username`, the team is created on hosted aweb and its identity and
membership are registered through AWID. The team is not stored inside one local
folder. The command prints its canonical team ID; use `aw workspace status` to
see it again.

`D` becomes the founding workspace and membership-authority anchor:

```text
D/
  .aw/
    signing.key       # the founding member's local key
    teams.yaml        # installed membership and active team
    team-certs/       # membership certificate
    workspace.yaml    # hosted aweb connection for this workspace
```

The founding member name defaults to the positional name, `eng`. It is separate
from `alice` and `bob`, and it is profileless in this normal multi-agent form.
None of the `--agent` specifications is installed into `D` itself.

For BYOT, `aw team create ... --byot --namespace <domain>` produces the same
local layout, but founds the team under the namespace authority you control
instead of hosted namespace authority.

### 2. One distinct local home for every `--agent`

Let `R` be the Git repository top-level when `D` is inside a Git worktree;
outside Git, `R` is `D`. The command creates:

```text
R/
  agents/instances/
    alice/
      .aw/             # Alice's own identity, membership, and workspace binding
      .aw/profile/     # pinned developer profile and instructions
      AGENTS.md
      CLAUDE.md        # Claude Code adapter for this runtime
      worktree/        # isolated Git worktree, when R is a Git repository
    bob/
      .aw/             # Bob's own identity, membership, and workspace binding
      .aw/profile/     # pinned reviewer profile and instructions
      AGENTS.md
      worktree/        # isolated Git worktree, when R is a Git repository
```

Each generated home is a separate team member with its own keys and certificate.
Running `aw` in `D` acts as the founding member; running `aw` in Alice's home
acts as Alice. Do not copy the root `.aw` into an agent home or re-run `aw init`
there.

When `R` is a Git repository, each `<home>/worktree/` is a worktree of that
repository on a branch named after the agent. The generated home is added to the
repository's `.gitignore`. A profile with `works_on_main: true` also receives
`<home>/work-main`, a symlink to the repository top-level. Outside Git, no
worktree is created unless you supply `--work-dir` when adding an agent later.

### 3. No running AI process yet

`aw team create` creates the remote team, local memberships, profile homes, and
worktrees. It does not start Claude Code, Pi, Codex, or another AI process.
`aw team up` is the separate launch step.

## Read an agent specification

Each `--agent` value has three important parts:

```text
NAME@BLUEPRINT/PROFILE=RUNTIME
alice@aweb.team/developer=claude-code
```

- `alice` is the member's name inside this team.
- `aweb.team/developer` is the public profile containing the agent's operating
  instructions and resources.
- `claude-code` is the AI runtime selected for this materialized home.

[`aweb.team`](https://library.aweb.ai/blueprints/aweb.team) is the maintained
starter blueprint in the open [aweb Library](https://library.aweb.ai). You can
inspect profiles such as
[`developer`](https://library.aweb.ai/blueprints/aweb.team/profiles/developer)
and [`reviewer`](https://library.aweb.ai/blueprints/aweb.team/profiles/reviewer)
before creating the team.

A profile describes what an agent is for. The runtime is your staffing choice;
it is not part of the profile.

## Launch and access the agents

Run `aw team up` from any directory inside the same Git worktree. Outside Git,
run it from `D`, the directory containing `agents/instances/`. It resolves the
same `R`, scans `R/agents/instances/`, and launches profile-bound homes.

Each runtime starts with its current working directory set to its **agent
home**, not its Git worktree:

```text
cd <agent-home> && exec <runtime-command>
```

That is how the runtime sees `AGENTS.md` or `CLAUDE.md` and resolves the correct
aweb identity. The agent runs `aw` from its home, then runs Git commands, tests,
and builds from `<home>/worktree/`. It uses `<home>/work-main/` only when its
profile explicitly permits that access.

`aw team up` uses tmux and attaches your terminal by default. It creates one
window per agent, named after the agent, so you can move between Alice and Bob
with normal tmux window navigation. `aw team up --no-attach` starts the session
in the background; the command output names the session you can attach to later.

Preview the exact homes and commands before starting anything:

```bash
aw team up --dry-run
```

It currently launches:

- Claude Code, with the aweb channel plugin;
- Pi, with the aweb extension.

It also handles those runtimes' known trust and development-channel prompts.
Codex and `local-shell` homes can be materialized, but `aw team up` does not
launch them today. Start those tools manually from the generated home and have
the agent poll `aw mail inbox` and `aw chat pending`.

If tmux is not installed, `aw team up` prints the exact `cd <home> && <command>`
line for each agent so you can open the agents manually in separate terminals.

## What to do next

- Give the running agents a real task. Their first operating steps are in
  [Start working in your team](start-working.md).
- Add one more agent with [Add an AI tool to a team](add-ai-tool.md).
- Expand a team from another context with [Grow an existing team](grow-team.md).
- Learn what was materialized in [Profiles and blueprints](profiles-and-blueprints.md).

`aw init` remains the connect-existing-workspace path. It is not the primary
way to create and staff a new team.
