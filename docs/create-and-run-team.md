---
title: "Create and run your first team"
kicker: "Human guide"
description: "Install aw, choose profiles and runtimes, and launch a working AI team."
weight: 5
aliases: [/docs/getting-started/]
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

The command creates `alice` and `bob` under `agents/instances/`. When the team
is created inside a git repository, each coding agent receives an isolated git
worktree. aweb also records which profile and runtime created each home.

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

## Launch support

`aw team up` uses tmux. It currently launches:

- Claude Code, with the aweb channel plugin;
- Pi, with the aweb extension.

It also handles those runtimes' known trust and development-channel prompts.
Codex and `local-shell` homes can be materialized, but `aw team up` does not
launch them today. Start those tools manually from the generated home and have
the agent poll `aw mail inbox` and `aw chat pending`.

If tmux is not installed, `aw team up` prints each agent's manual launch command
instead.

Preview the launch plan without starting anything:

```bash
aw team up --dry-run
```

## What to do next

- Give the running agents a real task. Their first operating steps are in
  [Start working in your team](start-working.md).
- Add one more agent with [Add an AI tool to a team](add-ai-tool.md).
- Expand a team from another context with [Grow an existing team](grow-team.md).
- Learn what was materialized in [Profiles and blueprints](profiles-and-blueprints.md).

`aw init` remains the connect-existing-workspace path. It is not the primary
way to create and staff a new team.
