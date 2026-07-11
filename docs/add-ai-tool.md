---
title: "Add an AI tool to a team"
kicker: "Human guide"
description: "Materialize one team member, isolate its work, and start a supported runtime."
weight: 10
---

# Add an AI tool to a team

Use this path when the current directory is already connected to the team and
you want to add one member. `aw team add` uses the current workspace as the
membership authority.

## Materialize and start one agent

```bash
aw team add charlie@aweb.team/developer=pi --start
```

The specification selects Charlie's team name, the `developer` profile from
the public `aweb.team` blueprint, and Pi as the runtime. `--start` materializes
the home and launches it through the same path as `aw team up`.

`--start` accepts exactly one agent. To add several members, omit `--start`,
then run `aw team up` after all homes have been materialized.

## Put the work in another repository

An agent's home contains its identity and operating resources. Its worktree is
where it edits and builds the project. Point that worktree at another git
repository with `--work-dir`:

```bash
aw team add charlie@aweb.team/developer=pi \
  --work-dir ~/prj/customer-app \
  --start
```

The checkout at `~/prj/customer-app` remains untouched. aweb creates Charlie's
isolated branch and worktree beneath the materialized home.

## Choose identity scope deliberately

Identity scope belongs to the agent, not the team:

```bash
aw team add local-reviewer@aweb.team/reviewer:local=pi
aw team add public-reviewer@aweb.team/reviewer:global=pi
```

When you omit the scope, the profile supplies the default. Every currently
published `aweb.team` profile defaults to local. Pass `:local` or `:global`
explicitly to override the profile:

- `:local` selects a team-scoped identity.
- `:global` creates or reuses a durable AWID identity that can hold public
  addresses and memberships in more than one team.

Hosted versus BYOT is a separate choice about who controls the team.

## Runtime limits

Claude Code and Pi can be started through `--start` and `aw team up`. Codex and
`local-shell` can be materialized, but must currently be started manually from
the generated home. Those agents need to poll `aw mail inbox` and
`aw chat pending` unless their runtime supplies another wake-up mechanism.

For the complete local layout and tmux lifecycle, see
[Running materialized agents](/docs/running-agents/).
