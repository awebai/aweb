---
title: "Add an AI tool to a team"
kicker: "Human guide"
description: "Materialize one team member, isolate its work, and start a supported runtime."
weight: 10
---

# Add an AI tool to a team

Use this path when the current directory is already connected to the team and
you want to add one member. `aw team add` uses the current workspace's `.aw`
state as the membership authority. If the current directory is not an active
team workspace, the command stops instead of guessing which team to use.

## Materialize and start one agent

```bash
aw team add charlie@aweb.team/developer=pi --start
```

The specification selects Charlie's member name, the `developer` profile from
the public `aweb.team` blueprint, and Pi as the runtime.

## Exactly where Charlie is created

Let `D` be the directory where you run the command. Let `R` be the Git
repository top-level when `D` is inside a Git worktree; outside Git, `R` is
`D`. Without `--home`, Charlie's home is:

```text
R/agents/instances/charlie/
```

This means that running `aw team add` from `repo/src/` still creates the home at
`repo/agents/instances/charlie/`. The command prints the absolute home path when
it finishes.

The home is a complete, distinct team member:

```text
charlie/
  .aw/
    signing.key       # Charlie's key, not the caller's key
    teams.yaml        # Charlie's installed team membership
    team-certs/       # Charlie's membership certificate
    workspace.yaml    # Charlie's aweb service connection
    profile/
      profile.yaml
      instructions.md
      ref.json        # pinned blueprint/profile/runtime provenance
  AGENTS.md
  worktree/           # isolated Git worktree when a work repo is available
```

The command creates the membership, materializes the profile, connects the
member to the team's aweb service, injects the current team guidance, and then
sets up its Git worktree. It does not reuse the caller's `.aw` directory.

Without `--start`, this is where the command stops: Charlie exists as a
materialized team member, but no Pi process is running. With `--start`, exactly
one agent is allowed and the command immediately launches that home through the
same path as `aw team up`.

## Where the runtime starts

The launched AI process starts in Charlie's **home**:

```text
cd R/agents/instances/charlie && exec pi --approve
```

It does not start in `worktree/`. The home is the identity and instruction
boundary, so Charlie runs `aw` there. Charlie changes into `worktree/` for Git,
tests, and builds.

`--start` attaches your terminal to the tmux session by default. Use
`--no-attach` to leave it running in the background. Without `--start`, run
`aw team up` from anywhere inside the same Git worktree—or from `D` outside
Git—to start all materialized homes. `aw team up --dry-run` prints each home and
runtime command first.

## Choose another home or work repository

`--home` replaces the default home path for one agent. A relative path is
resolved from the directory where you invoke the command:

```bash
aw team add charlie@aweb.team/developer=pi \
  --home ~/aweb-agents/charlie
```

`--home` accepts exactly one agent. If that home is outside Git and you do not
provide `--work-dir`, no worktree is created and the agent works directly in its
home.

Point the agent's worktree at another Git repository with `--work-dir`:

```bash
aw team add charlie@aweb.team/developer=pi \
  --home ~/aweb-agents/charlie \
  --work-dir ~/prj/customer-app \
  --start
```

The checkout at `~/prj/customer-app` remains untouched. aweb creates a Git
worktree at `~/aweb-agents/charlie/worktree/` on branch `charlie`. The home and
the repository it works on do not have to live in the same directory tree.

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
[Running materialized agents](running-agents.md).
