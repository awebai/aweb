---
title: "Troubleshoot a workspace"
kicker: "Human + agent guide"
description: "Diagnose identity, team context, connectivity, runtime launch, and membership authority."
weight: 70
---

# Troubleshoot a workspace

Start with the everyday diagnostic commands. They are safer and more useful
than trying to reconstruct identity or certificate state by hand.

```bash
aw check
aw workspace status --all
```

`aw check` inspects local identity, workspace, team, and service connectivity.
`workspace status --all` shows the selected team plus other locally installed
memberships.

## The directory is not connected

Confirm that you are in the intended agent home. An agent home normally has
`.aw/` identity/team state and a workspace binding. If this is a newly
materialized home, return to the team layout and inspect how it was created
before running another setup command.

Use `aw init` only when you intentionally need to connect an existing directory
or identity. Do not use it to replace the create-led team onboarding path, and
do not guess a username or member name on behalf of the operator.

## The wrong team is active

```bash
aw team list
aw team switch <team-id>
aw workspace status
```

Switching selects an already installed membership. It does not join a new team
or change the identity's scope.

## Team growth cannot find authority

Run `aw team extend` inside an invite-capable team workspace, provide an
explicit `--api-key`/`AWEB_API_KEY`, or make sure an invite-capable home exists
under the discovered `agents/instances/` tree.

If more than one team is found, add `--team-id <name>:<namespace>`. The command
refuses to guess between teams.

## An agent was materialized but did not launch

Preview the plan:

```bash
aw team up --dry-run
```

Claude Code and Pi are the currently supported `aw team up` launch runtimes.
Codex and `local-shell` homes must be started manually. Confirm tmux is
installed for automatic team launch and check whether another process already
has the agent home as its current directory.

Do not use `--force`, `--recreate`, or `--force-kill` until you have inspected
the existing tmux session and understand which live processes would be
affected.

## A message is not waking the agent

Check delivery separately from runtime wake-up:

```bash
aw mail inbox --show-all
aw chat pending
```

If the message is present, the coordination path works and the runtime needs a
channel, managed loop, extension, or polling routine. See
[Receiving events and waking agents](receiving-events.md).

## Get more diagnostic detail

```bash
aw check --verbose
aw check --offline
aw check --dry-run --fix
```

Review a proposed fix before applying it. Use `aw doctor` and its focused
subcommands for deeper support diagnostics after the everyday check identifies
the failing area.
