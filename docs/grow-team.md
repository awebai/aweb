---
title: "Orchestrate more local agents"
description: "Add agents by discovering membership authority from a key, workspace, or materialized team."
weight: 15
---

# Orchestrate more local agents

For people setting up aweb.

> **Status: current optional team-growth helper.** Membership is the aweb
> authority; profiles, homes, worktrees, runtime selection, and process launch
> remain optional operator/orchestrator choices.

For ordinary membership, use `aw team invite` and `aw team join`. The admin
command below is for operators who also want local home/profile materialization.

Use `aw team admin extend` when the team already exists and the current directory may
or may not be one of its workspaces. The command discovers authority to add
members, then uses the same materialization path as `aw team admin add`.

```bash
aw team admin extend charlie@aweb.team/developer=pi
```

You can pass more than one agent specification to grow a roster in one command:

```bash
aw team admin extend \
  charlie@aweb.team/developer=claude-code \
  dana@aweb.team/reviewer=pi
```

## How authority is selected

`aw team admin extend` uses the first applicable source:

1. a person's setup key in `--api-key` or `AWEB_API_KEY` (older servers without key-kind metadata keep their existing API behavior);
2. the current workspace when it can invite members;
3. exactly one invite-capable home found under `agents/instances/` for the requested team; the command prints the chosen creator home;
4. otherwise, an error explaining which authority is missing.

A person's explicit setup key wins over whatever happens to be on disk. An
agent's workspace key instead uses that team's native signing workspace, with
a notice; without one, the command explains how to select a creator or use a
setup key. A stored workspace key never creates another identity. From a clean
directory, a person's setup key is the complete credential:

```bash
AWEB_URL=<url> AWEB_API_KEY=<key> \
  aw team admin extend alice@aweb.team/developer=claude-code
```

If several candidate homes belong to the requested team, extend lists them and
refuses before writing: run from the creating workspace or select its
`--identity-home`. Directory order never chooses the creator.

If discovered homes belong to more than one team, `aw team admin extend` refuses to
guess. Select the intended team explicitly:

```bash
aw team admin extend charlie@aweb.team/developer=pi \
  --team-id <name>:<namespace>
```

## Add and start one member

For a single supported runtime, materialize and launch it immediately:

```bash
aw team admin extend charlie@aweb.team/developer=pi --start
```

`--start` accepts exactly one agent. It supports the same `--session`,
`--attach`, `--no-attach`, and `--work-dir` options as the corresponding local
team commands.

## Create and extend are different intents

- `aw team admin create <name>` always creates a new team.
- `aw team admin extend <spec>...` adds members to an existing team.
- `aw team admin add <spec>...` is the lower-level path when the current workspace
  itself is the team context.

The `:local` or `:global` part of an agent specification controls that new
member's identity scope. It does not influence how membership authority is
discovered.
