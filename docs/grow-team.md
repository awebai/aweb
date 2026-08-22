---
title: "Orchestrate more local agents"
kicker: "Advanced guide"
description: "Add agents by discovering membership authority from a key, workspace, or materialized team."
weight: 15
---

# Orchestrate more local agents

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

1. an explicit `--api-key`, or `AWEB_API_KEY`;
2. the current workspace when it can invite members;
3. an invite-capable home found under `agents/instances/`;
4. otherwise, an error explaining which authority is missing.

An explicit key wins over whatever happens to be on disk. From a clean
directory, it is the complete credential:

```bash
AWEB_URL=<url> AWEB_API_KEY=<key> \
  aw team admin extend alice@aweb.team/developer=claude-code
```

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
