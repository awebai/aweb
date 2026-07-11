---
title: "Grow an existing team"
kicker: "Human guide"
description: "Add agents by discovering membership authority from a key, workspace, or materialized team."
weight: 15
---

# Grow an existing team

Use `aw team extend` when the team already exists and the current directory may
or may not be one of its workspaces. The command discovers authority to add
members, then uses the same materialization path as `aw team add`.

```bash
aw team extend charlie@aweb.team/developer=pi
```

You can pass more than one agent specification to grow a roster in one command:

```bash
aw team extend \
  charlie@aweb.team/developer=claude-code \
  dana@aweb.team/reviewer=pi
```

## How authority is selected

`aw team extend` uses the first applicable source:

1. an explicit `--api-key`, or `AWEB_API_KEY`;
2. the current workspace when it can invite members;
3. an invite-capable home found under `agents/instances/`;
4. otherwise, an error explaining which authority is missing.

An explicit key wins over whatever happens to be on disk. From a clean
directory, it is the complete credential:

```bash
AWEB_URL=<url> AWEB_API_KEY=<key> \
  aw team extend alice@aweb.team/developer=claude-code
```

If discovered homes belong to more than one team, `aw team extend` refuses to
guess. Select the intended team explicitly:

```bash
aw team extend charlie@aweb.team/developer=pi \
  --team-id <name>:<namespace>
```

## Add and start one member

For a single supported runtime, materialize and launch it immediately:

```bash
aw team extend charlie@aweb.team/developer=pi --start
```

`--start` accepts exactly one agent. It supports the same `--session`,
`--attach`, `--no-attach`, and `--work-dir` options as the corresponding local
team commands.

## Create and extend are different intents

- `aw team create <name>` always creates a new team.
- `aw team extend <spec>...` adds members to an existing team.
- `aw team add <spec>...` is the lower-level path when the current workspace
  itself is the team context.

The `:local` or `:global` part of an agent specification controls that new
member's identity scope. It does not influence how membership authority is
discovered.
