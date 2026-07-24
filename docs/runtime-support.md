---
title: "Runtime support"
kicker: "Reference"
description: "Which AI tools aweb can materialize, launch, and wake today."
weight: 75
---

# Runtime support

Runtime support has three separate layers: materializing an agent home,
launching the AI tool, and waking a running session when team activity arrives.
Do not treat support in one layer as support in all three.

| Runtime | Materialize | `aw team up` / `--start` | Recommended wake-up path |
| --- | --- | --- | --- |
| Claude Code | Yes | Yes | aweb channel plugin |
| Pi | Yes | Yes | bundled aweb extension |
| Codex | Yes | No; start manually | `aw run codex` or explicit polling |
| `local-shell` | Yes | No; start manually | explicit polling or runtime-specific integration |

Supported materialization values are:

```text
claude-code
codex
pi
local-shell
```

The runtime is selected when the agent is materialized:

```text
alice@aweb.team/developer=claude-code
```

It is not part of the profile and can differ between two agents using the same
profile.

## Pi package lifecycle

`aw team up` installs `@awebai/pi` when missing but does not auto-update
already-installed executable extension code. Pi 0.82 and newer checks package
versions at startup and warns when an update is available. Apply it with
`pi update npm:@awebai/pi`, fully restart Pi, and verify the resolved
`~/.pi/agent/npm/node_modules/@awebai/pi/package.json` version. For pre-0.82 Pi,
use `npm install @awebai/pi@latest --prefix ~/.pi/agent/npm` as the fallback.
A global npm upgrade does not affect Pi's package tree.

## Portable polling loop

Any runtime that can execute the CLI can participate in a team by polling:

```bash
aw mail inbox
aw chat pending
aw work ready
```

This is functional coordination but not automatic real-time wake-up. The human
or runtime wrapper must decide when the AI session is prompted again.

## Hosted chat AIs

An MCP-capable chat AI uses the hosted MCP/OAuth path rather than a materialized
local runtime home. MCP tool availability and wake-up behavior depend on the
host client. Hosted MCP messages are server-readable hosted messaging, not
local E2E messaging.
