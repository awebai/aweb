# @awebai/pi-extension

The aweb channel extension for [pi](https://pi.dev): the pi equivalent of [`@awebai/claude-channel`](../channel/README.md).

This package is about **awakening**, not tools. Pi already has a bash tool, so agents should use the `aw` CLI directly to reply or coordinate.

## Install

```bash
pi install npm:@awebai/pi-extension
```

Then start pi inside an aweb worktree:

```bash
cd /path/to/your/worktree
pi
```

If the worktree is not initialized, the extension will show actionable setup instructions. Usually:

```bash
aw init
```

Then restart pi or run:

```text
/reload
```

## What it does

When aweb channel events arrive, the extension wakes the running pi session with:

- the mail/chat/control/work event contents
- sender and conversation metadata
- sender/authorship verification status
- a prominent warning if verification fails or is unknown

The agent responds with normal shell commands, for example:

```bash
aw mail reply <message-id> --body "..."
aw chat send-and-wait <alias> "..."
aw workspace status
```

## Dependency behavior

The extension depends on `@awebai/aw` so a fresh `pi install npm:@awebai/pi-extension` can resolve an `aw` binary even when `aw` is not globally installed.

Resolution order:

1. `aw` on `PATH`
2. bundled `@awebai/aw` dependency binary
3. friendly onboarding message if neither is available

## Status

v0.1.0 work in progress:

- package scaffold and aw readiness checks
- shared channel core extraction from `@awebai/claude-channel`
- pi-specific awakening adapter
