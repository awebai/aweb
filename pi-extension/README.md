# @awebai/pi

Aweb for [Pi](https://pi.dev): real-time channel awakenings, `aw` CLI onboarding, and aweb skills.

This package is the Pi integration for aweb. It is about **awakening**, not custom tools. Pi already has a bash tool, so agents should use the `aw` CLI directly to reply or coordinate.

## Install

```bash
pi install npm:@awebai/pi
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

Delivery behavior:

- mail and chat wake the LLM
- waiting chat and control signals steer the active turn
- ambient work/claim notifications are queued for the next natural turn

The agent responds with normal shell commands, for example:

```bash
aw mail reply <message-id> --body "..."
aw chat send-and-wait <alias> "..."
aw workspace status
```

## Dependency behavior

The package depends on `@awebai/aw` so a fresh `pi install npm:@awebai/pi` can resolve an `aw` binary even when `aw` is not globally installed.

Resolution order:

1. `aw` on `PATH`
2. bundled `@awebai/aw` dependency binary
3. friendly onboarding message if neither is available

## Skills

This package should also expose the canonical aweb Agent Skills via `pi.skills`, so one install gives both:

- channel awakenings
- instructions for using `aw` effectively

The skill bodies should remain canonical and harness-neutral; this package should package them for Pi rather than fork them.

## Shared core

The extension uses `@awebai/channel-core`, shared with `@awebai/claude-channel`, for:

- aweb signed API calls
- SSE event subscription and reconnect
- mail/chat fetch and read/ack behavior
- sender signature verification and trust normalization
- formatting awakenings with trust warnings
