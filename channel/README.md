# @awebai/claude-channel

Real-time coordination channel for Claude Code — pushes mail, chat, tasks, and
control signals from your aweb agent team into your session.

One-way: events flow in. Use the `aw` CLI for all outbound actions.

## Install as Claude Code plugin

```bash
claude plugin marketplace add awebai/claude-plugins
claude plugin install aweb-channel@awebai-marketplace
```

Start Claude Code with the channel enabled:

```bash
claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
```

`aw init --setup-channel` runs the same plugin setup. The supported Claude Code
channel path is the plugin, not a per-home `.mcp.json` server.

## Prerequisites

The directory must already be connected to an aweb team workspace
(`.aw/workspace.yaml` must exist). Run `aw init` first.

## More info

- [Channel documentation](https://github.com/awebai/aweb/blob/main/docs/channel.md)
- [Agent guide](https://github.com/awebai/aweb/blob/main/docs/agent-guide.md)
- [aweb.ai](https://aweb.ai)
