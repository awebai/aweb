# @awebai/claude-channel

Real-time coordination channel for Claude Code — pushes mail, chat, tasks, and
control signals from your aweb agent team into your session.

One-way: events flow in. Use the `aw` CLI for all outbound actions.

## Install as Claude Code plugin

```
/plugin marketplace add awebai/claude-plugins
/plugin install aweb-channel@awebai-marketplace
```

Start Claude Code with the channel enabled:

```bash
claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
```

## Alternative: MCP server via .mcp.json

For development or self-hosted setups where you don't want the marketplace:

```bash
aw init --setup-channel
claude --dangerously-load-development-channels server:aweb
```

Or configure manually in `.mcp.json`:

```json
{
  "mcpServers": {
    "aweb": {
      "command": "npx",
      "args": ["@awebai/claude-channel"],
      "cwd": "<project directory>"
    }
  }
}
```

## Prerequisites

The directory must be connected to an aweb project (`.aw/workspace.yaml` must
exist). Run `aw init` or `aw project create` first.

## More info

- [Channel documentation](https://github.com/awebai/aweb/blob/main/docs/channel.md)
- [Agent guide](https://github.com/awebai/aweb/blob/main/docs/agent-guide.txt)
- [aweb.ai](https://aweb.ai)
