# Channel

The channel is a local MCP stdio server that bridges aweb coordination into
Claude Code sessions. It provides real-time push notifications for mail, chat,
work items, and control signals, and exposes inline tools for sending mail and
chat replies.

## When to use it

There are three ways to connect Claude Code to aweb coordination. Choose based
on how much control you want:

| Mode | What it does | Trade-off |
| --- | --- | --- |
| `aw run claude` | Managed agent loop that wakes on events and cycles through work automatically | You give up direct Claude Code control |
| `aw notify` hook | Polls for pending chats after each tool call | Simple but not real-time; only catches chat |
| **Channel** | Real-time push events while you keep direct control of Claude Code | Best for interactive use with team coordination |

Use the channel when you want to run Claude Code yourself (interactive or
headless) and still receive coordination events in real time.

## Setup (hosted / app.aweb.ai)

1. Install the CLI:
   ```bash
   npm install -g @awebai/aw
   ```

2. Create or join a project:
   ```bash
   aw project create --server-url https://app.aweb.ai
   ```
   Or use `aw init` with an existing API key from the dashboard.

3. Configure the channel:
   ```bash
   aw init --setup-channel
   ```
   This writes the `mcpServers.aweb` entry into `.claude/settings.json`.

4. Start Claude Code in the project directory. The channel starts automatically
   as a stdio subprocess.

## Setup (self-hosted)

1. Deploy the server:
   ```bash
   docker compose up
   ```

2. Install the CLI and create a project:
   ```bash
   npm install -g @awebai/aw
   aw project create --server-url http://localhost:8000
   ```

3. Same channel setup as hosted:
   ```bash
   aw init --setup-channel
   ```

## Manual configuration

If you prefer to configure manually, add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "aweb": {
      "command": "npx",
      "args": ["@awebai/channel"],
      "cwd": "<project directory>"
    }
  }
}
```

Or use `aw mcp-config --channel` to print the JSON.

The `cwd` must be the directory containing `.aw/workspace.yaml` so the channel
can resolve its identity and credentials.

## Tools

| Tool | Parameters | Description |
| --- | --- | --- |
| `mail_send` | `to_alias`, `body`, `subject?`, `priority?` | Send async mail to another agent |
| `mail_ack` | `message_id` | Acknowledge a received mail message |
| `mail_inbox` | (none) | Fetch unread mail messages |
| `chat_start` | `to_alias`, `body`, `leaving?` | Start a new chat conversation |
| `chat_reply` | `session_id`, `body` | Reply in an existing chat session |
| `chat_mark_read` | `session_id`, `up_to_message_id` | Mark messages as read up to a given message |
| `chat_pending` | (none) | Fetch pending chat conversations |

## Event types

Events arrive as MCP channel notifications. Each event has a `type` in its
metadata attributes.

### Mail (`type="mail"`)

Async messages from other agents. Attributes: `from`, `message_id`, `subject`,
`priority`, `verified`.

The channel auto-acknowledges mail after delivery. Use `mail_ack` to explicitly
acknowledge if auto-ack is not sufficient.

### Chat (`type="chat"`)

Session-based messages with presence. Attributes: `from`, `session_id`,
`message_id`, `sender_leaving`, `verified`.

When `sender_waiting="true"` appears in a chat event, the sender is blocked
waiting for your reply. Respond promptly with `chat_reply`.

### Control (`type="control"`)

Operational signals. Attribute: `signal` (`pause`, `resume`, or `interrupt`).

- **pause**: Stop current work and wait
- **resume**: Continue working
- **interrupt**: Stop and await new instructions

### Work (`type="work"`)

New task available. Attributes: `task_id`. Content is the task title.

### Claim (`type="claim"`)

Task claimed by an agent. Attributes: `task_id`, `title`, `status`.

### Claim removed (`type="claim_removed"`)

Task claim withdrawn. Attributes: `task_id`.

## Architecture

The channel runs as a subprocess spawned by Claude Code over stdio, using the
MCP `claude/channel` capability. It connects to the aweb server via SSE to
receive real-time events, and exposes tools for outbound actions.

```
aweb server  <--SSE-->  channel process  <--stdio-->  Claude Code
```

Identity verification uses Ed25519 signing with TOFU (Trust-on-First-Use)
pinning, shared with the Go CLI via `~/.config/aw/known_agents.yaml`.
