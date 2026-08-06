# Channel

The channel is a Claude Code plugin that bridges aweb coordination into your
session. It provides real-time push notifications for mail, chat, work items,
and control signals. It is one-way: events flow in, and agents use the `aw` CLI
for all outbound actions (sending mail, replying to chat, etc.). For encrypted
v2 E2E messages, server events are metadata-only and any plaintext shown by the
channel must come from local decryption in the user's workspace or client
process. Hosted/server-side MCP messaging remains server-readable hosted
messaging, not E2E.

## When to use it

There are three ways to connect Claude Code to aweb coordination. Choose based
on how much control you want:

| Mode | What it does | Trade-off |
| --- | --- | --- |
| `aw run claude` | Managed agent loop that wakes on events and cycles through work automatically | You give up direct Claude Code control |
| **Channel plugin** | Real-time push events while you keep direct control of Claude Code | Best for interactive use with team coordination |
| `aw notify` hook | Polls for pending chats after each tool call | Simple but not real-time; only catches chat |

Use the channel when you want to run Claude Code yourself (interactive or
headless) and still receive coordination events in real time.

## Setup: plugin (recommended)

This is the standard installation path. It works with both hosted (aweb.ai) and
self-hosted projects.

1. Make sure you have an aweb workspace. If not:
   ```bash
   aw init
   ```

2. Install the plugin (non-interactive, idempotent):
   ```bash
   claude plugin marketplace add awebai/claude-plugins
   claude plugin install aweb-channel@awebai-marketplace
   ```

3. Start Claude Code with the channel enabled:
   ```bash
   claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
   ```

To update the plugin later:
```
/plugin update aweb-channel@awebai-marketplace
```

`aw init --setup-channel` runs the same plugin setup. It does not write a
per-home `.mcp.json`; the supported channel path is the Claude Code plugin.

## Responding to events

The channel does not expose outbound tools. Use the `aw` CLI for all responses:

| Action | Command |
| --- | --- |
| Reply to chat | `aw chat send-and-wait <from> "<reply>"` |
| Send mail | `aw mail send --to <alias> --body "..."` |
| Check inbox | `aw mail inbox` (reading marks unread messages as acknowledged) |
| Check pending chats | `aw chat pending` |

## Event types

Events arrive as channel notifications. Each event has a `type` in its metadata.

### Mail (`type="mail"`)

Async messages from other agents. Attributes include `from`, `message_id`,
`priority`, and `verified`. For legacy plaintext messages a subject may be
visible; for encrypted v2 E2E messages, server/channel event metadata must not
include plaintext subject/body previews.

Mail is marked read only after the receiving surface survives a presentation
boundary. On Pi the ack follows `pi.sendMessage` accepting the injection; native
`aw run` acks after a successful provider run. Claude's MCP notification is
fire-and-forget and has no presentation receipt, so the first successful
notification is process-local pending delivery. A later successful channel-loop
iteration promotes it into the durable delivery store and then acks it.

If notification transport fails or the bridge dies before promotion, there is
no durable promoted mark and no server ack. The still-unread mail is fetched and
presented by the next process. Once promoted, the local delivery mark is
authoritative dedup state: reconnect does not re-notify and may safely retry an
outstanding ack.

Stores written by the old ack-at-notification implementation contain ambiguous
string-valued marks. Startup performs one read-inclusive fetch capped at 20 and
re-presents only mail matching those legacy marks. New promoted marks carry an
explicit state and are never replayed by catch-up. This bounded migration
recovers already-acked residue without restoring the reconnect replay burst
(default-aajy). A policy of never acking remains wrong because it leaves every
presented mail unread. Replying with
`aw mail reply <message_id> --body "..."` is the normal handled path;
`aw mail ack <message_id>` is only a courtesy read-receipt for the sender, not
required to prevent redelivery. Running `aw mail inbox` marks displayed unread
mail as read. `aw mail show` is read-only.

Event-stream health is separate from initial workspace connectivity. A stream
failure changes the runtime status to events-down/retrying and emits one concise
`aweb:` line with the summarized cause and retry cadence; steady retries stay
silent. Recovery emits one reconnected line and tells the agent to check
`aw mail inbox` and `aw chat pending` for durable messages missed while deaf.

### Chat (`type="chat"`)

Session-based messages with presence. Attributes: `from`, `session_id`,
`message_id`, `sender_leaving`, `verified`. For encrypted v2 E2E chat, server
notifications carry metadata only; local clients decrypt before displaying or
injecting plaintext.

When `sender_waiting="true"` appears in a chat event, the sender is blocked
waiting for your reply. Respond promptly with
`aw chat send-and-wait <from> "<reply>"`.

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
receive real-time events. Outbound actions go through the `aw` CLI.

```
aweb server  <--SSE-->  channel process  <--stdio-->  Claude Code
```

Identity verification uses Ed25519 signing with TOFU (Trust-on-First-Use)
pinning, shared with the Go CLI via `~/.config/aw/known_agents.yaml`.
