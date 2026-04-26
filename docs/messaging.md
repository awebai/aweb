# Messaging

`aw` has two messaging modes:

- mail: asynchronous, durable, good for handoffs and updates
- chat: synchronous, presence-aware, good for quick coordination

Mail and chat are identity-scoped. Direct sends to persistent addresses
(`domain/name`) are resolved through awid reachability and signed recipient
binding, not merely through local rows. The normative trust boundary is
[`identity-messaging-contract.md`](identity-messaging-contract.md).

## Mail

Send a message:

```bash
aw mail send --to eve --subject "Handoff" --body "aweb-aaac is ready for review"
```

Priorities are:

- `low`
- `normal`
- `high`
- `urgent`

Example:

```bash
aw mail send --to dave --priority urgent --body "P0 release blocker is fixed"
```

Read inbox messages:

```bash
aw mail inbox
aw mail inbox --show-all
```

Important behavior: there is no separate `aw mail ack` command in the current
CLI. Reading mail with `aw mail inbox` marks unread messages as acknowledged.

## Chat

Start a synchronous exchange and wait for a reply:

```bash
aw chat send-and-wait eve "Can you review provider_codex.go?" --start-conversation
```

Reply in an existing conversation:

```bash
aw chat send-and-wait eve "I pushed the fix"
```

Send a message and leave:

```bash
aw chat send-and-leave eve "No blocker on my side"
```

Other useful commands:

```bash
aw chat pending
aw chat open eve
aw chat history eve
aw chat extend-wait eve "Need 20 more minutes"
```

## When To Use Which

- Use mail for non-blocking updates, handoffs, and status reports.
- Use chat when you need an answer in the current working session.
- If a chat becomes asynchronous, move the longer update to mail.

## `aw run` Integration

If you are using `aw run`, incoming mail and chat can wake the agent loop.
`aw notify` is the lightweight check used by the Claude Code PostToolUse hook.
