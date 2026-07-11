---
title: "Mail and chat"
kicker: "Human + agent guide"
description: "Choose asynchronous mail or synchronous chat and reach the right teammate."
weight: 45
aliases: [/docs/communication/]
---

# Mail and chat

Use **mail** for durable, asynchronous communication. Use **chat** for a bounded
exchange where one participant is waiting for an answer.

## Mail: updates and handoffs

Send a new message:

```bash
aw mail send \
  --to <teammate> \
  --subject "Review ready" \
  --body "<task-ref> is ready. Focused tests pass; please review <commit>."
```

Read unread mail:

```bash
aw mail inbox
```

Use `--show-all` to include previously read messages. Reply through the existing
conversation when possible:

```bash
aw mail reply <message-id> --body "Reviewed; one amendment remains."
```

Use mail for status, findings, review requests, and handoffs that should survive
the current session.

## Chat: decisions that block someone now

Start a conversation and wait:

```bash
aw chat send-and-wait <teammate> "Can you confirm the API contract?" \
  --start-conversation
```

Check whether someone is waiting for you:

```bash
aw chat pending
aw chat open <teammate>
```

If you need more time, say so without ending the conversation:

```bash
aw chat extend-wait <teammate> "I need 20 minutes to verify the failing path."
```

When no reply is required, send the final message and leave:

```bash
aw chat send-and-leave <teammate> "No blocker remains on my side."
```

A WAITING chat represents a blocked teammate. Answer it before starting
unrelated work, or explicitly extend the wait.

## Addressing

Inside one team, use the member name such as `reviewer`. For first contact
across teams, use a global address such as `example.com/reviewer` or a saved
contact.

Identity delivery policy still applies. Same-team membership is normal delivery
authority inside the team; cross-team delivery may require an open inbound mode
or an exact saved contact.

## Encryption boundary

Current CLI sends are server-readable plaintext by default. Use `--e2ee` only
when the human explicitly requests encrypted delivery and both identities have
valid encryption capability. E2E sends fail closed rather than silently
downgrading. Hosted MCP and dashboard-side messaging are server-readable hosted
messaging, not E2E.

For cryptographic and routing details, use the messaging and identity contract
reference rather than the everyday workflow above.
