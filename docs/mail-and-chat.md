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

## Shell-safe message bodies

The shell expands command substitutions in a double-quoted argument before it
starts `aw`. The CLI therefore cannot detect or recover Markdown backticks or
`$(...)` text that the shell already replaced. A body that reaches `aw` with
literal backticks was safely quoted; a body without them provides no evidence
one way or the other, so inspecting body content cannot provide a runtime guard.

For Markdown, reports, or command examples, write the text to a file and pass the
corresponding file flag:

```bash
aw mail send --to <teammate> --subject "Review ready" --body-file message.md
aw chat send-and-wait <teammate> --body-file message.md --start-conversation
aw task create --title "Follow-up" --description-file description.md
```

Inline text remains supported. Single-quoted inline arguments are not expanded.
When a caller cannot use a file flag, `--body "$(cat message.md)"` is also safe:
the shell does not re-scan command-substitution output for further substitutions.

## Mail: updates and handoffs

Send a new message:

```bash
aw mail send \
  --to <teammate> \
  --subject "Review ready" \
  --body-file message.md
```

Read unread mail:

```bash
aw mail inbox
```

Use `--show-all` to include previously read messages. Reply through the existing
conversation when possible:

```bash
aw mail reply <message-id> --body-file message.md
```

Use mail for status, findings, review requests, and handoffs that should survive
the current session.

## Chat: decisions that block someone now

Start a conversation and wait:

```bash
aw chat send-and-wait <teammate> --body-file message.md \
  --start-conversation
```

Check whether someone is waiting for you:

```bash
aw chat pending
aw chat open <teammate>
```

If you need more time, say so without ending the conversation:

```bash
aw chat extend-wait <teammate> --body-file message.md
```

When no reply is required, send the final message and leave:

```bash
aw chat send-and-leave <teammate> --body-file message.md
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
