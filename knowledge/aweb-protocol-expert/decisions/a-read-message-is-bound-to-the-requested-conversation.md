---
type: Decision
title: A message read from a conversation is bound to the conversation asked for
description: Received chat is verified against the conversation the reader requested, never against the conversation_id the server's row names, because checking against the row lets whoever writes rows replay a message signed for X into Y as verified; a row naming no conversation takes the requested one, for older servers. On a handed-back branch, not yet on main.
tags: [decision, verification, chat, replay, conversation, compatibility]
timestamp: 2026-11-21
---

History and the live stream used to compare a message's signed conversation
claim with the `conversation_id` on the server's row. A server, or anyone
able to write rows, could serve a message signed for conversation X, with
X's own identifiers, inside Y's history, and it verified.

# Decision

- The one verifier takes the conversation the reader asked for: in Go,
  `VerifyReceivedChatMessage`'s conversation argument (the stream passes its
  session); in channel-core, the history read's session id.
- A row that names a different conversation fails verification, however it
  is signed. A failed row is kept as received, not dropped.
- A row that names no conversation takes the requested one, because rows
  from older servers may omit the field.

# Rejected

Failing every row that has no `conversation_id`. It would break every older
server that omits the field, and it buys nothing: the reader already knows
which conversation it asked for, and that is the value that must match the
signature.

# Consequence

Fixtures that pair a chat session with a different conversation id describe
shapes no server sends; every chat route sets `conversation_id` to the
session id. Such fixtures are corrected to the real shape, not the rule.

This is the receive-path companion of
[a legacy status names a format, not a trust result](/aweb-protocol-expert/lessons/a-legacy-status-names-a-format-not-a-trust-result.md):
neither a server row nor a compatibility status may become a way around
verification. The tolerance for rows without the field follows
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

Status: decided in review of task aweb-adje.3 and implemented on branch
`agents/aweb-protocol-expert-chat-verify-adje3` (commit 573552b2ff, head
5e758c7bb5, handed back 2026-11-21); not yet on main or released.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/bind-a-read-message-to-the-requested-conversation.md. Commit 573552b2ff, `VerifyReceivedChatMessage` and channel-core's history check verified on the branch.
