---
type: Decision
title: aw mail reply answers received mail only
description: aw mail reply refuses a message the caller sent and names aw mail send --conversation-id instead of resolving it, because an encrypted reply is addressed to the source's verified sender and would be encrypted to the caller. Decided, not yet landed.
tags: [decision, aw-cli, mail, encryption]
timestamp: 2026-11-05
---

**Status:** decided on 2026-11-05 and implemented on a CLI branch for the
reply and admission-init fixes; not on main when recorded. On main, replying
to a message one sent still reports "mail message not found".

# Decision

- `aw mail reply <id>` answers mail the caller **received**.
- For a message the caller **sent**, it refuses and names the command that
  continues the conversation: `aw mail send --conversation-id <conv>`. It does
  not resolve the message and send.
- The refusal decides "you sent it" by two lookups: the inbox (recipient rows)
  has no match, and the exact read (sender or recipient rows) has one. Against
  a server that predates sender-visible exact reads, the exact read falls back
  to the inbox, finds nothing, and the plain not-found error stands.

# Rejected alternative

Resolving any message in a conversation the caller belongs to, and replying to
it. For plaintext it looks free, since a conversation-scoped send routes to the
participants. But an encrypted reply takes its single recipient from the
source message's verified sender (`MailReplyRecipient`). For a message the
caller sent, that sender is the caller, so the reply would be encrypted to
oneself.

# When to revisit

Reply-to-own-message is a new semantic, not a bug fix. A change that wants it
must first define which participant the encrypted reply goes to when the
source is one's own message, and only then relax the refusal.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/mail-reply-answers-received-mail-only.md. Verified by the harvester on 2026-11-05: the refusal text is on the branch, and on main `MailReplyRecipient` in the Go client takes the reply recipient from the source's sender.
