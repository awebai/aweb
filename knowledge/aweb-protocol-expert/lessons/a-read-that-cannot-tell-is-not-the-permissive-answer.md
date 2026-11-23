---
type: Lesson
title: A read that cannot tell is not the permissive answer
description: A read that cannot establish a fact must not default to the permissive answer; the continuation-encryption read mapped 403/404, a bounded page and a response without a list to "plaintext", so it now returns encrypted, plaintext or unknown with a reason, concludes plaintext only from a complete well-formed answer, and refuses on unknown. On a handed-back branch, not yet on main.
tags: [lesson, errors, encryption, e2ee, chat, mail, absence]
timestamp: 2026-11-21
---

Deciding whether to continue a conversation encrypted needs to know whether
the conversation is already encrypted. One helper read "no evidence of
encryption" as "plaintext" four ways, each of which could send
server-readable text into a possibly encrypted conversation:

- a 403 (a send-scoped grant may POST to a session it cannot GET) or a hidden
  404 read as "no encryption";
- a page of the newest 50 rows read as the whole history;
- a 200 whose body lacked the messages list (Go decodes absent or null as a
  nil slice) read as an empty, plaintext history;
- the mail route returned its oldest page because the newest-first order was
  not requested.

# What held up

- Three states, not two: encrypted, plaintext, unknown, each with a reason.
- Plaintext only from a complete, well-formed answer: the list present, the
  page not full, no further pages.
- Unknown refuses by default and names the explicit choices the user has.
- At most one narrow compatibility exception, pinned to its proof (here,
  distinguishing a route that does not exist from a resource that does not).
- The whole decision table in one owner (`awid.ContinuationEncryption`) so
  chat and mail cannot drift.

Expect hand-written fixtures that answered with shapes no server sends (a
null list, one handler answering every route) to start failing. Fix them to
the real route's shape and keep their assertions.

# The general rule

A failure to read is not absence. Whenever a read decides between a safe and
a permissive outcome, an error, a refusal, a partial page or a malformed body
yields "unknown", never the permissive answer. The opposite also holds: a
refusal that only a server with knowledge can send is an answer, not an
unknown, as in [after a team-create conflict, a failed read is "could not
confirm"](/aweb-protocol-expert/decisions/a-failed-read-after-a-team-name-conflict-is-unconfirmed.md).
This generalizes the "inference from absence" rejected for recipient kind in
[humans use mail](/aweb-protocol-expert/decisions/humans-use-mail.md) beyond
that one classification.

Status: fixed on branch `agents/aweb-protocol-expert-chat-verify-adje3`
(head 5e758c7bb5, handed back 2026-11-21) after review rounds of task
aweb-adje.3; not yet on main or released.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/cannot-tell-is-not-plaintext.md. `awid.ContinuationEncryption` verified on the branch.
