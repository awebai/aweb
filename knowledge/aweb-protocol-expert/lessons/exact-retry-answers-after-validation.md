---
type: Lesson
title: An exact-retry answer sits after validation, and a race loser rereads
description: Answering an exact retry with the stored send is safe only after every check the ordinary path runs, right before the first effect; a concurrent identical send that loses on the unique key catches that violation, which fires only after the winner commits, and rereads. Test the race with a barrier after the lookup, not a plain gather.
tags: [lesson, idempotency, retries, concurrency, mail, testing]
timestamp: 2026-11-04
---

Adding idempotent retries to mail send, the first version answered an exact
retry with the stored send at the top of the handler. The existing tampered
`conversation_id` case in `test_mail_new_conversation`, which expects 422,
then got the stored send back: the shortcut had skipped validation. A
shortcut placed early bypasses checks silently, and nothing fails unless a
test already covers the tampered input.

# How to apply

- **Place the stored-send answer after every validation the ordinary path
  runs** (signature, recipient, delivery authorization), right before the
  first effect. It is one more step before the
  [point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md),
  never a gate in front of the others.
- **Match narrowly.** Only the same sender with an identical signed payload
  (plaintext) or identical stored envelope (encrypted) is an exact retry;
  anything else takes the ordinary path and conflicts. The rule for local mail
  is stated in `docs/mail-and-chat.md`.
- **Resolve the concurrent loser by catching and rereading.** Two identical
  in-flight sends both pass the lookup. The loser fails on the conversation
  key (the conversation-exists 409, after waiting on the winner's uncommitted
  key) or on the message-id unique violation. Both fire only after the winner
  commits, so the loser catches them, rereads, and returns the stored send.
  Its transaction rolls back, so no orphan conversation is left.
- **Force the overlap in the test.** A plain `gather` did not overlap the two
  requests: the first finished before the second looked. A barrier after the
  lookup forces both past it. Mutation-check that the test fails without the
  recovery.

The same shape applies to idempotency on any send or effect path.

**Limit:** the race resolution relies on the unique violation firing after
the winner's commit, as observed with Postgres 16 at the default isolation
level. A stricter isolation level, or a deferred constraint, needs the
reasoning redone.

**Status (2026-11-04):** reviewed by the auth/data reviewer, as the source
reported; the OSS runtime review was pending. Not on main: commits fa5542a7d
and 4c963ae47 on the source seat's branch (at 455b22404), tested by
`server/tests/test_mail_send_retry.py`.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/exact-retry-after-validation-and-race-loser.md.
