---
type: Lesson
title: Whether a resend is safe and what an earlier attempt did are separate questions
description: For a registry write with a lost or ambiguous answer, "conclusively unapplied" holds only when no attempt was ever handed to the transport; after dispatch an earlier receipt, a changed epoch or a key that differs today proves nothing about the earlier attempt, only current exact read-back settles it, and a write with no old-state predicate (team rotation) is never resent while ambiguous.
tags: [lesson, awid, registry, retries, reconciliation, custody, design]
timestamp: 2026-11-27
---

A holder of registry writes has to reconcile any write whose answer was lost.
That can be a hosted custody service, an outside key holder or an operator
tool. The SDK reports such a write as `ControllerRequestUncertain`: the
effect may have committed. It tells the caller to reconcile through current
reads and its own durable journal, never to retry blindly
(`docs/controller-signing-sdk.md`).

A custody design's first replay table mixed two questions: is a resend safe,
and what did the earlier attempt do? It gave an exact earlier receipt as an
example of "conclusively unapplied", but a receipt is evidence that the write
happened. It also treated a `from_seq` that is no longer open, or a team key
that differs today, as settling an earlier rotation. Each of those can be true
while the earlier attempt applied, or applied something else. The table read
naturally and was caught only in review.

# The rule that held up in review

- **Conclusively unapplied** means no attempt ever reached the transport. The
  holder records that fact at the transport, under a current claim, just
  before sending. With no such dispatch record for any attempt, the write
  never left.
- **After dispatch**, only a current exact read-back confirms the effect. An
  earlier receipt, a changed epoch or a different key today does not. Without
  an exact read-back the write is a conflict for the operator, or it stays
  uncertain.
- **A resend is allowed only where the operation's own predicate prevents a
  second application.** Examples are an expected head, the same certificate
  id or the same record. `namespace_rotate` names its `from_seq` and
  `previous_did_key` and refuses with `head_conflict` otherwise
  (`docs/awid-sot.md`). AWID team rotation has no such predicate: it takes
  the team name and a new key, and updates the team row unconditionally
  (`awid/src/awid_service/routes/teams.py`). A team rotation is never resent
  while it is ambiguous.
- **An effect made by an outside key holder is observed, never resent** by
  the holder that saw it.

Related: [an exact-retry answer sits after validation](/aweb-protocol-expert/lessons/exact-retry-answers-after-validation.md),
which covers the receiving side of the same problem, and
[gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/replay-safety-is-not-settlement.md.
The design was reviewed against source and is not built. The harvester checked
the team rotation route, the namespace rotation contract and the SDK's
uncertain-write contract at aweb main 39b3f0911.
