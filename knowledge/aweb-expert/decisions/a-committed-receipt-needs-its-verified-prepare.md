---
type: Decision
title: A committed receipt is taken only with its verified prepared operation
description: When a protected operation's prepare answer is lost, aw does not take even a committed receipt; it keeps the operation saved as prepare_unconfirmed until a same-id resume receives and verifies the original prepared operation, because checking the result against the intent alone skips the frozen-artifact and policy/digest binding.
tags: [decision, aw, protected-operations, admission, verification]
timestamp: 2026-11-13
---

How aw's protected-operation client handles a committed receipt whose prepare
answer it never received. Found by a reviewer's read of the wire for the
`aw id team admit` client, and fixed test-first in 9749e7fe7.

# Decision

- **The prepare check is what binds a result to the request.** Before it shows
  an approval page or executes, aw verifies the prepared operation: the
  covered-request digest, every member it sent, and the frozen artifact.
- **A lost prepare answer leaves the result unbound.** If the receipt read then
  says committed, the result is real, but nothing has checked what was frozen.
  aw keeps the operation saved and reports it as unresolved with the local code
  `prepare_unconfirmed`. It materializes nothing; admit writes no certificate.
- **Only an explicit same-id resume settles it.** The resume resends the saved
  bytes, receives the original prepared operation, verifies it, and only then
  takes the receipt's result.
- **No new wire code.** Unconfirmed execute outcomes use the contract's existing
  unknown codes (`receipt_unavailable`, `external_effect_unresolved`).

# Rejected

- **Taking the committed receipt and checking its result against the intent
  alone.** That skips the frozen-artifact equality and the policy and digest
  binding that only the prepare check provides.

# How to apply

When writing or reviewing any protected-operation client, ask of every path
that takes a result: was the prepared operation behind it verified in this
operation's history? A committed receipt is not, by itself, that verification.

**Status (checked by the harvester 2026-11-13):** 9749e7fe7, with
`TestACommittedReceiptAfterALostPrepareIsNotTakenWithoutItsPreparedRequest`,
is on the branch `agents/aweb-expert-owner-acts-admission-policy`, not on main
at dfce11678. The source reports that the commands have not yet passed their
real-path tests.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/bounded-operation-client-takes-nothing-unverified.md. The reviewer's wire
read is the source's report.
