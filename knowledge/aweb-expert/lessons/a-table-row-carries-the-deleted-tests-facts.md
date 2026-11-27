---
type: Lesson
title: A table row carries the deleted test's facts
description: When pure table tests replace database tests, each deleted test becomes a row with that test's exact facts (the same leading selector, existing versus missing, local versus external identities); break-prove each row with a mutation narrowed to that branch's condition and confirm the old table stays green under it while the new one goes red, because a whole-rule mutation is caught by neighbouring rows and hides the uncovered branch.
tags: [lesson, testing, mutation, review, table-tests]
timestamp: 2026-11-27
---

Seen on 2026-11-27 in the review of E3.2 (the mail-target rule as a pure
function). Ten HTTP mismatch tests were deleted and replaced by table rows,
and the table was break-proved with six mutations. The reviewer then disabled
the identity comparison only when an address leads the selectors, and all 45
table tests still passed. The rows covered the external-address refusal and
the matching local case, but not the deleted test's own facts: a local
(resident) address beside another member's existing agent id. The author's
mutation had removed the comparison everywhere, so other rows went red and the
gap stayed hidden. Two more rows used "the lookup found nobody" where the
deleted tests used existing but different identities.

# How to apply

- For each deleted DB test, write a row with its exact facts: the same
  leading selector, the same kind of resolved identities (existing versus
  missing, local versus external), not a nearby case that reaches the same
  refusal.
- Break-prove each such row with a mutation narrowed to that branch's
  condition (for example gated on the leading selector). Run it against the
  table before the new rows and after: the old table must stay green under the
  mutation and the new one must go red. A row that does not change the result
  is not the cover for that test.
- List the mapping from each deleted test to its row in the handoff.

This sharpens the partial-red rule in
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
a mutation wider than the branch under test is caught by neighbouring rows, so
its red says nothing about that branch. The pure-rule shape these tables test
is [a pure rule asks for its facts one at a time](/aweb-expert/decisions/a-pure-rule-asks-for-facts-one-at-a-time.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/table-rows-must-mirror-deleted-tests.md. Checked by the harvester:
commit e17b2c8bd on the source's E3 branches deletes
`test_send_message_rejects_mismatched_to_agent_id_and_to_address` and adds a
45-case `test_mail_target_decision.py`. The review RETURN and the mutation
results are source-reported.
