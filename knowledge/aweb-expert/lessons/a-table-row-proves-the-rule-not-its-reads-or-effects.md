---
type: Lesson
title: A table row proves the rule, not its reads or its effects
description: When a pure verdict's table rows replace database or route tests, delete only the tests whose assertions are a branch of the rule; keep the route tests that prove an atomic effect (no write, the original receipt on a retry) or a distinct fact read (a real lookup a filter could break), and leave a refusal the reader itself raises to the reader's own test, because rows feed answers to the rule and never run the transaction or the query.
tags: [lesson, testing, refactoring, authority, table-tests]
timestamp: 2026-11-27
---

A table row hands the rule the answers it asks for and checks the verdict. It
never runs the transaction that applies the verdict or the query that produced
the answer. So a row can replace a test only when everything that test asserts
is a branch of the rule.

Seen on 2026-11-27 in E3.5 (registry identity-tree registration as a pure
rule). The first cut turned the route tests into rows. The protocol reviewer
returned it, and two signed route tests were restored because no row could
cover them:

- an exact retry after the inviter's revocation returns the original receipt
  and writes nothing. The rule decides "repeat", but only the route proves the
  stored receipt comes back and no row is written;
- a cross-domain candidate under a used invitation refuses through the real
  invitation lookup and writes nothing. The rule only sees the lookup's
  answer, so a broken filter in that lookup would leave every row green.

A refusal raised by the reader itself (here, a parent-chain snapshot too large
to read) is also not a row. It stays proven by the reader's own test.

# How to apply

Before you delete a test in favour of a row, classify what each of its
assertions proves:

- **A branch of the rule:** the row replaces it. Give the row that test's exact
  facts.
- **An atomic effect** (no write, the original receipt, a rollback): keep the
  route test.
- **A distinct fact read** (a lookup whose filter, join or scope could be
  wrong): keep the route test, or cover the read with its own real-database
  test.
- **A refusal the reader raises:** keep it with the reader's test.

Delete only the duplicates. List what you kept and why in the handoff.

This refines [tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md):
a pure rule is the authority for its verdict, not for the reads and writes
around it. Each row and each kept test must still be shown red on a defect
planted in its own check ([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

# Limits

As of 2026-11-27 this was seen at two Python sites over asyncpg transactions
(E3.5 registration and E3.4 install authority), on the source's branches and
not yet on main. The review return and the ACK are source-reported.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/a-pure-rule-must-keep-the-read-order.md. Checked by the harvester:
commit 71e02a013 on `agents/aweb-expert-contracts-adze5` restores
`test_invitation_conflict_domain` and
`test_accepted_human_invite_retry_after_inviter_revoke` and removes the
snapshot-refusal row; commit ca5606d43 on `agents/aweb-expert-contracts-adze4`
adds the install-authority table with five boundary rows.
