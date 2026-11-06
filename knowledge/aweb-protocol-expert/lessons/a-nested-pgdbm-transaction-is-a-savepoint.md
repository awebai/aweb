---
type: Lesson
title: A nested pgdbm transaction is a savepoint
description: In pgdbm, transaction() on a TransactionManager opens a savepoint, two extra round trips, so wrapping service calls in one caller transaction saves nothing until the services stop nesting; a service skips its own transaction when handed one only if no caller catches its failure and keeps using the transaction. Measure round trips after each step.
tags: [lesson, pgdbm, transactions, performance, measurement]
timestamp: 2026-11-04
---

Moving a mail send's service calls into one caller transaction was meant to
cut round trips. The measurement gate showed no gain: `create_conversation`
guards its own atomicity with `transaction()`, and inside a caller's
transaction pgdbm makes that a `SAVEPOINT`/`RELEASE` pair, two round trips
that cancelled the saving. Mail round trips per send went from 24 to 14 with
the single transaction, and to 11 only once the savepoint was removed. Chat
went from 33 to 16.

# How to apply

- Before a "one transaction" refactor, count the services that open their own
  `transaction()`. Each one costs a savepoint inside the caller's transaction.
- A service that guards its own atomicity can skip its transaction when it is
  handed a `TransactionManager`, because the caller's commit already makes it
  atomic. This is safe only if **no caller catches the service's failure and
  keeps using the transaction**: without the savepoint, the failed statement
  aborts the caller's whole transaction. Check every caller. No lint enforces
  this.
- Measure round trips after each step, not only at the end. The gate exposed
  the savepoint, and also a lookup of a message id the code had just
  generated, which could never match. Neither was in the plan.

This is about the savepoint's round-trip cost, not its durability semantics.

**Status (verified 2026-11-06):** the savepoint skip is on main (f09be84f7) and
first released in server-v1.27.47.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/pgdbm-nested-transaction-is-a-savepoint.md.
