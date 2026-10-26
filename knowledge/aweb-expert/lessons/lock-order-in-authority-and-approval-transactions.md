---
type: Lesson
title: Lock order in authority and approval transactions
description: Lock authority before the approvals it can revoke, prelock row sets explicitly in a sorted order, recheck expiry and authority after every blocking wait, and prepare every lock a later read will take; each rule cost a deadlock or a refusal that came too late.
tags: [lesson, postgresql, concurrency, authorization, naapp]
timestamp: 2026-10-24
---

Learned while building the shared approval primitive and the secrets naapp's
use approvals on PostgreSQL. Each rule below came from a real deadlock or a
real-database test that returned "may send" after the authority had lapsed. The
specific orderings are now encoded in `naapp-lib/README.md` and the real-database
tests; this records the general rules for designing the next lock path.

# The rules

- **Take locks in authority order.** Withdrawing coverage changes the
  approver record and then revokes affected approvals in one transaction, so an
  admission that holds an approval while waiting for coverage deadlocks against
  it. Lock coverage and authority first. Do not reverse locks just to retrieve
  a stable result before refusing.
- **Sorted input does not sort locks.** Sorting the input array or the
  selector does not order the row locks an `UPDATE ... = ANY(...)` takes.
  Prelock with `SELECT ... ORDER BY id FOR UPDATE`, and for several batches
  prelock the whole union before the first.
- **Recheck after every blocking wait.** Each lock wait or awaited read is a
  gap between check and use, and later waits can outlast an expiry checked
  earlier. Recheck after the last await, keep the tentative consume, outcome and
  audit writes inside a savepoint, and void them outside it; a refusal issued
  after the savepoint was released left those writes committed.
- **Read-only is not "no new locks".** A later plain read takes relation and
  index locks even when the rows are already held. To promise no new locks in a
  final phase, perform that read during preparation and discard its result;
  caching the earlier authority result or filtering relation locks out of the
  check would weaken the guarantee instead.

# Testing lock order

A test that blocks one authority row shared by every item proves the order only
for the first item; a per-item loop stops at the same wait and looks correct.
Use distinct authority rows, block a later one, and assert the earlier item's
downstream locks are still free. To get a deterministic physical order,
cluster the heap in the order that exposes the bug.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-naapp-approvals` (notes
`coverage-locks-precede-approval-locks.md`,
`bulk-revocation-needs-sorted-row-prelocks.md`,
`expiry-after-blocking-authority-checks.md`,
`read-only-is-not-no-new-locks.md`,
`batch-lock-tests-need-a-later-distinct-blocker.md`; review NACKs 4b06b9d7 and
77a3c74c).
