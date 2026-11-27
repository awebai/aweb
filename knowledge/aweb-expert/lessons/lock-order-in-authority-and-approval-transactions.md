---
type: Lesson
title: Lock order in authority and approval transactions
description: Lock authority before the approvals it can revoke, prelock row sets explicitly in a sorted order, recheck expiry and authority after every blocking wait (comparing revision and live holder, since expiry leaves a revision unchanged), judge existence and the tenant boundary before any lease, and prepare every lock a later read will take; each rule cost a deadlock, a late refusal or a wrong answer.
tags: [lesson, postgresql, concurrency, authorization, leases, naapp]
timestamp: 2026-11-27
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
- **A revision match is not a liveness match.** When an expiring lease, claim
  or lock is guarded by a revision, expiry happens in time and not in storage:
  nothing bumps the revision. A check that the state is "as the caller saw it"
  must therefore compare the pair (revision, live holder at the post-wait time),
  and a pre-wait observation must record that same pair, not the revision
  alone. Comparing revisions alone passes every test except the expiry
  boundary: one override path accepted a claim that had expired at an
  unchanged revision, while its sibling path refused it. Test the
  expired-since-seen case and a related row that expires during the wait.
- **Judge the boundary before the lease.** Decide existence, the installation
  or tenant boundary, and status first, then compare leases or revisions. A
  lease mismatch checked first hides the not-found answer and so reveals that a
  missing or foreign row exists.
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

The revision-versus-liveness and boundary-first rules: Evidence: OKF proposal
from aweb-expert/aweb-expert-tasks-app, 2026-11-27;
notes/revision-match-is-not-liveness.md. The protocol review of the Tasks app
decision functions found both defects. The fix added a test row for each case
(expired since seen, a descendant expired during the wait, a missing root with
an unseen descendant, a stale root with a foreign descendant, a closed root
with a stale revision), and each was red before it. The reviewer reran the
table through a revision-only adapter, and exactly those five rows regressed.
Limit: one implementation, of pure decision functions.
