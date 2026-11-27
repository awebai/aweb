---
type: Lesson
title: A race test proves a lock only if the racers wait on that lock
description: An upstream serializer can make a race test pass with the lock under test removed; naapp-lib's installation fence takes FOR UPDATE on a team's fence row at every admission, so one team's concurrent HTTP requests never reach an app's transaction together. At the barrier, check where the waiters wait, not how many there are, and race the component that holds the lock directly.
tags: [lesson, testing, concurrency, postgres, locking, naapp]
timestamp: 2026-11-27
---

In the first naapp Tasks app, an HTTP-level race test for claims and locks
passed 5 of 5 runs with the app's own `FOR UPDATE` removed. The barrier
reported the expected number of waiting backends, so the test looked forced.
`pg_stat_activity` at the barrier showed why it proved nothing: request 2 was
waiting (`transactionid`) in the installation fence's `SELECT ... FOR UPDATE`,
while request 1 waited on the app's row. The two requests never reached the
app's transaction at the same time.

# Why it happens

naapp-lib's installation fence runs on every request. Admission takes
`FOR UPDATE` on the team's fence row, and every fenced transaction holds
`FOR SHARE` on it. So a team's concurrent requests to an app are serialized
by the fence before they reach the app's store, whatever the app locks
itself.

# How to apply

- **At the barrier, check where each waiter is waiting:** the wait event and
  the query text in `pg_stat_activity`, not only the count of waiting
  backends. A count shows that something serialized the racers. It does not
  show that the lock under test did.
- **Race the component that holds the lock.** For a naapp app, race its store
  directly on real PostgreSQL with a held-row barrier: wait until the
  expected backends wait on a `Lock` on the app's row, then release. That
  test failed 3 of 3 for claims and 3 of 3 for locks with the app's
  `FOR UPDATE` removed.
- **Mutation-check the race as usual.** Removing the lock must turn the test
  red, as [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
  requires. Here that mutation check is what showed the HTTP test was
  vacuous.

This refines the barrier advice in
[an exact-retry answer sits after validation](/aweb-protocol-expert/lessons/exact-retry-answers-after-validation.md):
a barrier forces overlap only if its waiters are waiting on the lock the test
is about.

**Limit:** observed in one app on naapp main at one point in time. The fence's
locking is naapp-lib's design and can change; recheck it before relying on
the serialization for anything other than test design.

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-app, 2026-11-27;
notes/installation-fence-serializes-team-requests.md (naapp PR 61, Tasks app
E2.3).
