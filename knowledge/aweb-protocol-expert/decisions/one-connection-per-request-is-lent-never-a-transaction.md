---
type: Decision
title: One connection per request is lent, parked during waits, and never a transaction
description: A request shares one pool connection by lending it to one borrower at a time, discards it after any failed or cancelled borrow, lends nothing once closed, ends at http.response.start, parks it after 10 ms idle, bounds every checkout at 10 s with a retryable 503, and never opens a transaction. On main and in server-v1.27.47.
tags: [decision, database, pgdbm, connections, request-lifecycle, outage]
timestamp: 2026-11-04
---

pgdbm takes a pool connection per statement, and asyncpg resets each
connection on release (four statements, one round trip). A request of N
statements therefore paid N resets. Sharing one connection per request removes
that cost without changing what any statement sees. The rules below are what
keep the sharing safe. Reviewers required each of them, and each guards a
realistic outage. A future change to pgdbm usage or the request lifecycle must
keep them, and must not "simplify" the scope into a request-wide transaction or
into park hooks in individual clients.

**Status (verified 2026-11-06):** reviewed, with a ruling by the auth/data
reviewer; on main as `server/src/aweb/connection_scope.py` (e268a8703 and
5e46fb0f7), tested by `server/tests/test_connection_scope.py`, which was
mutation-checked, and first released in server-v1.27.47.

# Decision

- **Lend only while no other borrower holds the connection.** A manager call
  nested inside another manager's `transaction()` still runs on its own
  connection, outside that transaction, as it did before. A hosted operator's transaction
  lint relies on that invariant. The branches of a
  `gather` stay isolated.
- **Discard after any failed or cancelled borrow.** The connection goes back
  to the pool, which resets or terminates it, and later acquires use the pool.
  Without this, a deadline (`wait_for`, a 5 s custody bound) hands the next
  borrower a half-used connection.
- **A closed scope lends nothing**, including to a task that copied the
  context during the request and outlives it. The test that catches the real
  hazard holds a stale reference to the released proxy and expects asyncpg's
  `InterfaceError`; asserting the closed flag alone does not.
- **The scope ends at `http.response.start`.** SSE bodies and post-response
  work keep per-statement checkout; a stream reconcile opens its own scope.
- **Park after 10 ms idle.** The scope returns its connection to the pool unless
  another statement borrows it within 10 ms. The timer is one `call_later` per
  scope, re-armed on each borrow. A network wait (AWID, federation, DNS)
  therefore never holds a connection.
- **Bound every checkout at 10 s.** An exhausted pool fails the request with a
  typed, retryable 503 (`database_unavailable`) instead of hanging it. A
  middleware error raised before any response started gets the same 503, not a
  500.
- **Never open a transaction.** Handlers own their transactions; stream-push's
  post-commit wake point and
  [admission is not the effect transaction](/aweb-protocol-expert/lessons/admission-is-not-the-effect-transaction.md)
  both depend on it. This confirms that lesson's "no request-wide wrapper".

# Rejected alternatives

- **Putting the scope in pgdbm.** pgdbm is the operator's own library, and
  changing it would add a release to the critical path.
- **Changing asyncpg's reset on release.** The reset stays. The cost was
  handled by budget instead: the heartbeat path is held to three round trips.
- **Parking only from outbound HTTP clients.** Every client would need the
  hook, and one client that forgets it brings back pool starvation during an
  outage. The idle timer covers every wait without the client's cooperation.

# Evidence

The independently reproduced Track D gate measured round trips per request
falling from 28 to 4 for inbox, 18 to 3 for heartbeat and 26 to 4 for ack, with
CPU about halved. The CPU figures come from one M-series host. The 10 ms park
bound was benched only locally, and its production effect is unmeasured.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/connection-scope-lending-rule.md.
