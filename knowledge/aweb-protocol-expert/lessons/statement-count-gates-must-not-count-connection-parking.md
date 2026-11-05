---
type: Lesson
title: Statement-count gates must not count connection-scope parking
description: The request connection scope parks its connection after 10 ms with no borrower, so every longer pause adds one pool reset round trip; a gate that counts round trips measures wall-clock luck unless it pins the park or excludes the reset script, and raising its ceiling hides real growth.
tags: [lesson, testing, budgets, hot-path, database, connections, flaky-tests]
timestamp: 2026-11-05
---

`aweb.connection_scope` parks a request's pooled connection when no statement
borrows it within `IDLE_PARK_SECONDS` (10 ms). That is deliberate: a request
waiting on the network holds no connection. But any pause longer than that,
whether CPU work such as certificate-chain verification or an await, releases
the connection. The pool runs asyncpg's reset script
(`SELECT pg_advisory_unlock_all(); CLOSE ALL; UNLISTEN *; RESET ALL;`), and the
next statement checks out again.

A cost gate that counts database round trips, simple-protocol executes
included, therefore varies by one per pause. It counts timing, not the
request's work. A gate whose ceiling equals its median count fails about half
the time.

# What to do

- **Pin the park while measuring**: set `IDLE_PARK_SECONDS` high for the test,
  so the whole request shares one checkout and the count is the work.
- **Or exclude the pool's reset script from the count.**
- Counting only extended-protocol executes (`Connection._execute`) skips the
  reset script and is stable, but it also stops counting `BEGIN`/`COMMIT`.
- **Do not raise the ceiling.** Under load, more pauses add more resets, and a
  looser ceiling hides real growth, which is what the gate exists to catch.
- When a count flaps by one, diff the per-statement counts of a low run and a
  high run before suspecting the code under test. One extra reset script is
  this lesson; anything else is not.

# Elimination route

This lesson should become test-support code. As of aweb-cloud 151afefc (release
0.8.71), the pin is set in one gate only
(`test_messages_roster_does_bounded_work_independent_of_agent_count`). The
shared `StatementCounter` in `backend/tests/hot_path_support.py` still counts
the reset script, so the other gates that use it remain exposed. Pinning the
park or excluding the reset script inside the counter would retire this lesson
for every gate.

# Evidence

On 2026-11-05 the 0.8.71 roster hotfix gate gave 48 statements against a
ceiling of 47 in 2 of 4 runs. A per-statement diff between a 47 run and a 48
run showed exactly one extra reset script. With the park pinned, the gate gave
47 in 10 of 10 runs; this shipped in 0.8.71. A separate growth test that counts
only `Connection._execute` stayed at 42 throughout. The harvester checked the
10 ms constant and the parking timer against aweb main at e0d81e5a0, and the
single-test pin and the counter's reset-script counting against aweb-cloud at
151afefc.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/connection-scope-park-varies-statement-counts.md.
