---
type: Lesson
title: Slow the SQL clock for one test pool to make a two-read timing bug deterministic
description: A bug that needs a pause between two clock_timestamp() reads in one SQL statement does not show on an idle machine and a trigger cannot reach it; shadow clock_timestamp() with a sleeping test-schema function on a dedicated one-connection pool whose search_path puts that schema before pg_catalog, and assert the exact value.
tags: [lesson, testing, timing, postgres, pgdbm]
timestamp: 2026-11-27
---

A statement that reads the clock twice, for example stamping `created_at` and
`expires_at` from two `clock_timestamp()` calls in one INSERT, is wrong only
when time passes between the two reads. On an idle machine both reads land in
the same microsecond, so the test is green, and the usual fallbacks (sleeps,
tolerances) hide the very error under test. In the review that found this, a
reviewer measured a six-second publication passing a five-second bound when
the bound was read with a delay.

A trigger cannot inject the pause: `VALUES` is evaluated before `BEFORE INSERT`
triggers run, so both reads have already happened.

# What works

Put the fault at the database boundary, for one pool only:

- Create a test schema holding a function `clock_timestamp()` that runs
  `PERFORM pg_catalog.pg_sleep(0.01)` and returns
  `pg_catalog.clock_timestamp()`.
- Open a dedicated one-connection pool with
  `build_database_config(..., shared_pool_search_path="<fault schema>, pg_catalog")`
  and run the code under test through
  `AsyncDatabaseManager(pool=..., schema="aweb")` over it.
- Assert the exact result (`expires_at - created_at == ttl`), not a bound.

Unqualified calls in the product SQL now resolve to the fault; production SQL
is unchanged. The test gate pins the shared pool's search_path to
`pg_catalog`, so no other test sees the fault, and pgdbm's `{{tables.x}}`
qualifies every table, so the changed search_path moves no table.

# Limits

- Only unqualified calls are shadowed. A call written
  `pg_catalog.clock_timestamp()` bypasses the fault; check the statement under
  test before relying on the technique.
- Shown for `clock_timestamp()`; the same shadowing applies to any unqualified
  `pg_catalog` function, but has not been exercised on others.
- The technique currently lives in one test. If a second site needs it, make it
  a shared test fixture rather than copying the setup.

This is the SQL-statement form of [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md):
inject the delay where the code reads time, until the red is deterministic.

# Evidence

On 2026-11-27, `publish_result` in `aweb.federation.authority_work` read
`clock_timestamp()` twice. With the shadowed clock the red test stored
5.010408 s against an expected 5 s; the fix (8d602bf761) reads the clock once
in a CTE and the same exact assertion passes. The harvester read that commit
and the test on the source's branch; the 139 related passing tests and the
reviewer's ACK at 7b8eaab2ca are source-reported.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27; notes/inject-a-database-clock-fault-through-search-path.md.
