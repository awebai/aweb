---
type: Lesson
title: Forced checkpoints stall writes on a shared PostgreSQL
description: On the shared host PostgreSQL, a one-row write can wait over 5 s on IO/DataFileExtend while other suites' CREATE/DROP DATABASE force immediate checkpoints, so a fixture that makes many writes under a production deadline flakes; diagnose with pg_stat_activity snapshots on slow statements, and keep production deadlines off fixture construction rather than raising them.
tags: [lesson, testing, postgres, flaky-tests, timing]
timestamp: 2026-11-26
---

# The discovery

Test suites on the host create and drop a database per test, and DROP
DATABASE forces an immediate checkpoint. On the shared macOS host PostgreSQL
(fsync and synchronous commit on), a backend extending a relation file then
waits on I/O (`wait_event` `IO/DataFileExtend`) for seconds. One single-row
INSERT waited more than 5 s.

In aweb-adyr, a test built its registration history through the app's
registry client: 4,000 sequential calls, each under the client's production
5 s deadline. Occasionally one write stalled past the deadline, the route was
cancelled, and setup failed with "AWID registry unavailable (TimeoutError)"
before the test reached the code it measures. It failed 1 run in 20 on a quiet
host and 1 in 5 with a CREATE/DROP DATABASE loop running beside it. The
server's checkpoint counters showed about 63k requested against 1.6k timed
checkpoints.

# What was not the cause

GC pauses were measured at 0.02 to 0.08 s, so GC was not the cause here. An
earlier flake investigation (aweb-adtd) did attribute similar timeouts to GC
pauses. The two causes look the same from the test output; measure both before
blaming either.

# How to apply

- Diagnose with evidence taken during the stall: snapshot `pg_stat_activity`
  and the checkpointer counters when any statement passes about 1 s, and log
  GC pauses and event-loop lag in the same run. A snapshot taken 1 s into the
  stalled statement is what showed `IO/DataFileExtend`.
- Reproduce by running a CREATE/DROP DATABASE loop beside the test.
- Fix by keeping production deadlines off fixture construction. 2ba564a2f5
  writes the history through a setup-only client on the same product route,
  so the rows stay product-written, with a long finite deadline. The client
  under test keeps its real 5 s budget. With a 6 s stall injected into one
  history write, the old test fails and the new one passes; after the fix the
  test passed 10 of 10 runs.
- Never raise the deadline under test to make the flake go away. It would hide
  the stall and stop the test measuring the budget it exists for.
- The gate lanes keep PostgreSQL data on tmpfs, so the stall is much rarer
  there (source-reported). A rare gate red of this shape is still a failure to
  investigate, not one to note and wait for.

This is a case of [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md):
the latency came from the shared database, not from a stub.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-26;
notes/host-postgres-forced-checkpoints-stall-writes.md. Checked by the
harvester: 2ba564a2f5 on aweb main 5c2ee7bad and its commit message. The
failure rates, the snapshot and the checkpoint counts are source-reported.
