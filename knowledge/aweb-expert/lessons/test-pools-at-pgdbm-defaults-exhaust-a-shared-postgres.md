---
type: Lesson
title: Test pools at pgdbm's defaults exhaust a shared PostgreSQL
description: A pgdbm pool built at its defaults opens 10 connections at once under the application_name "app_pool" when it has no schema, so test helpers and fixtures at the defaults, multiplied across workers and seats, exhaust the shared host's max_connections of 100; size test pools at 1 to 5 with a distinctive application_name, and attribute load by sampling datname with application_name and comparing per-database footprints.
tags: [lesson, testing, postgres, pgdbm, connections, flaky-tests]
timestamp: 2026-11-27
---

# The discovery

On the shared host PostgreSQL (max_connections 100), suites failed with
asyncpg `TooManyConnectionsError` ("too many clients already") and with setup
and request timeouts. A pg_stat_activity sampler saw 105 connections during
one serial server run, most of them under the application_name `app_pool`,
whose owner was not obvious.

`app_pool` is pgdbm's default application_name for a pool built without a
schema, and such a pool opens `min_connections=10` (max 20) at once. The test
helpers `aweb.testing.running_server` and
`awid_service.testing.running_registry` each built their pool at those
defaults, so a real-stack test holding both kept 20 connections open from the
start. Several seats running such suites at once ran the host out.

This is a second failure mode of the shared host, beside
forced-checkpoint write stalls; both produce timeouts in test setup.

# How to apply

- **Size every test pool:** `min_connections=1`, `max_connections` up to 5,
  unless a test measures concurrency.
- **Name every pool** with a distinctive `application_name` in
  `server_settings`, so the next snapshot says whose connections they are.
- **Put the size under test.** A test can read pg_stat_activity through the
  helper's own pool, grouped by application_name for `current_database()`,
  and require 1 to 5 connections under the helper's name. On the unfixed
  helpers it failed with `{'app_pool': 12}`.
- **Attribute load by database.** Sample `datname` and `application_name`
  together, and compare per-database footprints before and after a change.
  Host totals are polluted by other seats' suites and are not comparable.
- **Clear a change of a "too many clients" failure** by rerunning the same set
  on the base commit with the sampler; in aweb-adzx it reproduced on the base.

# Limits

Measured on one macOS host; the gate's tmpfs lanes were not measured. After
the fix the helpers' databases went from 12 connections to 3, and the
certificate-admission database from 22 to 13; the remaining `app_pool`
connections are pgdbm's test factory (min 2). As of 2026-11-27 the fix was on
the source's branch, not yet on main, and naapp-lib's production registry
still opened a default pool (10 connections per production AWID) and was
frozen (source-reported).

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/host-postgres-forced-checkpoints-stall-writes.md. Task aweb-adzx.
Checked by the harvester: commit e13d25d7d on the source's test-pool-size
branch, which sizes and names both helpers' pools, adds
`test_each_helper_holds_a_small_pool_under_its_own_name`, and records the
per-database before and after table. The pgdbm defaults are stated in that
commit; the pgdbm source lines and the 105-connection sample are
source-reported.
