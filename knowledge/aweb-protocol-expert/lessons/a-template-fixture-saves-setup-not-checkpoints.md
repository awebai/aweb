---
type: Lesson
title: A template fixture saves setup time, not checkpoints
description: Cloning each test database from a migrated template removes repeated migration work, but every per-test DROP DATABASE still forces an immediate checkpoint and the template's own drop adds one, so qualify a template fixture on setup time and checkpoint pressure separately and never offer it as checkpoint relief.
tags: [lesson, testing, postgresql, fixtures, measurement]
timestamp: 2026-11-27
---

# The discovery

A test fixture that creates each test database from a migrated template, in
place of running the migration chain per test, makes setup faster. It does not
lower PostgreSQL checkpoint pressure. Each test still owns a database and
drops it, and in PostgreSQL 17 `dropdb` always requests an immediate, forced,
waited checkpoint. `CREATE DATABASE` with the default `WAL_LOG` strategy
requests none (only `FILE_COPY` does). The template is itself a database that
the session drops at the end, so a template fixture can add one forced
checkpoint per suite.

The two costs are separate. A reviewer who reads "the fixture is faster" as
"the fixture relieves the shared database host" picks the wrong remedy for
checkpoint stalls.

# Evidence

One matched pair per suite, on the same PostgreSQL 17 profile, before and
after a template fixture pilot (aweb commits b9b6c0f94 and 070c5062b, on an
agent branch, not on main). The same case IDs passed on both sides in a
presence suite and an AWID enrollment suite:

- Rounded setup totals fell from 3.64 s to 2.28 s and from 1.09 s to 0.76 s.
- Requested checkpoints rose from 5 to 6 and from 8 to 9. The server logged
  each one as immediate, force and wait. None was requested by WAL size or by
  time. The extra one matches the template's drop.

The sample is small. Statement counts were not measured, and each pair ran
once in a fixed order, so these figures support the direction of each cost,
not a suite-wide savings estimate. The `dropdb` and `createdb` checkpoint
paths were checked in PostgreSQL's `src/backend/commands/dbcommands.c` on
`REL_17_STABLE`.

# How to apply

- Qualify a fixture change with a matched bracket: the same test IDs, the same
  PostgreSQL profile, and the timed service's own log of checkpoint reasons.
- Count template creation and cleanup in elapsed setup time.
- Report setup time and checkpoint pressure as separate results. Accept a
  template fixture as a setup-time optimization only.
- A change meant to reduce checkpoint pressure must change the database
  lifecycle itself (how many databases are dropped, and when) and bring its
  own isolated checkpoint evidence. Keep real per-test isolation while doing
  it: tests still run the real migration chain and the real products, as
  [tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
  requires.

Related: [test databases run on tmpfs](/aweb-protocol-expert/decisions/test-databases-run-on-tmpfs.md),
the decision for disk stalls under test load.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-test-world, 2026-11-27; notes/migrated-fixtures-retain-database-drop-checkpoints.md.
The measured figures are source-reported. The commits and the PostgreSQL 17
source paths were checked by the harvester.
