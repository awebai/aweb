---
type: Decision
title: Test databases go on the host PostgreSQL through pgdbm's fixtures; Redis stays isolated
description: Test databases live on the host PostgreSQL, created and dropped by pgdbm's own test fixtures, with small named pools; per-run Postgres containers are rejected; the host Redis holds other seats' data, so a test uses its own Redis or explicitly isolated db numbers. Accepted by Juan, 2026-11-28 (source-reported).
tags: [decision, testing, postgres, pgdbm, redis, environment, human-accepted]
timestamp: 2026-11-28
---

# Decision

- Test databases go on the host PostgreSQL. pgdbm's own test fixtures create
  and drop them, through the repository's existing test database
  configuration (for example `TEST_DB_HOST` and `TEST_DB_PORT`). Every test
  database is dropped afterwards.
- No Postgres container per test run.
- Test pools are small and named. The precedent is aweb-adzx: `min 1`,
  `max 5`, and a distinctive `application_name`, unless a test measures
  concurrency. The host's `max_connections` of 100 is shared across every
  seat's suites.
- Redis is different. The host Redis holds other seats' data in its numbered
  dbs. A test uses its own Redis instance or a db number explicitly isolated
  for it, never a shared default db.

# Why

- The host PostgreSQL is provisioned for throwaway test databases.
- pgdbm is the team's own library, so its fixtures are the supported way to
  create and clean those databases.
- Shared Redis dbs have no equivalent create-and-drop isolation, so a test
  writing to one can damage another seat's state.

# Rejected

- **Per-run Postgres containers.** Juan's direction rules them out, because
  the host is provisioned for this. Earlier team steering towards per-run
  containers, and away from the shared host, came from the coordinator, not
  from Juan, and is superseded by this decision.

# Acceptance

Accepted by Juan, relayed by the coordinator seat in verified aweb mail on
2026-11-28: **source-reported** (who: Juan, via the coordinator; when:
2026-11-28; where: aweb mail). The active team instructions carry the same
rule (v63, source-reported).

A future instance sizes and names test pools from the start, does not add
test containers, and does not share a Redis db.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-28; notes/test-databases-on-host-postgres.md.
