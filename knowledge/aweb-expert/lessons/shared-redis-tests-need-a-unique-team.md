---
type: Lesson
title: Tests on a shared Redis need a unique team per test
description: The server's AWID client caches a team's public key in Redis for 60 seconds under the registry URL and team id, both constant across tests, so a test that re-registers a fixed team id with a fresh key meets an earlier test's key and gets 401; exactly one pass per xdist worker is the signature.
tags: [lesson, testing, redis, cache, awid, flaky-tests]
timestamp: 2026-11-11
---

The in-process coordination test stack gets a fresh AWID database per test, but
every test and every xdist worker share one real Redis. The server's
`CachedRegistryClient` keeps `team_public_key` there for 60 seconds, keyed by
the registry URL and the team id, and the registry URL is the same constant in
every test. A test that registers a new team key under a fixed team id (here
`people:example.com`) is checked against the previous test's cached key and
`/v1/connect` answers 401 "Certificate signature verification failed".

Observed 2026-11-11 in a focused run: the owner-act router suite had 2 passes,
one per xdist worker, and 29 errors, all with that 401. Giving each router test
its own team (a3c215e55) made it 31/31 green in the next run; the fix kept the
cache behaviour and the assertions. The logs tests already used a team per test.

# How to apply

- A fixture that creates team keys against the coordination stack uses a fresh
  team id per test (for example `people-<hex>:example.com`), not a shared
  constant.
- "Exactly one test passes per worker" points to state leaking through a shared
  cache, not to the tests' own logic.
- Whether the same 60-second window after a real team-key rotation is a product
  defect was put to the authority reviewer and is **not settled** here.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-11;
notes/shared-redis-team-key-cache-needs-unique-teams.md. Commit a3c215e55
(on an aweb-expert branch, not on main at 7f4be32fa) checked by the harvester;
the run counts are source-reported.
