---
type: Lesson
title: A test's name is no evidence that it is daemon-free
description: A test file's name, family, marker or make target says nothing about whether it opens a database or drives Docker; grep it for daemon and database calls and opt-in skip guards before running it on a host where those runs are not allowed, and name every daemon-using file in a check summary.
tags: [lesson, testing, docker, database, shared-host]
timestamp: 2026-11-14
---

Where the team's rule puts database and Docker runs on placed hosts and not on
the shared workstation, the hard part is not knowing the rule but recognising
which runs it covers. One seat broke it three times in two days while already
holding the rule, each time by choosing tests by their name:

- "focused" test files that opened PostgreSQL through database fixtures;
- a whole suite selected with `-m "not e2e"` as a "full check" (a marker such
  as "not e2e" or "unit" says nothing about a database);
- `scripts/test_candidate_gate_ledger.py`, picked from the candidate test
  family as a cheap check. It builds and runs a proof candidate gate on the
  local Docker daemon, has no default skip guard, and runs in the `make`
  graph only through `test-candidate-ledger`, a prerequisite of
  `candidate-gate`. Its output said "real Docker stages" only afterwards.

# How to apply

- Before running a test file where daemon or database runs are not allowed,
  grep it and its conftest for database fixtures and for
  `docker`/`compose`/`candidate-docker-gate` calls, and look for opt-in skip
  guards (such as `AWEB_TEST_DOCKER_NETWORK`). Run it there only if every
  such path is skipped by default.
- In a check summary, name every file or target that used a daemon or a
  database. A "cheap checks" or "focused" label must not hide a runtime
  execution.
- A note that records the rule does not help unless it is consulted when the
  checks are chosen; the grep is the mechanical step that does.

# Elimination route

A test that drives the daemon could skip by default behind an opt-in guard, as
some candidate tests already do; then a file's default run would be daemon-free
by construction. Until every such file follows that pattern, the grep above is
the check.

Related: [Focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md)
covers what a focused run must include; this lesson covers where it may run.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14; notes/db-tests-on-the-mac.md.
