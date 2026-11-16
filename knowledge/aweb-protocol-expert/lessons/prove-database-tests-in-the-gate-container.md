---
type: Lesson
title: Prove database tests in the gate container before handback
description: The unit gate's PostgreSQL role has search_path set to pg_catalog, so a test whose app connects without naming a schema passes on a Mac and fails at the gate; the test names its schema and the role is never weakened, and before handback, and again after merging a landing, the author runs every touched suite in full through the gate container.
tags: [lesson, testing, postgresql, gates, handback]
timestamp: 2026-11-16
---

The candidate gate's Docker entry point (`scripts/test-egress/docker.py`) sets
`search_path = pg_catalog` on the `postgres` role, preserving production's role
default. A local PostgreSQL keeps the default search path. A test whose app
connects by DSN alone, with no schema of its own, therefore passes locally
and fails only at the gate. Its migrations try to create objects in
`pg_catalog` and fail with `InsufficientPrivilegeError`.

# Rule

- **Fix the test, never the role.** The role default is deliberate: it makes
  unqualified table access fail. A test that trips it names its schema, for
  example a DSN `?search_path=<schema>` (asyncpg passes unknown DSN parameters
  as server settings), and its queries use `{{tables.<name>}}`, not
  `public.<name>`.
- **Run the touched suites in the gate container before handback.** When a
  head adds or changes database tests, run each touched suite in full through
  `scripts/test-egress/docker.py` (for example the `test-naapp` and
  `test-server` targets) before handing it to the coordinator. The gate stops
  at its first failing command (`docs/contributing.md`), so one gate run shows
  at most one failing suite; each failure found there costs a gate slot and a
  coordinator round trip.
- **Read Mac-only failures in the container.** A local timeout can be a Mac
  artifact. The container run tells it apart from a real failure.
- **Run again at the merged head.** A landing can move a shared pytest fixture
  into `conftest.py` and still merge without textual conflict into a branch
  that imports the fixture from its old module. Collection then fails with an
  `ImportError` that no conflict marker shows. After merging a landing,
  collect or run every test module the branch touches at the merged head, not
  only the files git or the coordinator flagged.

These runs still follow the team's rules for where database tests may run.
The gate container brings its own disposable PostgreSQL on an internal
network.

# Evidence

On 2026-11-16 the Library team-key pin test errored at the gate on a9bf9f623
with `InsufficientPrivilegeError`. e10a8992a fixed it by giving the app its
schema through the DSN. The gate container then ran `test-naapp` and
`test-server` green in full. Three alias "unreachable" cases that time out on
a Mac passed there. The same day 747304376 moved the shared controller
fixtures into `conftest.py`. At the integration head d852a41b6 two team-key
test modules failed collection, although the coordinator had flagged only an
auto-merged source file. 3adccc201 fixed the imports, and the full unit stage
went green. All five commits are on aweb main.

Related: [test databases run on tmpfs](/aweb-protocol-expert/decisions/test-databases-run-on-tmpfs.md)
and [reproduce the whole test context](/coordinator/reproduce-the-whole-test-context.md).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-16; notes/gate-role-search-path-pg-catalog.md, notes/merged-test-fixture-moves.md.
