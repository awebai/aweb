---
type: Lesson
title: Guard pgdbm test databases on the captured config, from a pytest-only module
description: pgdbm builds DEFAULT_TEST_CONFIG once, when its fixture module is imported, so a guard that reads os.environ can pass a run that pgdbm still points at localhost:5432; compare the captured config with the explicit TEST_DB_* selection instead. Put the pytest hook in a module only pytest loads, because a plugin that other code imports first cannot be assertion-rewritten and filterwarnings=error fails collection. Prove the guard's red with connects blocked and no database created.
tags: [lesson, testing, pytest, pgdbm, postgres, environment]
timestamp: 2026-11-20
---

The operator's rule forbids local database tests on the host's own Postgres
(5432). A pytest guard enforcing that rule refuses any test database that is
not on an explicitly selected server. Each of the two traps below cost a review
round while such a guard was being written for the naapp suites, and neither
shows in the finished code.

# Check the config pgdbm captured, not the environment

`pgdbm.fixtures.conftest` computes `DEFAULT_TEST_CONFIG` at import time from
`TEST_DB_*`, falling back to `localhost:5432`. Its fixtures then use that
object for the rest of the run. A selection made after pgdbm loaded is
visible in `os.environ` but never reaches the fixtures.

A review with the network blocked showed this. A run set `TEST_DB_*` late and
passed a guard that read `os.environ`, while the database factory still
targeted the host's 5432.

- The guard compares `pgdbm.fixtures.conftest.DEFAULT_TEST_CONFIG` with the
  explicit selection and refuses a mismatch or a missing selection.
- When reviewing such a guard, ask which object the fixture will actually
  connect with. An environment check passes the case the guard exists for.

# The hook lives in a module only pytest imports

The first version put the `pytest_fixture_setup` hook in
`awid_service.testing`. `aweb_naapp_testing` imports that module, and every
naapp conftest imports `aweb_naapp_testing` at top level. Pytest therefore
found the plugin module already imported and could not rewrite its
assertions. It emitted `PytestAssertRewriteWarning`, and with
`filterwarnings = ["error"]` collection failed in all four naapp suites.

- Keep the shared rule in the importable testing module. Put the hook in a
  separate plugin module that only pytest loads (here
  `awid_service.testing_postgres`), and have suites load that module in place
  of `pgdbm.fixtures.conftest`.
- Before adding a pytest hook to an existing shared module, check who imports
  that module. Any importer that runs before pytest loads the plugin breaks
  every suite that uses it.

# Prove the red without touching the forbidden server

A red that would itself connect to the host's Postgres must not be run.
Instead, block socket connects in the child process and request the fixture
without creating a database. A blocked-connect error means the fixture tried
pgdbm's default (red). A refusal raised before any connect means the guard
worked (green). This keeps
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
without breaking the rule the guard enforces.

The guard itself is the elimination route for the 5432 trap. This lesson is
for writing or reviewing such a guard, or adding one to another pgdbm suite.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-library-auth,
2026-11-20; notes/pytest-guard-plugin-pgdbm.md. Task aweb-admf, final head
7009d75ad ACKed in review.
