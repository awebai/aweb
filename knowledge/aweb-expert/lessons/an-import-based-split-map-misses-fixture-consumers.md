---
type: Lesson
title: An import-based split map misses pytest fixture consumers
description: When a repository split assigns each module to a side by its imports, a test module loaded through a conftest's pytest_plugins gives fixtures to test files that never import it; classify such modules by who uses their fixtures, found by a word-boundary grep for the fixture names and a read of pytest_plugins, and split a module when only part of it depends on the side that moves.
tags: [lesson, repository-split, boundary, pytest, fixtures, testing]
timestamp: 2026-11-24
---

A boundary map that places each module by its import edges sees only what a
module imports and who imports it. A pytest plugin module has consumers with
no import edge: a conftest lists it in `pytest_plugins`, and every test under
that conftest can request its fixtures by parameter name. The map then places
the module by its own imports alone. When it moves, the tests that stay lose
their fixture.

In the apps repository split (phase 0 map, aweb main at d8ee9ed31), the map
put `server/tests/real_stack.py` in the naapp server-compatibility suite
because it imports naapp runtime modules. `server/tests/conftest.py` loads it
through `pytest_plugins`, and 14 core server test files take its `real_stack`
fixture without importing it. Only one method, which built the runtime's
discovery client, used the runtime. It was split out into
`server/tests/naapp_discovery.py` on the contracts branch (7b420f9f0), and the
boundary map was corrected.

# How to apply

- For every test module a split would move, read each conftest's
  `pytest_plugins` and list the fixtures the module defines. Classify the module
  by which tests request those fixtures, not by its imports.
- Find fixture users with a word-boundary search for each fixture name.
  Test names often contain fixture names as substrings: a substring search for
  `real_stack` also matched `test_cli_never_grants_real_stack`, which does not
  use the fixture.
- When only part of the module depends on the side that moves, split that part
  into its own module rather than moving the whole fixture provider.
- After the cut, collect and run each side's tests on its own tree. A missing
  fixture fails at setup with "fixture not found". That catches the miss late,
  so it backs up the classification and does not replace it.

This extends [review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md):
the consumers of a fixture provider include tests that reach it through a
plugin list, with no import. Observed once, in this repository's pytest setup.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-24;
notes/import-maps-miss-fixture-consumers.md. Harvester checked at aweb main
da869f714: `server/tests/conftest.py` lists `tests.real_stack` in
`pytest_plugins`, `real_stack.py` imports `aweb_naapp.runtime` modules, 14
`test_*.py` files take `real_stack` as a fixture parameter, and
`test_cli_never_grants_real_stack` contains the name without using the fixture.
Commit 7b420f9f0 ("Keep the naapp runtime out of the real stack fixture") is on
`agents/aweb-expert-contracts`, not on main. The correction of the boundary map
is the source's report.
