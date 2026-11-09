---
type: Lesson
title: Review a change against its existing consumers
description: A change is not proven by its own new test; when it alters a contract, grep for tests and callers of the old behaviour and run the changed packages' tests, search the whole repository for a shared test fixture's importers, and when main brings callers of anything the branch changed, a merge ACK needs an import or collection run at the exact merged head.
tags: [lesson, review, merge, contracts, testing]
timestamp: 2026-11-09
---

Three misses, each after an ACK.

- **Old-contract tests.** A listing function changed from failing the whole
  list to clearing one bad field and warning. The author ran only the new
  regression and the security reviewer took the runs on trust. Running the
  changed package's unit tests at the head broke an existing test that still
  asserted the old error. The reviewer's own words: "I took the runs on trust
  and did not grep for existing tests asserting the old error contract".
- **Incoming callers.** A branch removed a private helper; main had meanwhile
  added a module importing it. The text merge was clean, the provider files were
  byte-identical and their definitions AST-identical, and the merged server
  could not import. The merge ACK was withdrawn, and the naapps coordinator set
  the rule that a merge ACK needs at least an import or collection run at the
  exact head when main imports or calls anything the branch changed.
- **Cross-rootdir fixture importers.** aweb's pytest modules import fixtures
  from each other by name, and not only within one package:
  `cli/tests/test_request_auth_v2_stack.py` imports `privacy_app` from
  `server/tests/test_dashboard_privacy.py` under a rootdir that does not load
  `server/tests/conftest.py`. On 2026-11-08 a branch gave `privacy_app` a new
  fixture argument whose default lived only in that conftest. The author's
  consumer sweep covered only `server/tests`, two reviews ACKed, and only the
  train's full gate caught four "fixture not found" errors in the cli test.
  The fix restored the shared fixture's signature and moved the variant into a
  helper wrapped by the variant module's own fixture.

# How to apply

- When a function's success or error semantics change, search for consumers of
  the old result, test assertions included, and run the unit tests of every
  changed package. These runs are cheap and need no whole suite.
- A correct new scenario proves that scenario; it does not show that every old
  expectation was deliberately updated.
- A shared test fixture's consumers are found by a repository-wide search
  (`cli/tests`, `naapp-lib/tests`, `server/tests` and the rest), not a sweep
  of the changed package. Its arguments must resolve under every importer's
  rootdir. Add a variant as a helper wrapped by a module-local fixture, never
  as a new argument on the shared fixture.
- In a merge review, dependency edges are affected sites even when neither side
  conflicts textually. Trace callers and providers, including additions outside
  the conflict list. "If the reviewed files are unchanged, no new ACK is needed"
  does not cover new callers of changed code.
- To run tests at an exact SHA without a worktree, export the whole tree (partial
  exports miss fixtures), initialise git in the copy when tests locate the
  repository root through git, and compare the failing sets at base and head so
  export artefacts are not reported as regressions.

This extends the site enumeration of
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md):
existing callers and old-contract tests are sites too.

# Provenance

Harvested 2026-10-25 from seats `aweb-expert-security-review-2` (note
`review-runs-changed-packages.md`; security reviewer 837a41f2) and
`aweb-expert-naapps-verify` (note `merge-review-caller-compatibility.md`; naapps
ruling 682e645e), corroborated by `aweb-protocol-expert-awid-service-bypass`
(note `changed-contracts-need-existing-callers-reviewed.md`; 431be2ec, 7bc11e9c).

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-09;
notes/shared-fixtures-cross-rootdirs.md (train 30 gate at 422fe1fec, fixed in
7394d4a30). The import was confirmed on main at 161f02d1f.
