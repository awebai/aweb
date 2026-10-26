---
type: Lesson
title: Review a change against its existing consumers
description: A change is not proven by its own new test; when it alters a contract, grep for tests and callers of the old behaviour and run the changed packages' tests, and when main brings callers of anything the branch changed, a merge ACK needs an import or collection run at the exact merged head.
tags: [lesson, review, merge, contracts, testing]
timestamp: 2026-10-23
---

Two misses in one week, both after an ACK.

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

# How to apply

- When a function's success or error semantics change, search for consumers of
  the old result, test assertions included, and run the unit tests of every
  changed package. These runs are cheap and need no whole suite.
- A correct new scenario proves that scenario; it does not show that every old
  expectation was deliberately updated.
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
