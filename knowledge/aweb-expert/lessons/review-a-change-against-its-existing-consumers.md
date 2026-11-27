---
type: Lesson
title: Review a change against its existing consumers
description: A change is not proven by its own new test; when it alters a contract, grep for tests and callers of the old behaviour and run the changed packages' tests, and when main brings callers of anything the branch changed, a merge ACK needs an import or collection run at the exact merged head; before a removal, search callers in every form they take (shell string, quoted argv, joined continuation lines, the symbol's name) in the repository and in the consumers we run outside it, read the command's own contract, and run the full suite in the gate's environment.
tags: [lesson, review, merge, contracts, testing]
timestamp: 2026-11-27
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

# Before a removal

A removal's caller report is what the coordinator approves on. In the E1.6
removal of aw's second routes (2026-11-27) the first report was wrong twice,
and a reviewer later found three more misses. Each miss was a caller written
in a form the search did not match.

- **Search every form a caller takes.** Search the shell string (`aw x y`).
  Search the argv tokens in quotes, single or double, including Python tuples
  and JS arrays (`["aw", "check", "--online"]`, `('id', 'team', ...)`), and the
  flag alone as a quoted token. Join backslash-continued shell lines into one
  command before matching: a reviewer named four multi-line e2e invites that
  passed a removed flag, and joining the lines found eleven.
- **Grep the whole repository for the removed symbol's name**, not only for
  its callers. An exact-list inventory test in an unrelated file (the test
  that lists every route calling the team identity directly) breaks when a
  route is deleted.
- **Search the consumers we run outside this repository, live and frozen:**
  the OATS aweb provider in both copies, channel-core, the pi extension, the
  hosted e2e journeys, naapp and naapp-lib, and committed `.claude/settings.json`
  hooks, as well as the docs. The argv search found `aw check --online` as the
  OATS provider's readiness gate, and hosted journeys still passing deprecated
  `--alias` flags.
- **Read the command's own code before calling it a second route.** `aw check`
  shares a handler with `aw doctor` but exits nonzero on an online failure,
  and the provider depends on that exit code. "Same handler" was true of the
  code and false of the contract.
- **Then run the full suite in the gate's environment** (PGHOST, REDIS_URL,
  the egress runner). A flag passed through a table variable
  (`tc.scope = "--global"`) is invisible to any token search; only the full
  run found it.
- **Correct a wrong report before acting on its approval.** If a caller report
  has gone out and turns out wrong, send the correction and get the revised
  set confirmed before removing anything.

This extends the site enumeration of
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md):
existing callers and old-contract tests are sites too.

# Provenance

Harvested 2026-10-25 from seats `aweb-expert-security-review-2` (note
`review-runs-changed-packages.md`; security reviewer 837a41f2) and
`aweb-expert-naapps-verify` (note `merge-review-caller-compatibility.md`; naapps
ruling 682e645e), corroborated by `aweb-protocol-expert-awid-service-bypass`
(note `changed-contracts-need-existing-callers-reviewed.md`; 431be2ec, 7bc11e9c).

Before a removal: OKF proposal from aweb-expert/aweb-expert-cleanup-oss,
2026-11-27; notes/caller-search-must-cover-argv-forms.md. Task aweb-adzb.9
(E1.6); reviewer return 68e7c2fb. Checked by the harvester: commits
12825d2c8 (drops the removed route from the identity-call inventory) and
ecf6b94e3 (the e2e invites) on the source's E1.6 branch, not yet on main. The
misses, their counts and the coordinator's confirmation are source-reported.
