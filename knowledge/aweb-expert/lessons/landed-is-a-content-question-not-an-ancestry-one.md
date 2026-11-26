---
type: Lesson
title: Landed is a content question, not an ancestry one
description: aweb work lands rebased, so an author's commits never become ancestors of main and `merge-base --is-ancestor` reports landed work as unlanded; `git cherry` misses commits whose rebase resolved a conflict, and a conflicting merge-tree proves nothing. Before saying work landed or a branch is stale, check its content on main.
tags: [lesson, git, landing, coordination, evidence]
timestamp: 2026-11-26
---

The integrator lands author branches rebased onto main, so the author's commit
SHAs never become ancestors of main. On 2026-11-26 a cleanup instance told the
coordinator that its test sweep (branch head b15c9183b) had not landed,
because `git merge-base --is-ancestor` said so. The sweep had landed as
b5a45ab5d..15df43297, five commits with the same subjects, and the report had
to be corrected.

The usual fallbacks are weaker than they look:

- **`git cherry`** matches commits by patch id. A commit whose rebase resolved
  a conflict gets a new patch id. For this sweep, `git cherry origin/main
  b15c9183b` matched two of the five landed commits and reported the other
  three as missing.
- **`git merge-tree --write-tree main <branch>`** proves containment only when
  it succeeds and its tree equals `main^{tree}`. When the landing resolved a
  conflict, or main has since changed the same lines, it reports a conflict.
  This sweep conflicts even against its own landing commit 15df43297, in the
  Makefile and `scripts/test_shipping.py`. A conflict says nothing about
  whether the work landed.

The source reported the same pattern across the 105 agent branches it
inventoried: `git cherry` called 9 merged, merge-tree found 7 contained and 81
conflicting.

# How to apply

- Before reporting that work landed or did not, or before calling a branch
  stale, never rely on ancestry alone.
- A clean merge-tree whose tree equals `main^{tree}` proves the branch's
  content is on main. Treat a `git cherry` "-" as a positive too.
- For anything else, check the content itself. Find main commits with the
  branch's subjects (`git log --oneline main --grep <subject>`). Check that the
  change's files, tests or exact lines exist on main. Diff the branch commit
  against its candidate landing (`git diff <branch commit> <main commit> --
  <its files>`).
- In an inventory, report "contained", "landed under other SHAs" and
  "unlanded" as separate findings. "Conflicts with main" is not one of them.

The elimination route would be a landing record that maps each author head to
the main commits it became. Until one exists, the check is manual.

Related: [verify a cross-team recipient like a SHA](/aweb-expert/lessons/verify-a-cross-team-recipient-like-a-sha.md)
and the [evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md):
"not landed" is a claim and needs evidence of its own.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-26;
notes/rebased-landings-defeat-ancestry-checks.md. Checked by the harvester
on aweb main df2f356b4: b15c9183b is not an ancestor and b5a45ab5d..15df43297
is; the `git cherry` and merge-tree results above were reproduced. The
105-branch counts are source-reported.
