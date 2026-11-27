---
type: Lesson
title: Fix reviewed work with new commits
description: Once a head has been sent for review, every fix is a new commit on top and main comes in by merge, never by amending or rebasing the reviewed commits, so the reviewer reads only the delta; amending is fine only before anyone has been sent the head.
tags: [lesson, process, review, git]
timestamp: 2026-11-27
---

On 2026-11-27 an author amended the E3.2 commit in answer to a review RETURN,
and had earlier amended another commit after a red gate. The coordinator
corrected the process and described it as the operator's rule: merge main,
never rewrite. That acceptance is source-reported (the coordinator's mail to
the source), not a record the harvester could read.

# The rule

- After a head has been sent to anyone for review, every fix is a new commit
  on top. No `git commit --amend`, and no force-push that rewrites reviewed
  commits.
- To bring in main, merge it into the branch; do not rebase.
- Exception: a stack the coordinator explicitly asks to be rebased (for
  example onto another seat's head for one gate run), reported with a
  `git range-diff`.

# Why

A separate commit lets the reviewer read just the delta against the head they
already reviewed. An amended or rebased head makes them re-read everything and
breaks the link between their verdict and the commit it named.

# How to apply

Before any amend, ask whether the commit has been sent to anyone. If it has,
make a new commit. How the integrator later lands the branch on main is a
separate step and does not change this rule for the author's reviewed head.

Related: [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
binds evidence to exact bytes; rewriting a reviewed head is the author-side
way to lose that binding.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-27;
notes/add-commits-after-review-starts.md. Source-reported: the coordinator's
correction and its attribution to the operator.
