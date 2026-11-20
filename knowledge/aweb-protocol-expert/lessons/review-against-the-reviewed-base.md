---
type: Lesson
title: Review against the reviewed base, not main
description: In a review, ruling or contract answer, read every cited line at the reviewed head's base (git show <base>:path) and check one's own queued branches, never origin/main alone unless the claim is about main; main both lacked a definition a queued stack already had and still showed a defect the reviewed base had fixed.
tags: [lesson, review, contracts, git, process]
timestamp: 2026-11-11
---

Two confident, wrong answers in November 2026 came from reading main when the
work in question sat on another base.

- **Missing on main, present in the queue.** Asked where a field goes on the
  wire, the contract owner answered from main and defined a second delivery
  field. Their own acknowledged, unlanded stack already defined it, with a
  reviewed vector. Reviewers read each change against main, so both
  definitions passed review separately and implementers were told to build to
  the wrong one. It surfaced only in a merge-tree check before landing.
- **Broken on main, fixed on the base.** A review cited main's code for a
  consumer-impact claim while the head under review sat on a release train
  that already carried the fix. The ruling stated a defect the reviewed code
  did not have and was corrected.

# How to apply

- Read every line you cite at the reviewed head's base,
  `git show <base>:path`, never at `origin/main`, unless the claim is
  explicitly about main.
- Before ruling that a contract lacks a field or rule, search your own
  unlanded branches as well (`git grep <term> <queued head>`).
- Before each landing request, run `git merge-tree --write-tree` against your
  other queued heads.
- When two acknowledged definitions conflict, keep the earlier vector-backed
  one, withdraw the duplicate, and tell every consumer which one to build to.

Related: [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md),
the same principle for test evidence.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-11; notes/check-own-queued-stacks.md.
Both incidents come from the source note and proposal; they were not
re-checked against the branches involved.
