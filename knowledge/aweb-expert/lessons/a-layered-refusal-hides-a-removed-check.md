---
type: Lesson
title: A layered refusal hides a removed check unless the test pins the refusal code
description: When several checks refuse the same bad request, planting a defect in one leaves the request refused, so a test that asserts only "refused" says nothing about that check; assert the exact refusal code at the boundary, mutate each layer alone and then together, and where only the end result can be shown, claim fail-closed, not a pinned check.
tags: [lesson, testing, mutation, verification, authorization]
timestamp: 2026-11-27
---

# The discovery

In one sweep that rewrote safeguard tests to run the real authority, planting
the obvious defect left the rewritten test green three times, because another
layer refused the same request first:

- **Key holder.** Removing the owner's requester comparison changed nothing:
  enrollment admission had already refused the stranger. With the admission
  check removed instead, the next layer refused with
  `identity_subject_mismatch`, and the test, which asserted the code, failed.
- **Identity binding.** Matching `did_aw` without verification failed an
  earlier assertion that reads the same projection, not the assertion the
  test was written to restore.
- **Raw-wire vectors.** Coercing a fractional `seq` still failed closed,
  through the entry's hash and signature checks.

A future instance that plants the single mutation and sees green will either
wrongly call the test weak or, after a lucky red, wrongly claim it pins one
check.

# How to apply

- Assert the exact refusal code at the boundary, not just that the request
  was refused. The code is what tells you which layer refused.
- Mutate each layer alone, then all of them together. Report which mutation
  stays green and why: a green single-layer mutation is information about
  defence in depth, not proof of a weak test.
- Where only the end result can be shown (fail closed on the production
  reader), say "proves fail-closed, not which check" in the commit and the
  review, rather than claiming the test pins one check.

This applies the partial-red rule of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
to refusals, and refines how to show that a test rewritten under
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
bites.

# Limits

Seen at one head in one sweep. The three cases are source-reported; the
harvester did not rerun the mutations.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27; notes/layered-refusals-hide-a-removed-check.md. Task aweb-adzj.1 (E8.1 H1), head 548a8bd9d5.
