---
type: Lesson
title: A fake must reproduce the failure's shape
description: When a test rewrite replaces a scripted Mock with a stateful fake, build the fake from the real failure (what each call returns, what state remains) and give each independent check a case where only it can refuse; a fake that is merely consistent passes the clean run and the planted defect alike.
tags: [lesson, testing, fakes, mutation, refactoring]
timestamp: 2026-11-27
---

# The discovery

A positional Mock pins call order, but it at least encodes the failure its
author meant. Replacing it with a "realistic" stateful fake silently drops
that failure unless the fake is built from it. In one sweep of behaviour
rewrites (2026-11-27), three rewritten tests passed their clean run and then
let a planted defect through:

- **Read-back.** The bug the test exists for is a released server that answers
  a set call with the requested mode and stores another. The fake answered the
  set with what it stored, so code that trusted the set's response instead of
  reading back still passed. The fix was a fake that answers as requested and
  stores something else.
- **Cleanup.** A container that survives `rm` was modelled only as "still
  labelled". The reader also refuses an id that is still present after its
  label is gone, and that branch was reachable only with a fake where `rm`
  strips the label but leaves the id.
- **Receipts.** The reader checks a cleanup verdict and an interruption receipt
  independently. A case where both said "failed" let a writer that always
  records cleanup as passed through, because the verdict alone already
  refused.

# How to apply

- For each refusal a test claims, name the observable shape of the real
  failure: what each call returns and what state remains afterwards. Build the
  fake to produce exactly that, including the inconsistent cases (a call that
  reports success and leaves the old state).
- Give each independent check its own case in which only that check can
  refuse. A case where two inputs are bad lets one check mask the other.
- Run the planted-defect step after every such rewrite, even when it
  "obviously" keeps the assertions. It is the only step that shows the fake
  lost the failure.

This applies [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
to fakes, and refines how a test rewritten under
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
keeps the failure it was written for.

# Limits

Seen at three sites in one sweep, in Python tests of gate and release tooling.
The planted defects that passed the first rewrites are source-reported; the
harvester read the fixing commits, not the runs.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/a-fake-must-reproduce-the-failure-shape.md. Task aweb-adzj.1 (E8.1 H3).
Checked by the harvester: commits 7a42295011 (a fake server that answers the
set with the requested mode but stores another), 350b948cfc (a stateful fake
docker; a survivor "still labelled or not" refuses) and b2641b6d70 (the test
writes receipts with the gate's own writers; the always-passed writer is among
the defects shown to fail) on the source's E8 H3 branch, not yet on main.
