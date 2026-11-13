---
type: Lesson
title: A bundle can carry a test without the product commit it was written against
description: A composed bundle can bring in a test file from one lineage and leave out the product wiring commit from another, so the test's positive cases can never pass; when a positive case fails on a refusal the product raises whenever an optional dependency is None, check the composition passes that dependency before touching the fixture, then audit the bundle for every absent source commit.
tags: [lesson, debugging, testing, branches, composition]
timestamp: 2026-11-13
---

Observed on 2026-11-13, clearing the requester tests in a deployment bundle that
had been composed from several authors' branches. The failures came off one
layer at a time, and each fix only exposed the next one:

1. live DNS (a fixture problem);
2. a browser cookie leaking into the controller's request (a fixture problem);
3. `scope_not_signer` on the positive cases.

The third failure was not in the fixture. The bundle carried the test file, but
not the commit that wires the requester handoff into the app's composition
(eda9d6011, "Wire requester handoffs through the runtime-owned registry
client"). That commit existed only on its author's own branch. The test had come
in through another lineage, and its positive cases had never passed in the
bundle. Once the commit was brought in (92430124a), the run went from 27 passed
and 2 failed to 29 passed.

# How to apply

- When a test's **positive** case fails on a refusal that the product raises
  whenever an optional dependency is None, first check that the composition
  actually passes that dependency, before changing the fixture.
- Separate fixture from product with a precondition assertion in the test. Here
  the assertion verified the chain under the runtime's own evidence and
  reported only codes. In one run it showed the child chain verified, so the
  cause was not the fixture.
- Once one missing product commit is found, audit for all of them, not only the
  one the test exposed. Run `git cherry <bundle> <source-branch>` for each
  source branch. In this case the audit found 21 of one author's commits
  absent from the bundle, and the author ruled 7 of them required.
- This is a case of [reproduce and read the first error before attributing a
  regression](/aweb-expert/lessons/reproduce-before-attributing-a-regression.md)
  applied to composition: a failure that moves one layer deeper after every
  fixture fix is a signal to check what the bundle contains.

# Elimination route

This should be a composition check, not a lesson: whoever composes a bundle
verifies that each carried test file's introducing branch is fully merged, so
that tests arrive with the product commits they were written against. Until
that check exists, this lesson stands in for it.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/bundle-carried-tests-without-their-wiring.md. The harvester checked that
eda9d6011 is not on main at f8f54ff53, and that 92430124a carries the same
subject on the bundle branches. The gate-run counts and the audit's 21/7 figures
are source-reported.
