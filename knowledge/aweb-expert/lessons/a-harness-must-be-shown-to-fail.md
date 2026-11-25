---
type: Lesson
title: A harness must be shown to fail
description: A red is evidence only if its failure text names the property; a zero is evidence only if the detector was shown positive on the real pattern in a separate invocation; a validated detector is still not a valid experiment until removing the fix makes the harness go red.
tags: [lesson, verification, review, testing]
timestamp: 2026-07-26
---

Recorded by the OSS coordinator role on 2026-07-26 as the durable output of a
security-remediation epic: a handful of real code defects were found, and in the
same period nine failures in the team's own measuring instruments — each of
which would have produced a confident wrong answer, none caught by inspection.

# The rules

- A red is evidence only if its failure text names the property. Environmental
  failures present as timeouts and killed processes and cannot name a property.
  Quote the assertion text, never a pass/fail count.
- A zero is evidence only if the detector was shown positive on the actual
  pattern, repeatably, in a separate invocation; a control in the same
  invocation puts the literal into the searcher's own arguments.
- A validated detector is not a valid experiment. A passing control proves the
  instrument can see; only removing the fix proves the harness can produce the
  condition.
- The control you need depends on the claim's direction: an absence claim needs
  a known positive; a presence claim needs a known negative.
- A partial red is evidence; widening the mutation until everything reds
  destroys the information. Classify every non-red after predicting the
  sensitivity set: expected-sensitive-but-passed is a vacuous guard.
- The harnesses most likely to lack all of this are the ones that are not tests:
  log greps, process counts, exit-code checks, read-backs, roster queries.

# When the tests cannot run locally

Database and e2e suites that need services the workstation lacks (no
database, no Docker on the Mac) can be shown to fail only in CI. Then:

- Make the PR's first commit plant the defects. The PR body predicts each
  failing test, with names copied from the code, not recalled. Check the red
  run one for one against the prediction, then push a revert commit.
- Tell the operator before the planned red run.
- Keep plants inside the package under test. CI selects packages by changed
  paths, so a plant in a shared library such as naapp-lib selects every
  package. One small red run becomes a full one, and other packages' tests
  that assert the same thing go red too; predict those as well, or avoid
  them.
- A predicted failure that passes is itself a finding: that test does not
  test what it claims.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-24; notes/2026-11-25-planted-defect-first-run.md. naapp PR #25,
planted run 45518289423 (a planted title limit failed exactly the predicted
test).

# Review standard

Any verdict citing a harness carries one of two lines: "the fix was removed and
it redded, at these assertions" or "I did not check whether this harness can
fail." Silence is not acceptable.
