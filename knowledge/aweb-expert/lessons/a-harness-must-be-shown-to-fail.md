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

# Review standard

Any verdict citing a harness carries one of two lines: "the fix was removed and
it redded, at these assertions" or "I did not check whether this harness can
fail." Silence is not acceptable.
