---
type: Lesson
title: Review every site on both axes
description: Before an ACK, restate why the change exists and verify that property at every affected site, then run the standard dimensions at each site as a checklist; reviews anchor on the most salient risk and miss an adjacent dimension at the structurally odd site.
tags: [lesson, review, security]
timestamp: 2026-06-23
---

Recorded by the OSS coordinator role on 2026-06-22 and 2026-06-23 after two
ACKs each missed a real gap that a second reviewer caught: a scanner narrowing
was checked for bare-form bypasses but not for serialisation-wrapped forms
(quoted JSON keys), and a fix whose stated purpose was restoring diagnostic
logging was checked for fail-closed behaviour at every site but not for the
logging it existed to restore, which one file without a logger still lacked.

# How to apply

- Axis 1, the change's own purpose: restate it in one sentence and verify that
  exact property at every site, mechanically enumerated.
- Axis 2, the standard dimensions at each site: still denies or fails closed,
  correct status, distinct message, the real error logged, tests in both
  directions. The outlier site is the structurally different one.
- For any detector narrowing, test the wrapped and serialised variants (quoted
  keys, quoted headers, single and double quotes) and confirm the inverse still
  passes; a narrowing is a loosening and is reviewed for false negatives.
- An ACK names what was checked at each site so a gap is visible.

The `code-review-discipline` skill carries the complementary procedure
(verify subagent findings against code; grep every call site of a helper).
