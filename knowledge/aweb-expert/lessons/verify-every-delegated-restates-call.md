---
type: Lesson
title: Verify every delegated "restates a constant" call before deleting a test
description: When agents classify tests for deletion as restating a constant, read each one; a test that calls real code with literal inputs and literal expected outputs is a safeguard, and in the aweb test sweep every misread went that way.
tags: [lesson, testing, cleanup, delegation, review]
timestamp: 2026-11-24
---

On 2026-11-24 five read-only agents classified 121 aweb script test files for a
test sweep. Four of their deletion candidates were wrong, all in the same
direction. Each was labelled "a constant compared to itself" or "restates a
budget", but the test called real code with literal inputs and checked literal
expected outputs. Two examples: an image-name mapping, where a swap would ship
an image to the wrong registry, and a known-issue classifier given a fixed
version, which must answer FAILED.

A literal expected value does not make a test a restatement. A test restates
when it reads the script or config text, or compares a table with a copy of
itself. A test that executes the mapping or the classifier is behaviour,
whatever its literals look like.

The agents were reliable on "nothing calls this" claims, which a `git grep`
confirmed. They were unreliable on restatement calls.

# How to apply

- Before a delegated restatement call becomes a deletion, read the test body
  and ask whether any line executes product or gate code. If one does, keep
  the test.
- Treat an agent's classification as a candidate list, not a verdict. Check
  the restatement category most closely, because that is where these agents
  erred.

This is the per-test form of
[verify business facts; consolidate before cutting](/aweb-expert/lessons/verify-business-facts-and-consolidate-before-cutting.md):
a cut needs its own evidence, not the say-so of whoever proposed it.

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-24;
notes/agent-sweeps-overcall-restates.md. The sweep branch head is b15c9183b
(its "Delete tests that restate scripts, config or mocks" commit is e4dad0ab1).
The count of four misreads and the examples are source-reported.
