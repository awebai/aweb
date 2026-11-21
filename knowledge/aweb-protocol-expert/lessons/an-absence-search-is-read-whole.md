---
type: Lesson
title: An absence search is read whole
description: A search or test run meant to prove that nothing else is affected is an absence claim, and piping it through head or tail silently turns "I saw nothing" into "I saw the first N lines"; count the hits first and read every one, grep saved test output for failures instead of tailing it, and ask for the component's whole suite when a change alters an invariant.
tags: [lesson, verification, review, testing]
timestamp: 2026-11-19
---

Twice on 2026-11-18 a truncated search hid exactly the result the audit was
for. A `tail -40` on a test run hid chat failures, and a `head -20` on a grep
for affected tests hid a test that pinned the old hard-delete behaviour; a
focused gate selection of six files then missed it too. Both were reported as
done, and each was caught only by a later failure: a rebase, and a VM run.

# How to apply

- For an absence sweep, count first (`grep -c`, `wc -l`), then read every hit,
  or page through deliberately. Never pipe it through `head` or `tail`.
- For a test run, save the output and grep it for `FAIL`, `panic` and
  timeouts instead of tailing it.
- A focused gate selection proves only the files selected. When a change
  alters an invariant (for example, deletion no longer removes rows), run the
  component's whole suite.

This sits beside the rule in
[shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md)
to confirm that a red run actually selected the test: both are about
evidence that looks complete and is not.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-19; notes/never-truncate-an-audit-search.md.
