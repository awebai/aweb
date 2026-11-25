---
type: Lesson
title: Map every deleted test to its cover
description: Before a port or retirement deletes a test suite, have someone who did not write the change map each deleted test to the exact test that now covers it, or mark it changed by design, retired by ruling or NOT COVERED; run the new suites with warnings as errors. "The replacement is tested" missed 30 behaviours and four defects.
tags: [lesson, testing, review, port, deletion]
timestamp: 2026-11-25
---

Seen on 2026-11-25 in naapp PR #53, which moved Library's deploy tool onto
naapp-lib's shared ops and retired AATK (see
[one shared deploy tool for every naapp](/aweb-expert/decisions/one-shared-deploy-tool-for-every-naapp.md)).
The author had written tests for every rule added, with a planted defect for
each one, and believed coverage was complete. A separate reader then mapped the
166 deleted tests one row at a time. The map found 30 behaviours that no
remaining test checked, and four defects:

- a make recipe that put an operator-supplied config value straight into the
  shell, so the value could run as a command. The same pattern is in Folio's
  Makefile on main;
- an HTTP error body that was left out of the evidence;
- a non-HTTP answer that escaped the CLI as something other than the tool's own
  error type;
- a Render API error response that was never closed. This one surfaced only
  when the new tests ran with warnings as errors.

# How to apply

- Before deleting a suite in a port, produce a map with one row per deleted
  test. Mark each row with one of: covered (name the exact covering test),
  changed by design (name the test that pins the new behaviour), retired by
  ruling (cite the ruling), or NOT COVERED. When in doubt, mark it NOT COVERED.
- The map is made by someone who did not write the change. Post it on the PR
  and resolve every NOT COVERED row before review.
- Run the new suites with warnings as errors (`-W error`).
- Every new check must be shown red on a planted defect. If a check cannot be
  made red, the test is wrong. In this port, bounded reads never raised
  `IncompleteRead`, so the planted defect had to come from a broken status line
  instead.

This applies [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
to deletions, and extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md):
the deleted tests are consumers of the behaviour too. One way to remove the
need for this lesson is a review rule that blocks any PR deleting test files
until it carries such a map.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/deleted-test-coverage-map.md. The coverage map posted on
naapp PR #53 was checked by the harvester.
