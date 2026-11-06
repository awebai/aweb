---
type: Lesson
title: Skipping the train skips the only full run
description: When whole suites run only in the coordinator's train, authors prove only focused tests and reviewers do not rerun, the train is the only place a change meets its existing consumers' tests; a coordinator brief that tells an author to self-land skips that run, and only the operator's explicit, per-change risk decision can.
tags: [lesson, coordination, review, testing, trains]
timestamp: 2026-11-04
---

The team's process divides proof three ways: authors run focused tests,
reviewers rely on the author's recorded runs instead of rerunning them, and
whole suites run only in the coordinator's train under the shared suite lock.
Each part is safe only because the train always runs.

In November 2026 two messaging-core changes self-landed on main on the
coordinator's brief, to hurry a fix. The author's evidence was focused runs,
and every review ACK recorded that it relied on the author's execution. The
next train's gate then failed 11 of about 4,000 server unit tests, all in
existing tests of chat, messages and address locality. The released-reader
end-to-end journey had passed on the regressing code, because it ran only
flows shaped like the feature's own design matrix; the existing HTTP unit
tests were what caught the reply regression. The coordinator recorded the
self-landing as its own process error. It cost a night of work and held a live
user fix behind a red main.

# How to apply

- Treat "self-land this" in a brief as skipping the only full run of the
  server suite, not as a shortcut through ceremony. Urgency in a brief does
  not change that.
- A bypass of the train is a risk decision for the operator, made explicitly
  for that one change. A coordinator or author does not make it by brief.
- An author or reviewer who receives such a brief says what will not run
  before acting: the changed package's whole suite.
  [Review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
  asks for the changed packages' unit tests; for the server package that is
  the whole suite, which only the train runs.
- Do not count a feature's own end-to-end set as covering its consumers: it is
  shaped by the feature's design, not by the user paths it can break.

The elimination route is architectural: main written only by train pushes.
[Main CI is a separate signal](/coordinator/main-ci-is-a-separate-signal.md)
records that admin-exempt branch protection does not enforce that. See also
[lane trains share main](/coordinator/lane-trains-share-main.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-fresh-eyes, 2026-11-04;
notes/full-suite-runs-only-in-the-train.md and
notes/existing-unit-tests-caught-what-e2e-missed.md (tasks aweb-acst and
aweb-actf, landed at aweb c375d392; train gate d2e9c886). The source ran no
tests itself; results are the authors' and the gate's recorded runs.
