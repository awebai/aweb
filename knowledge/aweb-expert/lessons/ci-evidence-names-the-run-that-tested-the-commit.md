---
type: Lesson
title: CI evidence names the run that tested the commit
description: On a branch with a CI concurrency group, the run for a given commit may never run, because a newer push replaces a pending run even with cancel-in-progress off; take evidence from a run whose head is exactly that commit, or name the later run that contains it, and never call a commit verified by a descendant's run without saying so.
tags: [lesson, ci, github-actions, release, evidence]
timestamp: 2026-11-25
---

GitHub keeps at most one pending run per concurrency group. When a newer push
queues a run, the waiting one is cancelled, even when `cancel-in-progress` is
off: that setting only protects the run already in progress. On a busy branch
"the CI run for commit X" may therefore never exist.

In the apps repository on 2026-11-25, run 45528903309 for main at dd0b6d555
was cancelled while pending and superseded by run 45529877178 for a later
head.

# How to apply

- Prefer a run whose head is exactly the commit. If the push run was
  superseded, a manually dispatched run of that exact SHA is one.
- Otherwise name the later run that contains the commit, check that it does
  (`git merge-base --is-ancestor <commit> <later head>`), and state both run
  ids and that the evidence comes from a descendant.
- Never call a commit verified by a descendant's run without saying so: the
  descendant carries other changes, so its green is evidence for its own head.
- The apps repository's release candidate check (`release_candidate.py`,
  naapp 2c524709f) encodes the strict form: it accepts a push run on main or a
  manual run of exactly that SHA. Prefer encoding the rule like that over
  judging it by hand.

This applies [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
to CI runs.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/ci-evidence-run-may-be-superseded.md. The note recommended reporting the
later run; the proposal refines that to the exact-SHA preference above. The
release candidate commit is the source's report. GitHub behaviour as of
2026-11.
