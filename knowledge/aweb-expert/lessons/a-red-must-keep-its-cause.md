---
type: Lesson
title: A red must keep its cause
description: A harness whose cleanup deletes the artifact that holds a step's error turns a gate failure into an exit code with no cause; before trusting an e2e harness, make every captured step output reach the log on failure before its runtime directory is removed, prove it with a red control that shows the error, and never rerun the same bytes on a paid VM only to see the cause.
tags: [lesson, testing, gates, harness, evidence, cleanup]
timestamp: 2026-11-20
---

Learned on 2026-11-20 from a VM gate of an aweb release-train candidate (aweb
d895e14cc). The integration stage ended at `test-federation-e2e` with
`Error 3` after every container was healthy, and the log carried no cause.

# Why the cause was lost

On aweb main at c42ad775a:

- `scripts/federation-authority-worker.py` catches every exception at its
  boundary, prints `{"status":"error","type":...,"detail":...}` to stdout and
  returns 3.
- `scripts/e2e-federation-authority.sh` redirects each worker's stdout into a
  file under `$RUNTIME`, and its `trap cleanup EXIT` ends with
  `rm -rf "$RUNTIME"`.

The cause was written and then deleted by the harness's own cleanup. All that
reached the gate log was the exit status.

# Why it matters

A failure seen in a gate needs its root cause found and fixed before the change
lands. Small VM runs for each fix are not allowed. A harness that destroys its
own cause blocks both rules: the only move left is to rerun the same bytes on a
paid VM, and that rerun teaches nothing if the harness is unchanged.

# How to apply

- Before trusting an e2e harness, check that every captured step output reaches
  the log on a failure, before the runtime directory is removed. For example,
  on a non-zero exit the cleanup prints the step artifacts to stderr first.
- A broad `except` that writes the error only into a captured artifact is the
  same defect.
- Fix the harness first. Prove it with a red control: a step that raises must
  show its exception type and detail in the log. Then reproduce the failure
  locally. Do not rerun the unchanged harness on a VM to see the cause.

This is the converse of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
that lesson says a red is evidence only if it names the property, and a red
that cannot keep its cause names nothing.

# Elimination route

The harness itself is the fix: its cleanup surfaces the step artifacts on
failure, and the red control above is its test. This lesson is for reviewing
harnesses that do not do this yet.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-20; notes/harness-cleanup-deletes-failure-cause.md. The VM run, its
`Error 3` and how the follow-up work was routed are the source's report. The
harvester read the worker's boundary handler and the harness's `$RUNTIME`
redirections and cleanup on aweb main at c42ad775a, and confirmed that
d895e14cc exists in the repository.
