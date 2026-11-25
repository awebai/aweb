---
type: Lesson
title: A gate's deadline belongs to the machine runner and arrives as TERM
description: A command that wraps a long gate puts no timeout on it; the runner that knows the machine owns the deadline and delivers it as TERM, then KILL after a grace period, and the gate records each stage as it passes, because a wrapper's SIGKILL-on-timeout skips the gate's finalizer and throws away hours of passed work.
tags: [lesson, release, candidate-gate, timeouts, signals, processes]
timestamp: 2026-11-24
---

On 2026-11-24 a release candidate gate printed PASSED after about three hours.
The release command then killed it before the gate wrote its ledger rows and
before the tag was created. The command ran the gate through
`subprocess.run(timeout=...)` with the same bound it used for every other
command (7,200 s by default; a local shim had raised it to 10,800 s). There was
no tag, and none of the passed stages could be reused.

Two separate mistakes combined:

- **The wrong owner for the deadline.** A single constant in the release
  command cannot fit the gate: its run time differs by about 5x across the
  machines the team runs it on. Only the runner that provisions the machine
  knows how long the gate should take there. The VM gate runner already sizes
  an expiry per machine and stops the command with TERM, then KILL after a
  grace period, so the gate can finish cleanup and record its verdict.
- **The wrong signal.** `subprocess.run(timeout=...)` sends SIGKILL to its
  direct child only. The gate's own TERM path (cleanup, then recording the
  stages that are eligible for reuse) never runs, and the gate's Docker
  children are orphaned.

The gate also recorded its stages only at the end, so even a correct deadline
would have lost every completed stage when it fired.

# How to apply

- When designing or reviewing release or gate tooling, do not put a timeout on
  the call that runs a long gate. Leave the deadline to the machine's runner,
  and keep ordinary bounded timeouts on short commands only.
- Never wrap a process that has a TERM finalizer in a SIGKILL-on-timeout. If a
  deadline is needed at that level, deliver TERM first and KILL only after a
  grace period.
- Persist each stage's proof as soon as that stage passes, not only at the end,
  so a kill or a host loss keeps the work already done.
- Know the limit: the gate's stages carry no timeouts of their own (only the
  Go stage has one, 20 minutes). A gate run directly, without a machine runner,
  has no bound, and an operator who runs it that way owns stopping it with
  TERM.

The child-process side of the same failure class (process groups, turning
SIGTERM into cleanup) is a separate rule for the tool that spawns children;
[a time budget covers the whole operation](/aweb-protocol-expert/lessons/a-time-budget-covers-the-whole-operation.md)
is the opposite case, where an operation needed a bound it did not have.

# Status

As of 2026-11-24 the fix is on the source's review branch
`agents/aweb-expert-gate-dispatch-gate-deadline` (head 06c637853b), under
review and not on main. On that branch the release command runs the Docker
gate with no timeout while other commands keep theirs, the gate records each
stage in the ledger as its verdict line passes, and `docs/release.md` states
the deadline owner. Check main before relying on the code.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-24;
notes/gate-deadline-belongs-to-the-machine.md (coordinator 9c9d72e5). The
incident timings and the per-machine spread are source-reported. The harvester
read the branch diff at 06c637853b (`scripts/release_candidate.py`,
`scripts/candidate-record.sh`, `scripts/test_shipping.py`
CandidateGateDeadlineTest, `scripts/test_candidate_interruption.py`) and
confirmed on aweb main at 1378733f0 that the release command bounds the gate at
7,200 s and that the VM gate runner stops its command with TERM and a KILL
grace.
