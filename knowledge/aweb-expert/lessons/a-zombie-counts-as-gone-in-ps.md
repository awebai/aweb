---
type: Lesson
title: A zombie counts as gone in ps
description: A ps check by pid and command treats a killed but unreaped process as gone, because ps shows it as defunct, while kill(-pgid, 0) succeeds until every member is reaped and an orphan is reaped at init's pace; prove a process group gone by waiting, bounded and loud, for ESRCH.
tags: [lesson, testing, processes, harness, linux]
timestamp: 2026-11-25
---

A test that stopped an owned process tree checked each member with `ps`,
matching the pid and its command. A killed member that has not been reaped
still has its pid, but `ps` shows its command as `[name] <defunct>`, so the
command match fails and the check reports the member gone. The process group
is not gone: `kill(-pgid, 0)` keeps succeeding until every member is reaped.

A killed descendant whose parent has exited is an orphan, and init reaps it
when init gets to it. In a Linux container whose PID 1 reaped once a second,
the only process left in the group was the orphaned descendant, shown as
`Z [node] <defunct>`, and the assertion that the group was gone failed. Under
load the gap between death and reap is wide enough to fail such an assertion
on an ordinary host too.

# How to apply

- To prove a process group ended, wait for `kill(-pgid, 0)` to fail with
  ESRCH. Bound the wait and fail loudly with what is still in the group.
- Do not treat "killed", a missing command match in `ps`, or a dead parent as
  proof of termination. Any test or supervisor that proves termination with
  `ps` has this gap.
- Reproduce reaping delays with a slow reaper as PID 1, not with load alone.

The elimination route is code: the owned-process-group test now asserts the
group's reap. Related:
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md)
and [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/zombie-counts-as-gone-in-ps.md. Gate run vm-06bed6ed,
`channel/test/owned-process-group.test.ts`; red before the fix and green after,
green again in vm-b3ec44c0; fixed at aweb 9ac2fabf37. One run per observation.
