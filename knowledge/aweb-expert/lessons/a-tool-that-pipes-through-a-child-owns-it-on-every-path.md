---
type: Lesson
title: A tool that pipes through a child owns it on every path
description: A deployment tool that streams through a child process (age, a CLI) kills, reaps and closes it on every exit, including the final drain and close, SIGTERM and the window before the guard; it bounds the call with one deadline from launch plus a separate reserve for ending the group; and its ownership tests observe exit, leftovers and group absence before their own cleanup, failing when the tool's cleanup is removed.
tags: [lesson, processes, signals, testing, deploy, python]
timestamp: 2026-11-18
---

Learned on 2026-11-18 in the team-deployment agent-state backup, which streams
a tar archive through `age` and runs other CLIs. In four review rounds, each
round found a different path on which a child process survived its caller:

- a tar parse error skipped the close;
- the final drain and close sat outside the guard, so an interrupt there left
  the child alive;
- SIGTERM kept Python's default action and ran no cleanup;
- an interrupt arrived between `Popen` and entering the guard;
- an observation error in the test harness escaped while the call was still
  alive;
- stdin and stdout pipes were left open (a `ResourceWarning` under `-X dev`).

The rules below are what held. Check them before review, not during it.

# The rules

1. **One guard around the whole use, the final drain and close included,**
   entered with no gap after the launch. On any failure, kill the child, wait
   for it and close its pipes. Keep the first error and append the child's
   outcome to it once.
2. **Turn SIGTERM into the same cleanup.** Raise it as an exception so that the
   guard runs, and exit with status 143.
3. **End process groups, not just the child.** `subprocess.run(timeout=...)`
   kills only the direct child. Start each child in its own process group. To
   end it, send TERM, then KILL, then reap, and confirm the group is gone with
   `os.killpg(pgid, 0)`.
4. **One absolute deadline per call, set at launch.** It covers observation,
   waiting and reading the result, with a separate reserve for ending the
   group. An elapsed outer timeout is INCOMPLETE, never PASS.
5. **Tests of ownership observe before they clean up.** Read the exit status,
   the leftover files and the absence of the group before any cleanup of the
   test's own. Send the child's stderr to a file, because an orphan holding a
   pipe turns the test's oracle into a timeout. Remove the tool's cleanup and
   the test must fail on the ownership assertion. This is
   [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
   applied to process ownership.
6. **Interrupt tests install `signal.default_int_handler`,** because a
   background job inherits SIGINT as ignored. They synchronize on an observed
   phase of the call, never on a timer.

# A trap seen here

Python's `tarfile` reads a stream in 10 KiB records. A short garbage stream
from the child therefore blocks the reader on the child instead of failing
fast, and only the deadline and the guard end it.

Ending only what you started is the process side of
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md).
The archive format that this tool writes is in
[agent-state backups keep in-root links](/aweb-expert/decisions/agent-state-backups-keep-in-root-links.md).

# Elimination route

These rules belong in one shared helper for running a child from the
deployment tools, with the ownership tests as its tests, so that a new tool
inherits them. Until that helper exists, each new tool meets them by design.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-18;
notes/own-child-processes-on-every-path.md. The four review rounds and their
findings are source-reported. The code is on the aweb task branch
`agents/aweb-expert-deploy-team-acwd25-state-archive` (head b2dac36aba, under
review), not on main, in `deploy/team/agent_state.py` and
`scripts/e2e/agent_state_age_check.py`.
