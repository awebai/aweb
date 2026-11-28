---
type: Lesson
title: A runner that bounds a test process owns its process group on every exit path
description: Bounding a test process takes a runner, not the test harness, that owns the process group under one deadline for the leader and its descendants, kills, reaps and observes the group empty on every exit path, records stop signals and acts on them between steps instead of raising, never touches the group number after the first ESRCH, and writes a verdict that consumers must match because no exit code is unique to a timeout.
tags: [lesson, testing, processes, signals, runners, python, macos]
timestamp: 2026-11-27
---

Learned on 2026-11-27 from a bound on each Node test process in the TypeScript
dist self-test. A hosted hook that never settled had left a session alive.
The first version bounded only the timeout path. It took five review rounds
before the runner held, and each round found another way a process or a
verdict escaped. Write the runner with every exit path listed up front.

# The design that held

- **The runner owns the process, not the test harness.** A timeout inside the
  harness only gives a verdict. A hook that stalls before the product's own
  abort leaves the process running. Start the test in its own session
  (`start_new_session=True`) and own that group from outside.
- **One monotonic deadline covers the leader and the group.** A leader that
  exits normally can leave a descendant holding the caller's captured pipe.
  The caller then blocks long after the "bound". Wait for the group to empty
  within the same deadline, not only for the leader.
- **Every exit path ends the group:** finished, timed out, SIGINT, SIGTERM and
  SIGHUP. Kill the group, then reap the leader, because an unreaped leader
  zombie keeps the group present. Then poll `killpg(pgid, 0)` until it raises
  ESRCH. On macOS a group whose last members are zombies awaiting their new
  parent answers **EPERM**, so count EPERM as still present, not as gone.
- **Stop handlers record; they never raise.** A raising handler makes every
  statement an unwind point, including the gap between `Popen` returning and
  the child being recorded as owned. The handler appends the signal to a list.
  The loop acts on it between steps, cleans up, and then re-raises the signal
  on itself with `SIG_DFL`, so the runner dies of the signal it received. A
  stop seen at any point, cleanup included, makes the verdict "interrupted".
- **Rejected: blocking signals with `pthread_sigmask` around `Popen`.** The
  signal mask is inherited across fork and exec. The command under test would
  start with SIGINT and SIGTERM blocked.
- **Ownership ends at the first probe that observes ESRCH.** After that the
  kernel may reuse the group number, so it is never signalled or probed again.
- **Only the runner writes its verdict** ("exit N", "timeout", "interrupted
  SIGNAME"). No exit code is unique to a timeout: a test can exit with the
  timeout code itself. A consumer requires the verdict file to match the exit
  status, and treats a missing or contradictory verdict as inconclusive.

# Controls that bite

Each control was shown red against a runner mutant that removed the rule it
guards, per [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):

- a descendant holding the captured pipe after the leader exits;
- a child that exits with the timeout code;
- TERM, INT and HUP sent after launch;
- a stop injected after a real `Popen` and before it returns;
- a stop at the ESRCH probe, with every group call recorded, so that a reused
  group number would show.

# When the bound is optional

The same ownership problem came up for a bash background job (a revocation
probe). `kill $!` signals only the job's subshell. A child that ignores TERM
is reparented to init once the subshell dies, so `pgrep -P` no longer finds
it. Rounds of hardening still left the bash ownership unsound. The fix there
was to drop the parallelism and run each attempt as one
`subprocess.run(timeout=...)`, accepting the wall time. When a bound is
optional, remove the background work rather than harden its ownership. When
the bound is required, as here, ownership has to be complete.

Ending only the group you own is the process side of
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md).

# Elimination route

The runner is the fix. It is one standalone, unit-tested script that test
gates call, and its controls are its tests. This lesson is for writing or
reviewing any other runner that has to bound a process.

# Limits

The evidence is one runner, run on macOS locally and on Linux in the gate.
The EPERM behaviour was observed on macOS only.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27;
notes/owning-a-process-group-on-every-exit-path.md;
notes/ending-a-shell-attempt-needs-its-tree-recorded-first.md. The review
rounds and the coordinator's direction are the source's report. The harvester
read `scripts/lib/bounded_group.py` and the test names in
`scripts/test_bounded_group.py` at aweb 96cf6e6b81, which is on the source's
review branch and not on main. That revision has the EPERM handling, recorded
stops, release at the first empty observation, the runner-only verdict and
the timeout exit code 254. Check main before relying on the code.
