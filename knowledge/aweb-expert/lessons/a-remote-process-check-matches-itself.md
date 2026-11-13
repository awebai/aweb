---
type: Lesson
title: A remote process check that names its target matches itself
description: Over SSH, the remote shell running a pgrep -f, ps | grep or grep -c carries the whole command as its argv, so a check that names the target in plain text finds itself; use a bracketed pattern in a separate call or an exact /proc cmdline comparison, and take the wrapper's own exit line as the completion evidence.
tags: [lesson, processes, ssh, evidence, gates]
timestamp: 2026-11-13
---

Observed on 2026-11-13 during gated stage launches on a held VM (the run46
teardown and the run47 build and teardown). The shell that runs an SSH command
has that whole command as its argv. So `ssh host 'pgrep -f "x.sh"'`, or a
`ps | grep` or `grep -c` that names the target in plain text, matches the very
shell running the check. In one day this gave three false readings: two
pre-launch checks refused a launch as "busy", and one reported a finished
wrapper as still running. The integration owner rejected such checks as
evidence and asked for a check that cannot match its own command.

# How to apply

- A process check whose pattern also appears in its own command line is not
  evidence, whether it says "busy" or "idle".
- Use a pattern that cannot match its own text, such as a bracketed class
  (`pgrep -af "run4[67][.]sh"`), and run it as a separate call before the
  launch, not chained into the launch command.
- Where the answer gates a stage, compare the exact script arguments in
  `/proc/<pid>/cmdline`. That is what the gate accepted (it reported
  `active_wrapper_pids=[]`).
- For completion, prefer the wrapper's own exit line over any process check.
- The elimination route is a launcher that records its own PID and exit
  status, so that no pattern is needed at all.

The same name-matching hazard on the kill side is
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13; notes/remote-process-checks-match-themselves.md.
