---
type: Lesson
title: A gate records finished stages in its stop path
description: A gate that records stages only after its child exits loses every passed stage when an outer timeout stops it (2.7 hours of VM evidence lost once); record finished stages and then clean up in the stop path, keep the log writer of cmd | tee alive through a group TERM so the child's cleanup trap does not die on SIGPIPE, and size VM timeouts from recorded VM stage times, never from Mac times.
tags: [lesson, testing, gates, signals, bash, processes, infrastructure]
timestamp: 2026-11-13
---

Learned on 2026-11-13 from a release-profile candidate gate on a CCX43 VM. The
checks, user-paths, unit and artifacts stages passed and the gate's
`summary.tsv` said so. The VM run's outer timeout (10,800 s) then stopped the
gate during integration, and the ledger was empty. About 2.7 hours of passed
evidence could not be used to skip those stages on the next run.

# What went wrong

- **Recording happens only after a normal exit.** On main at ecb9d825a,
  `scripts/candidate-docker-gate.sh` records each stage from the child's
  summary only after the child exits, and exits 130 or 143 without recording
  anything. Any outer stop therefore discards everything that already passed.
- **The timeout was sized from the Mac.** On the CCX43 the release profile
  took 9,728 s before integration started. The unit stage alone took 7,731 s,
  against about 3,000 s on the Mac.
- **A group TERM kills the log writer first.** The gate runs
  `run_candidate 2>&1 | tee "$run_log"`. A process-group TERM reaches `tee` as
  well as the command. The command's TERM trap then dies on SIGPIPE at its
  first write, so its cleanup never runs. This is the likely cause of build
  containers surviving an interrupted gate. Group INT behaves differently:
  background commands in a non-interactive shell ignore INT, so an INT test
  does not show the TERM failure. Reproduced with bash 5.3.

# How to apply

- Put recording in the stop path: on TERM, INT or an outer timeout, record the
  stages that finished, then clean up. A longer timeout alone does not fix
  this.
- Keep the log writer immune to INT and TERM (ignore them before `exec tee`),
  and have the parent wait for the child's cleanup after recording.
- Test interruption with a group TERM, not only INT, and show the control red
  on the unfixed gate.
- Size VM timeouts from recorded VM stage times. Mac times understate VM
  stages by a factor of two or more for the unit stage.

The fix is a stop-path series on a task branch, with interruption controls
shown red before the fix (source-reported; not on main at ecb9d825a). A stage
result recorded on a stop still belongs to the exact SHA that ran:
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md).
Cleanup that leaks on interruption leaves other agents to remove it, which
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md)
forbids them to do by name.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-18; notes/gate-lessons-2026-11-12.md (items 10 and 11). The VM run
(vm-6f478cd4 on acyn cb37244c8), its stage times, the bash 5.3 reproduction and
the fix series 9703b77cb with its red controls on 3914a15e7 are the source's
report; the harvester did not find 9703b77cb or 3914a15e7 in the aweb
repository. The record-after-exit behaviour and the `tee` pipeline were read in
`scripts/candidate-docker-gate.sh` on main at ecb9d825a.
