---
type: Lesson
title: A native e2e runner owns its processes, its evidence and its cleanup on every path
description: A runner that drives a fixture on a shared host reaps each child's process group on every unwind, cleans up before and independently of receipts, re-checks cancellation before every step, caps each capture below the next point of supervision, captures image identity from the running container, owns unlabelled helpers by image ancestry, treats malformed events as gaps, and uses only Docker's own template functions.
tags: [lesson, testing, shared-host, processes, docker, signals, evidence]
timestamp: 2026-11-13
---

Observed on 2026-11-13. A Python runner that drives the Secrets lane fixture
on a shared host was refused in review six times before its source was
accepted. Each refusal was a counterexample that the runner's stub harness had
passed, because the stubs never modelled the hostile case. The rules below
are what the accepted version does. A runner written from them starts where
that review ended.

# The rules

1. **Reap on every unwind.** Start each child in its own process group. On
   every exit from its supervision (a return, a signal, or an exception raised
   in a capture callback), send TERM, then KILL after the grace period, then
   confirm that the whole group is gone. Run resource cleanup only after that
   confirmation. Without it, report cleanup as "uncertain", never as done.
2. **Cleanup does not depend on receipts.** Writing a receipt never raises.
   Inventory, removal and the final inventory come before any receipt is
   written, and a failed receipt write has its own exit status.
3. **Check cancellation live, before every step.** Re-read the stop condition
   before each launch, each inspection and each optional read. A boolean
   computed once goes stale: with one, whole batches of work started after a
   TERM had arrived.
4. **Cap each capture.** No inspection's timeout may outlast the next point of
   supervision: take the smallest of its own cap, the KILL grace and the time
   left to the deadline. Optional context reads get a short timeout. One
   budget covers the whole stage, probes and source checks included.
5. **Capture identity from the running container.** A create event names its
   image by a mutable reference, and resolving that tag after the run proves
   nothing: a retag in between still passes. Inspect the container's image ID
   while it runs. A container that is gone before it was inspected means the
   run does not qualify; it is not a pass.
6. **Own unlabelled helpers.** `docker run --rm` helpers carry no compose
   label and get random names. Own them by `ancestor=` the project-named image
   plus the container IDs seen in events, and refuse to start a run if any
   such helper already exists.
7. **Validate untrusted event shapes.** A malformed Docker event is an
   evidence gap, recorded as such, never an exception that unwinds the runner.
8. **Use only Docker's own template functions.** Docker's Go templates have
   no `dict` or similar helpers. Select fields with plain templates such as
   `{{json .Image}}` and assemble the structure in the runner.

# How the fixes were proved

Every reviewer counterexample became a focused regression. Each was shown to
fail on the reviewed version, reconstructed byte-exact and hash-checked,
before it passed on the fix. This is
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
applied to the runner, and
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
applied to the reviewed version. Rule 5 is the same principle for images: a
claim about a run is about the image ID that ran, not the tag that names it.
Rule 6 is the container side of
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md):
only an identifier you observed is yours.

# Limits

The runner's source was accepted in review; no native run had been made when
this was recorded. The rules are review-proven, not yet run-proven.

# Elimination route

These rules belong in one shared runner for fixtures on shared hosts, with the
regressions as its tests, so that a new lane inherits them. Until that runner
exists, a new runner meets them by design, and its review asks for each
regression's red run on the previous version.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/native-runner-supervision.md. The review refusals, the accepted source
version and the regressions' red runs are source-reported. The harvester did
not find the runner on aweb main at 4b478bba5.
