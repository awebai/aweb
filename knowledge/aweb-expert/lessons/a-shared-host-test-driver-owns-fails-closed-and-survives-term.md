---
type: Lesson
title: A test driver on a shared host owns what it removes, fails closed and survives a group TERM
description: A driver that runs tests on a held host beside a kept deployment removes only the resource IDs it recorded at creation, treats a failed query as a failure rather than as empty, enforces negative controls from the JUnit XML, survives a process-group SIGTERM with its log and status intact, and owns a disposable instance of every service its fixtures open; prove each rule with a stub harness shown red against the previous driver.
tags: [lesson, testing, shared-host, cleanup, signals, verification]
timestamp: 2026-11-13
---

Observed on 2026-11-13. One driver that ran database-backed tests on a held
host, next to a deployment that had to stay up, was refused four times in
review before a run passed with clean owned cleanup. Each refusal was for a
defect class that can be designed out before the first review.

# The rules

1. **Own what you remove.** The first driver's cleanup trap removed resources
   by name. A preflight refusal caused by an existing container with that name
   then deleted the existing container. Record each resource's exact ID only
   after its creation succeeds, and remove only those IDs. Check names, ports
   and paths before creating anything, and refuse ones that already exist
   without touching them.
2. **Fail closed on every query.** `query | grep … || true` and
   `while …; done < <(query)` read a failed query as an empty result: "no
   writers running", "no databases", "no volumes", or "start every service".
   Capture the query's output, check its exit status, then iterate. A cleanup
   failure, or drift in the kept deployment's inventory between start and end,
   turns the verdict to FAIL; a printed warning is not enough.
3. **Enforce negative controls; don't just print them.** Printing a control's
   exit code does not enforce it. Parse the JUnit XML and require the exact set
   of failing nodes, the intended assertion text, no errors or skips, and the
   raw status. Restore the patched source on every outcome and check its blob
   hash.
4. **Survive a process-group SIGTERM.** `exec > >(tee log)` puts the log writer
   in the driver's process group. A group SIGTERM kills it, and cleanup then
   dies on SIGPIPE. Write the log directly with no pipe writer, ignore PIPE,
   make cleanup uninterruptible, and keep the signal status (143 or 130)
   separate from the cleanup result. Finish an interrupted control's source
   restore before removing its tree.
5. **Own every service the fixtures open.** Read the selected fixtures for each
   external service they reach. In this case one fixture opened a real Redis
   from `REDIS_URL`, which defaulted to localhost, and a browser test needed
   system libraries. Start a disposable instance of each such service, or check
   the prerequisite on the host before asking for a slot.

# How the fixes were proved

A stub harness drove the real driver through each case: fake `docker`, `ss`
and `uv`, and a throwaway git origin that carried the real patched file. The
cases were name collisions, failed queries, wrong and unexpected control
results, cleanup failure, inventory drift, and a real `os.killpg` SIGTERM. The
harness was red against the earlier drivers for the group-TERM and in-control
cases before it was green against the final one. This is
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
applied to the driver itself.

Rule 1 is the cleanup side of
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md):
a name, like a process pattern, matches other people's resources, and only an
identifier you recorded is yours.

# Elimination route

These rules belong in one shared driver for placed runs, with the stub harness
as its test. Until that driver exists, each new driver must meet them by
design, and its review should ask for the stub harness's red and green runs.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/run-driver-on-a-shared-host.md. The review refusals, the stub harness's
red and green results and the final passing run are source-reported. The
harvester did not find the driver on main at 3be7a30f0.
