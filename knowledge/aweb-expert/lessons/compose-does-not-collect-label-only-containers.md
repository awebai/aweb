---
type: Lesson
title: Compose does not collect a container that only carries its project label
description: A container made with plain docker create or docker run and only the com.docker.compose.project label is never removed by docker compose down --remove-orphans, because Compose lists only containers that also carry its config-hash label; a stack script's own helper containers need traps, removal on every path and a name-prefix teardown sweep.
tags: [lesson, testing, docker, compose, cleanup]
timestamp: 2026-11-19
---

A test-stack script created a helper container with `docker create` and gave
it the `com.docker.compose.project` label, so that the stack's
`docker compose down --remove-orphans` would remove it after an interrupted
run. It does not. Compose finds a project's containers with a label filter
that also requires `com.docker.compose.config-hash`, which only Compose itself
sets. The helper stays invisible to `down`, and here it kept the fixture
volume in use. The approach passed the author's own review and was caught
only by a reviewer who read Compose's source.

# How to apply

When a stack script starts a container outside Compose, the script owns its
cleanup:

- Track the live helper and remove it from INT and TERM traps, keeping the
  first error as the exit status.
- Remove it on every normal and error path, and report a removal that fails.
- In teardown, sweep leftovers by an anchored name prefix, for example
  `docker ps -aq --filter "name=^<project>-prepare-"`. This also covers a run
  that was SIGKILLed and never reached its traps.

The project label is still worth setting, but only so that a label-based
residue check (`docker ps --filter label=com.docker.compose.project=<project>`)
can see the leftover. Rejected: adding more Compose labels so that Compose
adopts the container; that imitates Compose's private bookkeeping.

Name the prefix after your own project, as
[never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md)
asks, so the sweep cannot remove another agent's containers.

# Citations

1. docker/compose v5.5.1, `pkg/compose/containers.go`, `getDefaultFilters`,
   which adds `api.ConfigHashLabel` to every project container listing. The
   harvester re-read this function at the tag.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-library-auth,
2026-11-19; notes/compose-project-label-does-not-collect-containers.md (task
aweb-acgh.5; fix at aweb 2652640b0f in scripts/e2e-library-stack.sh). The
behaviour was established by reading Compose's source, not by a local Docker
run, which the team's rules did not allow at the time.
