---
type: Lesson
title: Bind sources live where the Docker daemon sees them
description: Inside the candidate runner every docker -v and compose bind source resolves on the host daemon's filesystem, so a source in the runner's own /tmp binds an empty directory the daemon creates; put bind sources under AWEB_DOCKER_BIND_ROOT and check bound files are visible before acting on them.
tags: [lesson, testing, docker, candidate-gate, e2e]
timestamp: 2026-11-14
---

The candidate runner talks to the host's Docker daemon through the host
socket. Every `docker run -v SRC:DST` and every compose bind names SRC on the
daemon's host, not in the runner. A directory that exists only in the runner's
filesystem (its private `/tmp`, for example) does not exist there. The daemon
does not refuse the bind: it creates an empty directory at that path and mounts
it. The step then fails far from its cause.

That is what happened on 2026-11-14 (aweb-acwd.24.12). An RC2 integration gate
at 169b44324 failed in Phase 11b2 of the OSS user journey after 152 passes. The
runner sets no `TMPDIR`, so the journey root was the runner's `/tmp`, and the
docker shim passes `-v` through unchanged. The container's `chown` on `/keys`
reported "No such file", and `set -e` ended the script with a bare exit and no
named assertion.

The gate shares only what it mounts at the same path on both sides: the
run-owned bind root (`AWEB_DOCKER_BIND_ROOT`) and the log directory. The other
Docker-binding e2e scripts already default their bind root to
`${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}`, and the shim already requires the
bind root for compose. The repository shows that convention but not the reason
for it, the symptom when it is missed, or that a new phase can silently miss it.

A related trap with a different cause: a single-file bind pins the old inode,
so a credential replaced by rename must be mounted by its directory.

# How to apply

- When a phase adds a bind mount, check where its source directory is
  allocated, not only that the files are written. Allocate it under
  `AWEB_DOCKER_BIND_ROOT`, falling back to `TMPDIR` outside the gate.
- A container step that acts on bound files first checks that they are present
  in its own view, so a visibility failure is a named assertion instead of a
  stray `chown` error and a bare exit.
- "The script is unchanged and an earlier gate passed" is not a baseline until
  the gate ledger shows the earlier gate actually ran that phase. Here no
  integration run on a commit containing the phase had passed: each such run
  failed earlier or failed here. This extends
  [reproduce before attributing a regression](/aweb-expert/lessons/reproduce-before-attributing-a-regression.md):
  a pass is evidence only for what it executed.

# Elimination route

The journey fix (733c0fbac, under review when this was recorded) moves the
journey root to the bind root and checks staged files in the daemon's view
before changing their ownership. That fixes one script. The general fix is for
the candidate docker shim to refuse a `docker run` bind source outside the
run-owned bind root and log directory, as it already requires the bind root for
compose. Until it does, this lesson is the guard for new phases.

# Limits

The failure was reproduced against a stub of the daemon's filesystem, which
produced the exact gate output from the old script lines. A reproduction on a
real daemon had not been run when this was recorded.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14; notes/runner-private-paths-are-invisible-to-the-daemon.md.
