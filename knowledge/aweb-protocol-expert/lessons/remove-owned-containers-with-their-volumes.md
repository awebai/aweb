---
type: Lesson
title: Remove owned containers with their volumes
description: Docker deletes a --rm container's anonymous volumes only when the daemon removes the container itself; an explicit docker rm -f without -v leaves them, and postgres and redis images declare VOLUME, so test runners and agents removing their own service containers use docker rm -f -v.
tags: [lesson, docker, testing, infrastructure]
timestamp: 2026-11-17
---

**Status (checked 2026-11-17):** the AWID fixture fix (82eed6a93a) is on the
review branch `agents/aweb-protocol-expert-team-key-trust`, not yet on main.

# Lesson

- Docker deletes a `--rm` container's anonymous volumes only when the daemon
  removes the container on exit.
- An explicit `docker rm -f <id>` without `-v` leaves those volumes, whether or
  not the container was started with `--rm`.
- The postgres and redis images declare `VOLUME`, so every disposable service
  container we start and then remove ourselves leaks one volume, unless its
  data path is a tmpfs (as in
  [test databases run on tmpfs](/aweb-protocol-expert/decisions/test-databases-run-on-tmpfs.md)).

# How to apply

- Test runners, and agents removing their own private service containers, use
  `docker rm -f -v`. It removes only that container's own anonymous volumes,
  never anyone else's.
- The code route is already taken for the AWID test fixture: it removes its
  containers with `-v`, and scripts/test-egress/test_awid_fixture.py checks
  this against real Docker with a bystander control. This lesson covers
  containers started by hand, which no test can cover.
- Containers abandoned by a killed run are a separate gap: no cleanup runs at
  all. Fixing that would need ownership labels and a sweep scoped to the
  owner.

# Evidence

Found during task aweb-adgs, a leak of roughly 580 volumes in 11 hours.

- A probe on Docker 29.8.1 left the volume both with and without `--rm` when
  the container was removed without `-v`.
- One run of the Go CLI tests left two volumes that docker mount events tie to
  the fixture's containers. After 82eed6a93a the same run left none.
- A 50-minute docker events watch showed the test-egress runner and the
  candidate gates removing their volumes, while hand-started private
  PostgreSQL and Redis containers removed without `-v` leaked.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/docker-rm-anonymous-volumes.md. Checked by the harvester: 82eed6a93a changes the fixture's removal to `docker rm -f -v` and adds the real-Docker test.
