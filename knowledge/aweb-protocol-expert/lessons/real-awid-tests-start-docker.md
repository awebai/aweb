---
type: Lesson
title: Real-AWID tests in cmd/aw start Docker
description: cmd/aw tests built on the real-AWID fixtures start throwaway postgres:17 and redis:7 containers whenever PGHOST is unset, and the awid log still prints pgdbm's default localhost:5432; on a host where Docker is off limits a whole-package cmd/aw run is not a unit run, so skip those tests by name and never set PGHOST to dodge Docker.
tags: [lesson, testing, docker, awid, cli]
timestamp: 2026-11-19
---

`cmd/aw` tests that call `realAWIDFixture`, `realAWIDFixtureWithStorage`,
`realAWIDFixtureRateLimited` or `productionAWIDFixture` run
`scripts/test-egress/awid_fixture.py`. When `PGHOST` is unset it starts
`postgres:17` and `redis:7` containers on random loopback ports; when `PGHOST`
is set it uses that server. So "run the whole `cmd/aw` package locally" quietly
needs Docker. An observed whole-package run on 2026-11-19 started containers on
a host where Docker was reserved for the gate VMs.

The log hides it. The awid service prints
`Creating shared connection pool to localhost:5432/postgres`, which is pgdbm's
default host and port in its config, not where the pool connects: the pool uses
the database URL the fixture passes, the container's mapped port. Do not read
that line as "host Postgres"; check `PGHOST` instead.

# How to apply

- Where Docker is off limits, build a `-skip` list from the test functions
  that call the fixtures above and leave them to the gate's run.
- Never set `PGHOST` to avoid Docker: the fixture would then use the host's
  database server.

# Elimination route

The misleading line would go if the awid startup log printed the host and port
of the URL it actually uses. Until then the check is `PGHOST`, not the log.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-19; notes/real-awid-fixture-starts-docker.md. Verified by the harvester on aweb main (ecb9d825a): `awid_fixture.py` starts both containers only when `PGHOST` is unset, and the awid pool is built from the settings' database URL.
