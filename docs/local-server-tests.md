# Local server and registry feedback

`make test-server-local` creates a unique Compose project for this invocation,
using PostgreSQL 17 on verified tmpfs (including WAL, with swap disabled) and
Redis 7. Docker assigns free **loopback-only** host ports. It calls the existing
`test-server` and `test-awid` Make targets with their normal dependency preparation
and native egress guard; it does not replace release-gate qualification.

```sh
make test-server-local
LOCAL_TEST_SUITE=server LOCAL_PYTEST_ARGS='tests/test_mail_send_retry.py' make test-server-local
LOCAL_TEST_SUITE=registry make test-server-local
LOCAL_TEST_WORKERS=2 make test-server-local
```

`LOCAL_TEST_SUITE` is `all` (default), `server`, or `registry`. Server execution
uses one private PostgreSQL/Redis pair per worker, capped at four workers and
four by default. Registry execution stays serial on the first pair; a
registry-only invocation creates just one pair. Focused pytest arguments are
relative to the selected package. Use one suite when selecting a package-specific
file. Existing `PYTEST_ADDOPTS` is preserved; worker options must instead use
`LOCAL_TEST_WORKERS`.

Before a server suite, the target runs `make prepare-server-node`: the existing
`make test-node-deps` installs the three committed npm lockfiles, then builds
channel-core, channel and pi-extension in that order. A preparation failure
stops before pytest; fix the reported error with `make prepare-server-node`
and rerun the local target. Registry-only runs do not need this preparation.

## Guards and cleanup

An inherited database URL or host/port that names a non-loopback host or port
5432 is refused before creating services. Unset it; this target supplies its own
`TEST_DB_*`, `TEST_DATABASE_URL`, `PG*`, Redis settings and `AWEB_TEST_SERVICES=1`.
It does not attach to an existing host database. Each xdist worker binds its own
ports before fixtures import their database settings.

The target resolves Docker's context-over-host precedence before any daemon
operation, refuses remote endpoints, and pins the selected Unix socket for disk
inspection, provisioning, readback, suite children and cleanup. A later change
to Docker's current context cannot redirect these operations. It delegates the
free-disk check to
`candidate-docker-gate.sh --check-disk`. A refusal stops the command. Reclaim
unused Docker objects with `docker system prune` and reclaim the Docker VM disk
with `fstrim` using the host's approved maintenance procedure; review the affected
objects first. The test target never prunes or trims automatically. The guard's
existing floor and reserve apply.

On normal exit, failure, INT or TERM, the suite process group is stopped before
`docker compose down --volumes --remove-orphans` removes this project's resources.
The target then verifies its containers, networks, labelled volumes and recorded
anonymous volumes are absent. Cleanup failure is an error. SIGKILL and host power
loss cannot run cleanup; the printed `aw-local-*` project name identifies the
resources to inspect. No other Compose project is removed.

The pure controls are in `scripts/test_server_local_controls.py`. Explicit native
acceptance is `server/.venv/bin/python scripts/test-egress/test_local_services.py`:
it uses real PostgreSQL and checks cleanup after success, failure, INT and TERM.
Run that native control only when Docker execution on the host is authorized.

For the isolated head/released and forward/reverse messaging selections, use
[`make test-user-paths-local`](local-user-paths.md).

Whole-suite invocations share the host-wide [local suite slots](local-suite-slots.md)
with Cloud (default three), held from preparation through cleanup.
