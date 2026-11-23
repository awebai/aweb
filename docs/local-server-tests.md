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

## Live progress and interrupted runs

Each invocation retains evidence under a unique `test-results/server-local-*`
directory. Set `LOCAL_TEST_REPORT_DIR` to a new, unused directory to choose its
location. The runner prints the paths before each suite; server and registry
have separate subdirectories:

- `pytest.log` receives native Make/pytest output as it arrives. Use `tail -f`
  on the printed path while the run is active.
- `worker-*.json` records each worker's PID, current node ID, phase and UTC time.
  These files are replaced atomically; `progress.jsonl` retains the event history
  and pytest's setup/call/teardown durations.
- `cases.xml` is written by pytest's JUnit plugin. The final log also includes
  every completed case's duration, including sub-millisecond phases.

The progress plugin records test identities and phase outcomes, never environment
variables, credentials, fixture values or stack locals. Evidence directories are
private (0700); progress and log files are 0600. Native pytest output remains in
the private log, including ordinary failure diagnostics.

On INT or TERM, the launcher requests graceful termination of the owned process
group. The plugin converts TERM to pytest's normal interruption path so pytest
can finalize its own summary and JUnit. The launcher drains output through the
Make/egress wrappers before service cleanup. After ten seconds it force-stops an
unresponsive group; that case can retain partial logs and worker state without a
complete JUnit report. It never invents test results. There is no per-test timeout.

## Guards and cleanup

An inherited database URL or host/port that names a non-loopback host or port
5432 is refused before creating services. Unset it; this target supplies its own
`TEST_DB_*`, `TEST_DATABASE_URL`, `PG*`, Redis settings and `AWEB_TEST_SERVICES=1`.
It does not attach to an existing host database. Each xdist worker binds its own
ports before fixtures import their database settings. Port discovery reads the
owned container's `NetworkSettings.Ports`, verifying its ID and Compose project
and service labels. It waits up to five seconds for a nonzero `127.0.0.1` binding;
Compose's exposed-port summary is not used as a connection address. A refusal
prints a bounded `LOCAL_PORT_DIAGNOSTIC` JSON record with the container ID,
port-map readback and Compose port output before cleanup. No container environment
or credentials are inspected.

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

Focused and whole-suite invocations share the host-wide
[local suite slots](local-suite-slots.md) with Cloud (default three), held
from preparation through cleanup.
