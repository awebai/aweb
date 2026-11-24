# Local Docker and database admission

On the shared Mac, each Docker or database run takes one machine-wide slot,
including focused runs. The local server and registry runner, the user-path
runner, the portable Docker runner and Cloud's local backend runner use the
same pool. Admission precedes installation, image preparation and service
creation. The runner holds the slot through cleanup. Linux gate workers use
their own admission. Use a gate worker for any Docker or database test whose
entry point lacks slot support. There is no host load threshold.

## 1. Shared files and capacity

All runners use `/private/tmp/aweb-local-suite-slots/slot-N.lock`, numbered from
zero. `AWEB_LOCAL_SUITE_SLOTS` sets the positive capacity, default **3**. Use the
same value for every seat on the host, and change it only when no slot is
held. The directory is explicitly mode 0777 and
files mode 0666, independent of umask, so seats share the same inodes. The path
is fixed; it does not vary with checkout, account, repository or `TMPDIR`.

Never delete or replace these files while runners may exist. File existence and
metadata are not occupancy: only the kernel lock determines whether a slot is
held. Descriptors use `O_CLOEXEC` and are not inherited by suite subprocesses.

## 2. Lock and owner protocol

Each runner opens the persistent files and tries `fcntl.flock(LOCK_EX | LOCK_NB)`
in order. If all are occupied, it prints the holder descriptions and repeats the
nonblocking scan every two seconds, reporting current holders once per minute.
It takes any freed slot, never exceeds the configured capacity, and starts no
services while waiting.

Under the acquired lock, the runner truncates and writes one JSON line with
`pid`, `repo` (`aweb` or `ac`), `source_sha`, `label` (`server`, `registry`,
`user-paths`, `portable` or `backend`) and `started_utc`. The aweb runner also
records `scope` (`focused` or `whole`). Optional `owner` identifies the seat.
Waiting output uses the holder record to identify the process. A partially
written record appears as metadata being published while the lock is held.

Closing the descriptor releases the lock on every process exit, including
SIGKILL. SIGKILL prevents the runner from executing cleanup. Interrupted
waiters exit without starting a project. The lock files stay in place when
a runner releases its slot.

## 3. Focused feedback

Explicit pytest paths or node IDs, `-k`, `-m` and `--deselect` can narrow the
tests run, including through `LOCAL_PYTEST_ARGS` or `PYTEST_ADDOPTS`. A focused
server or registry run still takes a slot. Options that change reporting,
verbosity or timing leave the scope whole. Static checks such as Ruff, mypy,
Go vet and diff checks run without a slot.

`make test-user-paths-local` holds one slot for all three declared lanes.
`make test-isolated` and direct invocations of `scripts/test-egress/docker.py`
use the `portable` label on macOS.

Both repositories follow the same lock protocol. The aweb implementation is
`scripts/local_suite_slots.py`. The process controls in
`scripts/test_local_suite_slots.py` exercise real flock contention, including
focused and portable admission, without starting Docker.
